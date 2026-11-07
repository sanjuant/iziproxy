"""
Authentification NTLM / Negotiate auprès des proxys d'entreprise.

Le protocole NTLM authentifie une *connexion* et non une requête : la
négociation (type 1 -> challenge type 2 -> type 3) doit avoir lieu sur le
même socket. Cet adaptateur ouvre donc lui-même la connexion vers le proxy,
réalise la négociation, puis laisse http.client / urllib3 lire la réponse
afin de bénéficier du même comportement que requests (en-têtes insensibles
à la casse, cookies, redirections, streaming, décompression...).

Les jetons sont produits par pyspnego, qui :

- embarque sa propre implémentation de MD4 (OpenSSL 3 ne la fournit plus) ;
- sous Windows, utilise SSPI et peut donc s'authentifier avec la session
  Windows courante sans connaître le mot de passe.
"""

import base64
import http.client
import logging
import platform
import socket
import ssl
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ConnectTimeout,
    ProxyError,
    ReadTimeout,
    SSLError,
)
from requests.utils import select_proxy
from urllib3.response import HTTPResponse

try:  # urllib3 >= 1.26 / 2.x
    from urllib3._collections import HTTPHeaderDict
except ImportError:  # pragma: no cover
    from urllib3.response import HTTPHeaderDict

from .proxy_utils import (
    build_ssl_context,
    parse_proxy_authenticate,
    proxy_host_port,
    split_timeout,
)
from .secure_config import SecurePassword

logger = logging.getLogger("iziproxy")

try:
    import spnego

    NTLM_AVAILABLE = True
except ImportError:  # pragma: no cover - dépend de l'installation
    spnego = None
    NTLM_AVAILABLE = False

IS_WINDOWS = platform.system() == "Windows"


def is_ntlm_auth_available():
    """
    Indique si le support NTLM est disponible (paquet pyspnego installé).

    Returns:
        bool: True si NTLM est utilisable
    """
    return NTLM_AVAILABLE


def can_use_current_user():
    """
    Indique si l'on peut s'authentifier avec la session Windows courante
    (SSPI), sans nom d'utilisateur ni mot de passe.
    """
    return NTLM_AVAILABLE and IS_WINDOWS


class NtlmAuthenticationError(ProxyError):
    """Le proxy a refusé les identifiants NTLM / Negotiate."""


class _SocketCloser:
    """Objet « connexion » minimal passé à urllib3 pour fermer le socket."""

    def __init__(self, sock):
        self.sock = sock

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class NtlmProxyAdapter(HTTPAdapter):
    """
    Adaptateur requests qui traverse un proxy exigeant NTLM ou Negotiate.

    Les URLs HTTPS passent par un tunnel CONNECT authentifié ; les URLs HTTP
    sont envoyées au proxy en forme absolue sur une connexion authentifiée.
    Les hôtes que le résolveur déclare « directs » sont contactés sans proxy.
    """

    def __init__(self, proxy_url=None, username=None, password=None, domain=None,
                 workstation=None, resolver=None, **kwargs):
        """
        Args:
            proxy_url (str): URL du proxy (utilisée si aucun résolveur)
            username (str): Utilisateur ; None pour la session Windows courante
            password (str|SecurePassword): Mot de passe
            domain (str): Domaine NTLM
            workstation (str): Nom du poste (par défaut : nom d'hôte)
            resolver (callable): url -> dict de proxys ({} = connexion directe)
        """
        super().__init__(**kwargs)
        if not NTLM_AVAILABLE:
            raise ImportError("NTLM support requires pyspnego: pip install iziproxy[ntlm]")
        self.proxy_url = proxy_url
        self.resolver = resolver
        self.username = username or None
        if password is not None and not isinstance(password, SecurePassword):
            password = SecurePassword(password) if password != "" else None
        self.password = password
        self.domain = domain or None
        self.workstation = workstation or socket.gethostname()
        # Schéma retenu lors de la première négociation (évite une requête de sondage)
        self._scheme = None

    # ------------------------------------------------------------------ #
    # Sélection du proxy
    # ------------------------------------------------------------------ #
    def _proxy_for(self, url):
        """Retourne l'URL du proxy à utiliser pour cette URL, ou None (direct)."""
        if self.resolver is not None:
            proxies = self.resolver(url) or {}
            return select_proxy(url, proxies)
        return self.proxy_url

    # ------------------------------------------------------------------ #
    # Contexte d'authentification
    # ------------------------------------------------------------------ #
    def _qualified_username(self):
        """Nom d'utilisateur au format DOMAINE\\utilisateur si nécessaire."""
        user = self.username
        if user and self.domain and "\\" not in user and "@" not in user:
            user = f"{self.domain}\\{user}"
        return user

    def _new_context(self, proxy_host, scheme):
        """Crée un contexte pyspnego pour le schéma demandé."""
        password = self.password.get_password() if self.password else None
        protocol = "negotiate" if scheme == "negotiate" else "ntlm"
        return spnego.client(
            self._qualified_username(),
            password,
            hostname=proxy_host,
            service="http",
            protocol=protocol,
        )

    @staticmethod
    def _choose_scheme(offered):
        """Choisit le schéma à utiliser parmi ceux proposés par le proxy."""
        if "ntlm" in offered:
            return "ntlm"
        if "negotiate" in offered:
            return "negotiate"
        return None

    # ------------------------------------------------------------------ #
    # Entrées / sorties bas niveau
    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_response(sock, method):
        """Lit l'en-tête d'une réponse HTTP sur le socket."""
        response = http.client.HTTPResponse(sock, method=method)
        response.begin()
        return response

    @staticmethod
    def _drain(response):
        """Consomme le corps d'une réponse intermédiaire (407)."""
        try:
            response.read()
        finally:
            response.close()

    @staticmethod
    def _connection_closing(response):
        """Indique si le proxy va fermer la connexion après cette réponse."""
        values = " ".join(
            (response.getheader("Connection") or "", response.getheader("Proxy-Connection") or "")
        ).lower()
        return "close" in values

    def _open_socket(self, proxy_host, proxy_port, connect_timeout):
        try:
            return socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout)
        except socket.timeout as exc:
            raise ConnectTimeout(f"Timed out connecting to proxy {proxy_host}:{proxy_port}") from exc
        except OSError as exc:
            raise ProxyError(f"Cannot connect to proxy {proxy_host}:{proxy_port}: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Négociation
    # ------------------------------------------------------------------ #
    def _negotiate(self, proxy_host, proxy_port, connect_timeout, send_leg):
        """
        Réalise la négociation NTLM / Negotiate.

        Args:
            send_leg (callable): (sock, auth_header|None) -> HTTPResponse

        Returns:
            tuple: (socket, réponse finale non consommée)
        """
        sock = self._open_socket(proxy_host, proxy_port, connect_timeout)
        try:
            scheme = self._scheme
            if scheme is None:
                # Sondage sans authentification pour connaître les schémas proposés
                response = send_leg(sock, None)
                if response.status != 407:
                    return sock, response
                offered = parse_proxy_authenticate(response.getheaders())
                closing = self._connection_closing(response)
                self._drain(response)
                scheme = self._choose_scheme(offered)
                if scheme is None:
                    raise NtlmAuthenticationError(
                        f"Proxy {proxy_host}:{proxy_port} does not offer NTLM/Negotiate "
                        f"(offered: {', '.join(offered) or 'none'})"
                    )
                if closing:
                    sock.close()
                    sock = self._open_socket(proxy_host, proxy_port, connect_timeout)

            header_name = "NTLM" if scheme == "ntlm" else "Negotiate"
            try:
                context = self._new_context(proxy_host, scheme)
                token = context.step()
            except Exception as exc:
                raise NtlmAuthenticationError(
                    f"Cannot build the {header_name} token (missing or invalid credentials?): {exc}"
                ) from exc
            response = send_leg(sock, f"{header_name} {base64.b64encode(token).decode('ascii')}")

            rounds = 0
            while response.status == 407 and rounds < 5:
                rounds += 1
                offered = parse_proxy_authenticate(response.getheaders())
                challenge = offered.get(scheme)
                closing = self._connection_closing(response)
                self._drain(response)
                if not challenge or context.complete:
                    raise NtlmAuthenticationError(
                        f"Proxy {proxy_host}:{proxy_port} rejected the {header_name} credentials"
                    )
                if closing:
                    raise NtlmAuthenticationError(
                        f"Proxy {proxy_host}:{proxy_port} closed the connection during the "
                        f"{header_name} handshake"
                    )
                try:
                    token = context.step(base64.b64decode(challenge))
                except Exception as exc:
                    raise NtlmAuthenticationError(
                        f"Invalid {header_name} challenge from proxy {proxy_host}:{proxy_port}: {exc}"
                    ) from exc
                if not token:
                    break
                response = send_leg(sock, f"{header_name} {base64.b64encode(token).decode('ascii')}")

            if response.status == 407:
                self._drain(response)
                raise NtlmAuthenticationError(
                    f"Proxy {proxy_host}:{proxy_port} rejected the {header_name} credentials"
                )

            self._scheme = scheme
            return sock, response
        except Exception:
            sock.close()
            raise

    # ------------------------------------------------------------------ #
    # Construction des requêtes
    # ------------------------------------------------------------------ #
    @staticmethod
    def _body_bytes(request):
        """Retourne le corps sous forme d'octets (il peut être rejoué)."""
        body = request.body
        if body is None:
            return b""
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode("utf-8")
        if hasattr(body, "read"):
            data = body.read()
            return data.encode("utf-8") if isinstance(data, str) else data
        # Itérable / générateur (envoi « chunked » dans requests)
        chunks = []
        for chunk in body:
            chunks.append(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
        return b"".join(chunks)

    @staticmethod
    def _host_header(parts):
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        default = 443 if parts.scheme == "https" else 80
        if parts.port and parts.port != default:
            host = f"{host}:{parts.port}"
        return host

    def _serialize(self, request, target, parts, body, extra_headers):
        """Sérialise une requête HTTP/1.1."""
        lines = [f"{request.method} {target} HTTP/1.1", f"Host: {self._host_header(parts)}"]
        skip = {"host", "content-length", "transfer-encoding", "connection",
                "proxy-connection", "proxy-authorization"}
        for name, value in request.headers.items():
            if name.lower() not in skip:
                lines.append(f"{name}: {value}")
        if body or request.method.upper() in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(body)}")
        for name, value in extra_headers:
            lines.append(f"{name}: {value}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    # ------------------------------------------------------------------ #
    # Envoi
    # ------------------------------------------------------------------ #
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Envoie la requête, via le proxy NTLM ou directement selon le résolveur."""
        proxy_url = self._proxy_for(request.url)
        if not proxy_url:
            return super().send(request, stream=stream, timeout=timeout,
                                verify=verify, cert=cert, proxies={})

        proxy_host, proxy_port = proxy_host_port(proxy_url)
        connect_timeout, read_timeout = split_timeout(timeout)
        parts = urlsplit(request.url)
        method = request.method.upper()

        if parts.scheme == "https":
            sock, response = self._send_https(request, parts, proxy_host, proxy_port,
                                              connect_timeout, read_timeout, verify, cert)
        else:
            sock, response = self._send_http(request, parts, proxy_host, proxy_port,
                                             connect_timeout, read_timeout)

        return self._build(request, sock, response, method, stream)

    def open_tunnel(self, proxy_host, proxy_port, authority, connect_timeout=None):
        """
        Ouvre un tunnel CONNECT authentifié vers « hôte:port ».

        Utilisé par l'adaptateur (HTTPS) et par le proxy local.

        Args:
            authority (str): Cible du tunnel, au format « hôte:port »

        Returns:
            tuple: (socket, réponse finale du proxy, non consommée)
        """

        def connect_leg(sock, auth_header):
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}",
                     "Proxy-Connection: Keep-Alive"]
            if auth_header:
                lines.append(f"Proxy-Authorization: {auth_header}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            # Méthode CONNECT : pas de corps sur 200, http.client lit le corps des 407
            return self._read_response(sock, "CONNECT")

        try:
            return self._negotiate(proxy_host, proxy_port, connect_timeout, connect_leg)
        except socket.timeout as exc:
            raise ConnectTimeout(f"Timed out negotiating with proxy {proxy_host}:{proxy_port}") from exc

    def _send_https(self, request, parts, proxy_host, proxy_port,
                    connect_timeout, read_timeout, verify, cert):
        """Tunnel CONNECT authentifié puis requête chiffrée."""
        target_port = parts.port or 443
        authority = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        authority = f"{authority}:{target_port}"

        sock, response = self.open_tunnel(proxy_host, proxy_port, authority, connect_timeout)

        if response.status != 200:
            status, reason = response.status, response.reason
            self._drain(response)
            sock.close()
            raise ProxyError(f"Tunnel connection failed: {status} {reason}")
        response.close()

        try:
            ctx = build_ssl_context(verify, cert)
            sock.settimeout(connect_timeout)
            tls = ctx.wrap_socket(sock, server_hostname=parts.hostname)
        except ssl.SSLError as exc:
            sock.close()
            raise SSLError(exc) from exc
        except socket.timeout as exc:
            sock.close()
            raise ConnectTimeout(f"TLS handshake timed out with {parts.hostname}") from exc

        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        body = self._body_bytes(request)
        payload = self._serialize(request, target, parts, body, [("Connection", "close")])
        try:
            tls.settimeout(read_timeout)
            tls.sendall(payload)
            return tls, self._read_response(tls, request.method.upper())
        except socket.timeout as exc:
            tls.close()
            raise ReadTimeout(f"Read timed out from {parts.hostname}") from exc

    def _send_http(self, request, parts, proxy_host, proxy_port, connect_timeout, read_timeout):
        """Requête HTTP en forme absolue sur une connexion proxy authentifiée."""
        absolute = request.url.split("#", 1)[0]
        body = self._body_bytes(request)

        def http_leg(sock, auth_header):
            extra = [("Proxy-Connection", "Keep-Alive"), ("Connection", "Keep-Alive")]
            if auth_header:
                extra.append(("Proxy-Authorization", auth_header))
            sock.sendall(self._serialize(request, absolute, parts, body, extra))
            return self._read_response(sock, request.method.upper())

        try:
            sock, response = self._negotiate(proxy_host, proxy_port, connect_timeout, http_leg)
        except socket.timeout as exc:
            raise ReadTimeout(f"Read timed out from proxy {proxy_host}:{proxy_port}") from exc
        sock.settimeout(read_timeout)
        return sock, response

    def _build(self, request, sock, response, method, stream):
        """Transforme la réponse http.client en requests.Response."""
        headers = HTTPHeaderDict()
        for name, value in response.getheaders():
            headers.add(name, value)

        raw = HTTPResponse(
            body=response,
            headers=headers,
            status=response.status,
            version=response.version,
            reason=response.reason,
            preload_content=False,
            decode_content=True,
            original_response=response,
            connection=_SocketCloser(sock),
            request_method=method,
            request_url=request.url,
        )
        result = self.build_response(request, raw)
        if not stream:
            try:
                result.content  # noqa: B018 - force la lecture complète
            except socket.timeout as exc:
                raise ReadTimeout(f"Read timed out from {request.url}") from exc
            finally:
                raw.close()
        return result


class NtlmProxyManager:
    """
    Fabrique conservée pour compatibilité : crée une session requests
    utilisant NtlmProxyAdapter.
    """

    def __init__(self):
        if not NTLM_AVAILABLE:
            raise ImportError("NTLM support requires pyspnego: pip install iziproxy[ntlm]")

    def create_ntlm_proxy_session(self, proxy_host, proxy_port, username=None, password=None,
                                  domain="", workstation=None, debug=False):
        """
        Crée une session requests configurée pour un proxy NTLM.

        Returns:
            requests.Session: Session prête à l'emploi
        """
        adapter = NtlmProxyAdapter(
            proxy_url=f"http://{proxy_host}:{proxy_port}",
            username=username,
            password=password,
            domain=domain,
            workstation=workstation,
        )
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session
