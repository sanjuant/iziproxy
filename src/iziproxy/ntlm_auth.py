"""
Authentification NTLM / Negotiate auprès des proxys d'entreprise.

Le protocole NTLM authentifie une *connexion* et non une requête : la
négociation (type 1 -> challenge type 2 -> type 3) doit avoir lieu sur le
même socket. Cet adaptateur ouvre donc lui-même la connexion vers le proxy,
réalise la négociation, puis laisse http.client / urllib3 lire la réponse
afin de bénéficier du même comportement que requests (en-têtes insensibles
à la casse, cookies, redirections, streaming, décompression...).

Les connexions sont ensuite réutilisées (keep-alive) : une connexion
authentifiée au proxy sert aux requêtes http:// suivantes et aux CONNECT,
un tunnel TLS vers un site sert aux requêtes https:// suivantes vers ce
site. La négociation n'a donc lieu qu'à l'ouverture d'une connexion.

Quand le proxy propose Negotiate et NTLM, Negotiate est essayé d'abord
(Kerberos si possible, plus sûr que NTLM), puis NTLM s'il échoue.

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
import threading
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import (
    ConnectTimeout,
    ProxyError,
    ReadTimeout,
    RequestException,
    SSLError,
)
from requests.utils import select_proxy
from urllib3 import HTTPHeaderDict
from urllib3.response import HTTPResponse
from urllib3.util.wait import wait_for_read

from .proxy_utils import (
    build_ssl_context,
    is_https_proxy,
    parse_proxy_authenticate,
    proxy_host_port,
    read_tunnel_response,
    split_timeout,
    strip_credentials,
    wrap_tls,
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


# Erreurs d'une connexion réutilisée que l'autre bout venait de fermer : la
# requête est renvoyée une fois sur une nouvelle connexion (aucun octet de
# réponse n'a été reçu)
_STALE_ERRORS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLEOFError)


def _closing(response):
    """Indique si le proxy ou le site va fermer la connexion après cette réponse."""
    values = " ".join(
        (response.getheader("Connection") or "", response.getheader("Proxy-Connection") or "")
    ).lower()
    return "close" in values


def _tls_key(verify, cert):
    """Réglages TLS d'un tunnel (un tunnel ne resert qu'avec les mêmes)."""
    return (verify if isinstance(verify, (bool, str)) else repr(verify),
            tuple(cert) if isinstance(cert, (list, tuple)) else cert)


class _Connection:
    """
    Connexion ouverte par l'adaptateur : authentifiée auprès du proxy
    (requêtes http://, CONNECT) ou tunnel TLS vers un site. urllib3 la rend
    au pool (_ConnectionPool._put_conn) une fois la réponse lue.
    """

    def __init__(self, sock, key):
        self.sock = sock
        self.key = key
        self.response = None
        self.closed = False

    def reusable(self):
        """Réponse lue en entier, sans fermeture annoncée : la connexion peut resservir."""
        response = self.response
        return (not self.closed and response is not None and response.isclosed()
                and not response.will_close and not _closing(response))

    def dropped(self):
        """Connexion inactive fermée par l'autre bout (ou données inattendues)."""
        if self.closed:
            return True
        try:
            pending = getattr(self.sock, "pending", None)
            if pending is not None and pending():
                return True
            return wait_for_read(self.sock, timeout=0.0)
        except (OSError, ValueError):
            return True

    def close(self):
        self.closed = True
        # Le makefile() d'une réponse ouverte garderait le socket ouvert
        if self.response is not None:
            try:
                self.response.close()
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass


class _ConnectionPool:
    """
    Connexions inactives réutilisables, par clé : ("http", proxy) pour une
    connexion authentifiée au proxy, ("tunnel", proxy, hôte, port, tls)
    pour un tunnel TLS vers un site. Sert aussi de « pool » à urllib3, qui
    y rend la connexion d'une réponse lue (release_conn).
    """

    def __init__(self, maxsize):
        self._maxsize = maxsize
        self._idle = {}
        self._lock = threading.Lock()
        self._closed = False

    def __str__(self):
        # Figure dans les messages d'urllib3 (« <pool>: Read timed out. »)
        return "NTLM proxy connection"

    def _put_conn(self, connection):
        self.put(connection)

    def put(self, connection):
        """Garde la connexion si elle peut resservir, sinon la ferme."""
        if connection.reusable():
            with self._lock:
                idle = self._idle.setdefault(connection.key, [])
                if not self._closed and len(idle) < self._maxsize:
                    connection.response = None
                    idle.append(connection)
                    return
        connection.close()

    def get(self, key):
        """Connexion inactive encore ouverte pour cette clé, ou None."""
        while True:
            with self._lock:
                idle = self._idle.get(key)
                if not idle:
                    return None
                connection = idle.pop()
            if not connection.dropped():
                return connection
            connection.close()

    def close(self):
        """Ferme les connexions inactives ; celles rendues ensuite sont fermées."""
        with self._lock:
            self._closed = True
            connections = [connection for idle in self._idle.values() for connection in idle]
            self._idle.clear()
        for connection in connections:
            connection.close()


class NtlmProxyAdapter(HTTPAdapter):
    """
    Adaptateur requests qui traverse un proxy exigeant NTLM ou Negotiate.

    Les URLs HTTPS passent par un tunnel CONNECT authentifié ; les URLs HTTP
    sont envoyées au proxy en forme absolue sur une connexion authentifiée.
    Connexions authentifiées et tunnels sont réutilisés (``pool_maxsize``
    connexions inactives au plus par proxy ou par site).
    Les hôtes que le résolveur déclare « directs » sont contactés sans proxy.
    Un proxy en https:// est joint en TLS (certificat vérifié selon
    ``proxy_verify``) ; une cible HTTPS est alors chiffrée une seconde fois
    dans le tunnel.
    """

    def __init__(self, proxy_url=None, username=None, password=None, domain=None,
                 resolver=None, proxy_verify=True, **kwargs):
        """
        Args:
            proxy_url (str): URL du proxy (utilisée si aucun résolveur)
            username (str): Utilisateur ; None pour la session Windows courante
            password (str|SecurePassword): Mot de passe
            domain (str): Domaine NTLM
            resolver (callable): url -> dict de proxys ({} = connexion directe)
            proxy_verify (bool|str): Vérification du certificat d'un proxy
                https:// (True : autorités du système, False, ou chemin CA)
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
        self.proxy_verify = proxy_verify
        # Schémas à essayer, dans l'ordre, connus après la première négociation
        # (évite une requête de sondage) ; le premier est celui qui a réussi
        self._schemes = None
        self._connections = _ConnectionPool(self._pool_maxsize)
        # Contextes TLS déjà construits (lecture des autorités coûteuse)
        self._ssl_contexts = {}
        self._contexts_lock = threading.Lock()

    def _ssl_context(self, verify, cert=None):
        """Contexte TLS mis en cache, vers le proxy https:// ou vers un site."""
        key = _tls_key(verify, cert)
        with self._contexts_lock:
            context = self._ssl_contexts.get(key)
            if context is None:
                context = self._ssl_contexts[key] = build_ssl_context(verify, cert)
            return context

    def close(self):
        """Ferme les connexions réutilisables et les pools de requests."""
        super().close()
        self._connections.close()

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
    def _choose_schemes(offered):
        """
        Schémas à essayer parmi ceux proposés par le proxy : Negotiate
        (Kerberos quand c'est possible, plus sûr) puis NTLM.
        """
        return [scheme for scheme in ("negotiate", "ntlm") if scheme in offered]

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
        return _closing(response)

    def _open_socket(self, proxy_url, connect_timeout, proxy_ssl_context=None):
        """
        Ouvre la connexion vers le proxy, en TLS pour un proxy https://.

        Args:
            proxy_ssl_context (ssl.SSLContext): Contexte TLS vers le proxy
                (par défaut : construit selon proxy_verify)
        """
        proxy_host, proxy_port = proxy_host_port(proxy_url)
        try:
            sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout)
        except socket.timeout as exc:
            raise ConnectTimeout(f"Timed out connecting to proxy {proxy_host}:{proxy_port}") from exc
        except OSError as exc:
            raise ProxyError(f"Cannot connect to proxy {proxy_host}:{proxy_port}: {exc}") from exc
        if not is_https_proxy(proxy_url):
            return sock
        try:
            context = proxy_ssl_context or self._ssl_context(self.proxy_verify)
            return context.wrap_socket(sock, server_hostname=proxy_host)
        except socket.timeout as exc:
            sock.close()
            raise ConnectTimeout(f"TLS handshake timed out with proxy {proxy_host}:{proxy_port}") from exc
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            raise ProxyError(f"TLS handshake with proxy {proxy_host}:{proxy_port} failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Négociation
    # ------------------------------------------------------------------ #
    def _negotiate(self, proxy_url, connect_timeout, send_leg, proxy_ssl_context=None):
        """
        Réalise la négociation NTLM / Negotiate.

        Args:
            proxy_url (str): URL du proxy (http:// ou https://)
            send_leg (callable): (sock, auth_header|None) -> HTTPResponse
            proxy_ssl_context (ssl.SSLContext): Contexte TLS vers un proxy https://

        Returns:
            tuple: (socket, réponse finale non consommée)
        """
        proxy_host, proxy_port = proxy_host_port(proxy_url)
        sock = self._open_socket(proxy_url, connect_timeout, proxy_ssl_context)
        try:
            schemes = self._schemes
            if schemes is None:
                # Sondage sans authentification pour connaître les schémas proposés
                response = send_leg(sock, None)
                if response.status != 407:
                    return sock, response
                offered = parse_proxy_authenticate(response.getheaders())
                closing = self._connection_closing(response)
                self._drain(response)
                schemes = self._choose_schemes(offered)
                if not schemes:
                    raise NtlmAuthenticationError(
                        f"Proxy {proxy_host}:{proxy_port} does not offer NTLM/Negotiate "
                        f"(offered: {', '.join(offered) or 'none'})"
                    )
                if closing:
                    sock.close()
                    sock = self._open_socket(proxy_url, connect_timeout, proxy_ssl_context)

            for index, scheme in enumerate(schemes):
                try:
                    response = self._authenticate(sock, proxy_host, proxy_port, scheme, send_leg)
                except NtlmAuthenticationError as exc:
                    if index + 1 == len(schemes):
                        raise
                    # Negotiate refusé (pas de ticket Kerberos, proxy qui n'accepte pas
                    # NTLM dans Negotiate...) : NTLM sur une nouvelle connexion
                    logger.debug("%s with proxy %s:%s failed (%s), trying %s", scheme, proxy_host,
                                 proxy_port, exc, schemes[index + 1])
                    sock.close()
                    sock = self._open_socket(proxy_url, connect_timeout, proxy_ssl_context)
                    continue
                # Les négociations suivantes commencent par le schéma qui a réussi
                self._schemes = schemes[index:]
                return sock, response
        except Exception as exc:
            sock.close()
            # Connexion coupée ou réponse illisible : exception requests (les
            # délais dépassés sont convertis par l'appelant)
            if isinstance(exc, (OSError, http.client.HTTPException)) and \
                    not isinstance(exc, (socket.timeout, RequestException)):
                raise ProxyError(f"Connection to proxy {proxy_host}:{proxy_port} failed: {exc}") from exc
            raise

    def _authenticate(self, sock, proxy_host, proxy_port, scheme, send_leg):
        """
        Échange de jetons d'un schéma sur une connexion.

        Returns:
            http.client.HTTPResponse: Première réponse autre que 407, non consommée

        Raises:
            NtlmAuthenticationError: Identifiants refusés ou jeton impossible à produire
        """
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
        return response

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
        # L'authentification du proxy est gérée ici : un Proxy-Authorization
        # ajouté par requests (redirection) partirait vers le site
        request.headers.pop("Proxy-Authorization", None)
        proxy_url = self._proxy_for(request.url)
        if not proxy_url:
            return super().send(request, stream=stream, timeout=timeout,
                                verify=verify, cert=cert, proxies={})

        connect_timeout, read_timeout = split_timeout(timeout)
        parts = urlsplit(request.url)
        method = request.method.upper()

        try:
            if parts.scheme == "https":
                connection, response = self._send_https(request, parts, proxy_url, connect_timeout,
                                                        read_timeout, verify, cert)
            else:
                connection, response = self._send_http(request, parts, proxy_url, connect_timeout,
                                                       read_timeout)
        except RequestException:
            raise
        except socket.timeout as exc:
            raise ReadTimeout(exc, request=request) from exc
        except (OSError, http.client.HTTPException) as exc:
            # Les appelants de requests n'interceptent que ses propres exceptions
            raise RequestsConnectionError(exc, request=request) from exc

        return self._build(request, connection, response, method, stream)

    def open_tunnel(self, proxy_url, authority, connect_timeout=None, proxy_ssl_context=None):
        """
        Ouvre un tunnel CONNECT authentifié vers « hôte:port ».

        Utilisé par l'adaptateur (HTTPS) et par le proxy local. Une connexion
        déjà authentifiée (requêtes http:// précédentes) est utilisée si
        possible : NTLM authentifie la connexion, le CONNECT n'a alors pas
        besoin d'une nouvelle négociation.

        Args:
            proxy_url (str): URL du proxy (http:// ou https://)
            authority (str): Cible du tunnel, au format « hôte:port »
            proxy_ssl_context (ssl.SSLContext): Contexte TLS vers un proxy https://

        Returns:
            tuple: (socket, réponse finale du proxy, non consommée)
        """

        def connect_leg(sock, auth_header):
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}",
                     "Proxy-Connection: Keep-Alive"]
            if auth_header:
                lines.append(f"Proxy-Authorization: {auth_header}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            # Méthode CONNECT : pas de corps sur 200, http.client lit le corps des
            # 407 ; les octets qui suivent un 200 appartiennent au tunnel
            return read_tunnel_response(sock)

        connection = self._connections.get(("http", proxy_url))
        if connection is not None:
            try:
                connection.sock.settimeout(connect_timeout)
                response = connect_leg(connection.sock, None)
            except (*_STALE_ERRORS, http.client.HTTPException, socket.timeout):
                connection.close()
            except BaseException:
                connection.close()
                raise
            else:
                if response.status != 407:
                    # La connexion devient le tunnel (ou porte le refus du proxy)
                    return connection.sock, response
                # Connexion qui n'est plus authentifiée : nouvelle négociation
                self._drain(response)
                connection.close()

        try:
            return self._negotiate(proxy_url, connect_timeout, connect_leg, proxy_ssl_context)
        except socket.timeout as exc:
            raise ConnectTimeout(f"Timed out negotiating with proxy {strip_credentials(proxy_url)}") from exc

    def _open_tls_tunnel(self, proxy_url, parts, connect_timeout, verify, cert):
        """Tunnel CONNECT authentifié vers le site, puis session TLS avec lui."""
        authority = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        authority = f"{authority}:{parts.port or 443}"
        sock, response = self.open_tunnel(proxy_url, authority, connect_timeout)

        if response.status != 200:
            status, reason = response.status, response.reason
            self._drain(response)
            sock.close()
            raise ProxyError(f"Tunnel connection failed: {status} {reason}")
        response.close()

        try:
            sock.settimeout(connect_timeout)
            return wrap_tls(sock, self._ssl_context(verify, cert), parts.hostname)
        except ssl.SSLError as exc:
            sock.close()
            raise SSLError(exc) from exc
        except socket.timeout as exc:
            sock.close()
            raise ConnectTimeout(f"TLS handshake timed out with {parts.hostname}") from exc
        except BaseException:
            sock.close()
            raise

    def _exchange(self, connection, payload, method, read_timeout):
        """Envoie une requête sur une connexion et lit l'en-tête de la réponse."""
        connection.sock.settimeout(read_timeout)
        connection.sock.sendall(payload)
        connection.response = self._read_response(connection.sock, method)
        return connection.response

    def _send_https(self, request, parts, proxy_url, connect_timeout, read_timeout, verify, cert):
        """Requête chiffrée dans un tunnel vers le site, réutilisé si possible."""
        key = ("tunnel", proxy_url, parts.hostname.lower(), parts.port or 443, _tls_key(verify, cert))
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        body = self._body_bytes(request)
        payload = self._serialize(request, target, parts, body, [("Connection", "keep-alive")])
        method = request.method.upper()

        connection = self._connections.get(key)
        if connection is not None:
            try:
                return connection, self._exchange(connection, payload, method, read_timeout)
            except (*_STALE_ERRORS, http.client.RemoteDisconnected):
                # Fermée par le site entre-temps : nouvelle connexion
                connection.close()
            except BaseException:
                connection.close()
                raise

        connection = _Connection(self._open_tls_tunnel(proxy_url, parts, connect_timeout, verify, cert), key)
        try:
            return connection, self._exchange(connection, payload, method, read_timeout)
        except socket.timeout as exc:
            connection.close()
            raise ReadTimeout(f"Read timed out from {parts.hostname}") from exc
        except BaseException:
            connection.close()
            raise

    def _send_http(self, request, parts, proxy_url, connect_timeout, read_timeout):
        """Requête HTTP en forme absolue sur une connexion proxy authentifiée."""
        absolute = request.url.split("#", 1)[0]
        body = self._body_bytes(request)

        def write_request(sock, auth_header):
            extra = [("Proxy-Connection", "Keep-Alive"), ("Connection", "Keep-Alive")]
            if auth_header:
                extra.append(("Proxy-Authorization", auth_header))
            sock.sendall(self._serialize(request, absolute, parts, body, extra))

        return self.http_exchange(proxy_url, connect_timeout, read_timeout, write_request,
                                  request.method.upper())

    def http_exchange(self, proxy_url, connect_timeout, read_timeout, write_request, method):
        """
        Envoie une requête http:// en forme absolue au proxy, sur une connexion
        déjà authentifiée si possible, sinon après négociation.

        Utilisé par l'adaptateur et par le proxy local, qui rendent ensuite la
        connexion avec release() (urllib3 le fait pour l'adaptateur).

        Args:
            write_request (callable): (sock, en-tête Proxy-Authorization|None)
                -> None ; envoie la requête complète (corps compris)
            method (str): Méthode (lecture correcte d'une réponse à HEAD)

        Returns:
            tuple: (_Connection, réponse dont le corps reste à lire)
        """
        key = ("http", proxy_url)

        def leg(sock, auth_header):
            write_request(sock, auth_header)
            return self._read_response(sock, method)

        connection = self._connections.get(key)
        if connection is not None:
            try:
                connection.sock.settimeout(read_timeout)
                response = leg(connection.sock, None)
            except (*_STALE_ERRORS, http.client.RemoteDisconnected):
                connection.close()
            except BaseException:
                connection.close()
                raise
            else:
                if response.status != 407:
                    connection.response = response
                    return connection, response
                # Connexion qui n'est plus authentifiée : nouvelle négociation
                self._drain(response)
                connection.close()

        try:
            sock, response = self._negotiate(proxy_url, connect_timeout, leg)
        except socket.timeout as exc:
            raise ReadTimeout(f"Read timed out from proxy {strip_credentials(proxy_url)}") from exc
        sock.settimeout(read_timeout)
        connection = _Connection(sock, key)
        connection.response = response
        return connection, response

    def release(self, connection):
        """Rend une connexion dont la réponse a été lue en entier (sinon elle est fermée)."""
        self._connections.put(connection)

    def _build(self, request, connection, response, method, stream):
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
            # Réponse lue en entier : urllib3 rend la connexion au pool (release_conn)
            pool=self._connections,
            connection=connection,
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
