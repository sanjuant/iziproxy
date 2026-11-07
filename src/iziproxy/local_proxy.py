"""
Proxy local de relais (à la manière de cntlm / px).

Beaucoup d'outils (pip, git, curl, conda...) ne savent lire que les
variables HTTP(S)_PROXY et ne parlent pas NTLM. Ce module démarre un petit
proxy HTTP sur 127.0.0.1 qui :

- accepte les requêtes HTTP en forme absolue et les tunnels CONNECT ;
- choisit, pour chaque URL, la même route qu'IziProxy (no_proxy, PAC,
  connexion directe) ;
- s'authentifie auprès du proxy d'entreprise à la place du client
  (NTLM / Negotiate via pyspnego, ou Basic).

Les clients n'ont donc besoin d'aucun identifiant : il suffit de pointer
leurs variables d'environnement vers http://127.0.0.1:<port> (3128 par
défaut, comme cntlm).

Sécurité : le proxy n'écoute que sur la boucle locale et, par défaut, exige
un jeton aléatoire (Basic, utilisateur « iziproxy »). Ce jeton figure dans
``LocalProxy.url`` : les clients qui reçoivent cette URL l'envoient d'eux-
mêmes, tandis qu'un autre utilisateur de la machine (poste partagé, serveur
Citrix) ne peut pas emprunter votre identité auprès du proxy d'entreprise.

Limites : une requête HTTP par connexion cliente (la réponse est renvoyée
avec « Connection: close ») ; pas de relais vers un proxy SOCKS.
"""

import base64
import binascii
import hmac
import http.client
import ipaddress
import logging
import re
import secrets
import socket
import socketserver
import threading
from urllib.parse import urlsplit

from .ntlm_auth import NtlmProxyAdapter
from .proxy_utils import (
    basic_proxy_authorization,
    is_https_proxy,
    proxy_host_port,
    read_tunnel_response,
    strip_credentials,
)

logger = logging.getLogger("iziproxy")

LISTEN_HOST = "127.0.0.1"
# Port par défaut de IziProxy.start_local_proxy() : celui de cntlm et squid,
# déjà connu de la plupart des outils configurés pour un proxy local
DEFAULT_PORT = 3128

# Nom d'utilisateur placé devant le jeton dans l'URL du proxy local
TOKEN_USERNAME = "iziproxy"
# Caractères autorisés dans un jeton fourni (aucun encodage d'URL nécessaire)
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~-]{16,}")

# En-têtes propres à un saut (RFC 9110 §7.6.1) : jamais relayés tels quels
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-connection", "proxy-authorization",
    "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
}
# En-têtes de requête recalculés par le proxy local
_REQUEST_SKIP = _HOP_BY_HOP | {"content-length", "expect"}

_MAX_LINE = 65536
_MAX_HEADERS = 200
_BUFFER = 65536
# Corps d'une requête http:// (les tunnels CONNECT ne sont pas concernés),
# lu en mémoire pour pouvoir être rejoué pendant la négociation NTLM
MAX_BODY = 100 * 1024 * 1024
# Connexions clientes simultanées (un thread chacune)
MAX_CONNECTIONS = 256
# Caractères de contrôle interdits dans la ligne de requête et les en-têtes :
# un « \r » isolé serait pris pour une fin de ligne par certains proxys amont
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
# Nombres (Content-Length, port) : chiffres ASCII seulement ; str.isdigit()
# accepte « ² », que int() refuse ensuite
_DIGITS_RE = re.compile(r"[0-9]+")
# Hôte d'une cible CONNECT (hors IPv6 entre crochets) : nom DNS ou IPv4. Un
# « @ » ou un « / » ferait choisir la route d'un autre hôte que celui joint
_HOST_RE = re.compile(r"[A-Za-z0-9._-]+")


class _BadRequest(Exception):
    """Requête cliente invalide (réponse 400)."""


class _LoopDetected(Exception):
    """La route choisie renvoie vers le proxy local lui-même."""


class _UnsupportedRoute(Exception):
    """La route choisie passe par un proxy que le proxy local ne sait pas joindre."""


class _BodyTooLarge(Exception):
    """Corps de requête supérieur à MAX_BODY (réponse 413)."""


def _is_local_address(host):
    """Boucle locale ou adresse « toutes interfaces » (127.0.0.0/8, ::1, 0.0.0.0, localhost)."""
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


# ---------------------------------------------------------------------- #
# Lecture de la requête cliente
# ---------------------------------------------------------------------- #
def _read_line(rfile):
    line = rfile.readline(_MAX_LINE + 1)
    if len(line) > _MAX_LINE:
        raise _BadRequest("Line too long")
    return line


def _read_headers(rfile):
    """Lit les en-têtes jusqu'à la ligne vide ; retourne une liste (nom, valeur)."""
    headers = []
    while True:
        line = _read_line(rfile)
        if not line:
            raise _BadRequest("Connection closed while reading headers")
        line = line.decode("latin-1").rstrip("\r\n")
        if not line:
            return headers
        if _CONTROL_RE.search(line):
            raise _BadRequest("Control character in header")
        if line[0] in " \t" and headers:
            # Ligne de continuation (obsolète mais tolérée)
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {line.strip()}")
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise _BadRequest(f"Invalid header line: {line!r}")
        headers.append((name.strip(), value.strip()))
        if len(headers) > _MAX_HEADERS:
            raise _BadRequest("Too many headers")


def _read_chunked(rfile):
    """Décode un corps « chunked » (les trailers sont ignorés)."""
    chunks = []
    total = 0
    while True:
        size_line = _read_line(rfile).split(b";", 1)[0].strip()
        # int(…, 16) accepterait « -1 », « +5 » ou « 0x10 »
        if not size_line or size_line.strip(b"0123456789abcdefABCDEF"):
            raise _BadRequest("Invalid chunk size")
        size = int(size_line, 16)
        total += size
        if total > MAX_BODY:
            raise _BodyTooLarge()
        if size == 0:
            # Trailers éventuels, terminés par une ligne vide
            while _read_line(rfile).strip():
                pass
            return b"".join(chunks)
        chunks.append(_read_exact(rfile, size))
        if _read_exact(rfile, 2) != b"\r\n":
            raise _BadRequest("Invalid chunk terminator")


def _read_exact(rfile, size):
    """Lit exactement size octets (une connexion fermée avant est une erreur)."""
    data = rfile.read(size)
    if len(data) != size:
        raise _BadRequest("Connection closed before the end of the body")
    return data


def _header(headers, name):
    """Valeur d'un en-tête (insensible à la casse), ou None."""
    name = name.lower()
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _read_body(rfile, headers):
    if "chunked" in (_header(headers, "Transfer-Encoding") or "").lower():
        return _read_chunked(rfile)
    length = _header(headers, "Content-Length")
    if length:
        # int() accepterait « -1 » ou « +5 » : rfile.read(-1) lirait jusqu'à la fermeture
        if not _DIGITS_RE.fullmatch(length.strip()):
            raise _BadRequest("Invalid Content-Length")
        if int(length) > MAX_BODY:
            raise _BodyTooLarge()
        return _read_exact(rfile, int(length))
    return b""


def _split_authority(authority):
    """« hôte:port » ou « [ipv6]:port » -> (hôte, port)."""
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        try:
            valid_host = ipaddress.ip_address(host).version == 6
        except ValueError:
            valid_host = False
    else:
        host, _, port = authority.rpartition(":")
        valid_host = bool(_HOST_RE.fullmatch(host))
    if not valid_host or not _DIGITS_RE.fullmatch(port) or not 0 < int(port) < 65536:
        raise _BadRequest(f"Invalid CONNECT target: {authority!r}")
    return host, int(port)


# ---------------------------------------------------------------------- #
# Relais des octets
# ---------------------------------------------------------------------- #
def _pipe(read, dst):
    """Copie les octets de read() vers dst jusqu'à la fin, puis ferme l'écriture."""
    try:
        while True:
            data = read(_BUFFER)
            if not data:
                break
            dst.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            # socket.socket.shutdown et non dst.shutdown : sur une SSLSocket
            # (proxy https://), ce dernier abandonnerait la session TLS alors
            # que l'autre sens du tunnel la lit encore
            socket.socket.shutdown(dst, socket.SHUT_WR)
        except OSError:
            pass


class _Handler(socketserver.StreamRequestHandler):
    """Traite une connexion cliente (une requête HTTP ou un tunnel)."""

    def setup(self):
        super().setup()
        self.replied = False
        self.connection.settimeout(self.server.local_proxy.timeout)

    # -------------------------------------------------------------- #
    # Réponses locales
    # -------------------------------------------------------------- #
    def _reply(self, status, reason, message="", extra_headers=()):
        if self.replied:
            # Une réponse est déjà partie : une seconde corromprait le flux
            return
        self.replied = True
        body = (message + "\n").encode("utf-8") if message else b""
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                + "".join(f"{name}: {value}\r\n" for name, value in extra_headers)
                + "Connection: close\r\n\r\n")
        try:
            self.wfile.write(head.encode("latin-1") + body)
            self.wfile.flush()
        except OSError:
            pass

    def _relay_response(self, response, method):
        """Renvoie au client une réponse lue par http.client."""
        lines = [f"HTTP/1.1 {response.status} {response.reason}"]
        chunked = getattr(response, "chunked", False)
        for name, value in response.getheaders():
            lower = name.lower()
            if lower in _HOP_BY_HOP and lower != "proxy-authenticate":
                continue
            if lower == "content-length" and chunked:
                continue
            lines.append(f"{name}: {value}")
        # Le corps est renvoyé tel quel puis la connexion est fermée
        lines.append("Connection: close")
        self.replied = True
        self.wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        if method != "HEAD" and response.status not in (204, 304):
            while True:
                data = response.read1(_BUFFER)
                if not data:
                    break
                self.wfile.write(data)
        self.wfile.flush()

    # -------------------------------------------------------------- #
    # Point d'entrée
    # -------------------------------------------------------------- #
    def handle(self):
        proxy = self.server.local_proxy
        try:
            line = _read_line(self.rfile)
            if not line.strip():
                return
            line = line.decode("latin-1").rstrip("\r\n")
            if _CONTROL_RE.search(line):
                raise _BadRequest("Control character in the request line")
            try:
                method, target, _version = line.strip().split(" ", 2)
            except ValueError as exc:
                raise _BadRequest("Invalid request line") from exc
            method = method.upper()
            headers = _read_headers(self.rfile)

            if not proxy._authorized(headers):
                self._reply(407, "Proxy Authentication Required",
                            "This local proxy requires the token included in its URL",
                            [("Proxy-Authenticate", f'Basic realm="{TOKEN_USERNAME}"')])
                return

            if method == "CONNECT":
                self._handle_connect(proxy, target)
            else:
                self._handle_http(proxy, method, target, headers)
        except _BadRequest as exc:
            self._reply(400, "Bad Request", str(exc))
        except _BodyTooLarge:
            self._reply(413, "Content Too Large", f"Request bodies are limited to {MAX_BODY} bytes")
        except _LoopDetected as exc:
            self._reply(508, "Loop Detected", str(exc))
        except _UnsupportedRoute as exc:
            self._reply(502, "Bad Gateway", str(exc))
        except socket.timeout as exc:
            logger.debug("Local proxy: timeout (%s)", exc)
            self._reply(504, "Gateway Timeout", "Upstream timed out")
        except Exception as exc:  # noqa: BLE001 - toute erreur devient une 502 pour le client
            logger.debug("Local proxy: upstream error: %s", exc)
            self._reply(502, "Bad Gateway", str(exc))

    # -------------------------------------------------------------- #
    # CONNECT
    # -------------------------------------------------------------- #
    def _handle_connect(self, proxy, authority):
        host, port = _split_authority(authority)
        upstream, refusal = proxy._open_tunnel(host, port, authority)
        if refusal is not None:
            # Refus du proxy amont : relayer sa réponse
            try:
                self._relay_response(refusal, "CONNECT")
            finally:
                refusal.close()
                upstream.close()
            return

        try:
            self.replied = True
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            upstream.settimeout(None)
            self.connection.settimeout(None)
            # Le client peut avoir déjà envoyé des octets lus dans le tampon : read1 les rend
            back = threading.Thread(target=_pipe, args=(upstream.recv, self.connection), daemon=True)
            back.start()
            _pipe(self.rfile.read1, upstream)
            back.join()
        finally:
            upstream.close()

    # -------------------------------------------------------------- #
    # HTTP en forme absolue
    # -------------------------------------------------------------- #
    def _handle_http(self, proxy, method, target, headers):
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.hostname:
            raise _BadRequest("Only absolute http:// URLs and CONNECT are supported")
        try:
            parts.port  # noqa: B018 - ValueError pour un port invalide
        except ValueError as exc:
            raise _BadRequest(f"Invalid port in {target!r}") from exc
        length = (_header(headers, "Content-Length") or "").strip()
        if _DIGITS_RE.fullmatch(length) and int(length) > MAX_BODY:
            raise _BodyTooLarge()
        if "100-continue" in (_header(headers, "Expect") or "").lower():
            # Le client attend ce feu vert avant d'envoyer le corps (curl : 1 s sinon)
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.wfile.flush()
        body = _read_body(self.rfile, headers)
        sock, response = proxy._forward_http(method, target, parts, headers, body)
        try:
            self._relay_response(response, method)
        finally:
            response.close()
            sock.close()


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Au-delà de MAX_CONNECTIONS, refus immédiat plutôt qu'un thread de plus
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class LocalProxy:
    """
    Proxy local qui relaie vers la route choisie par une instance IziProxy.

    Ne pas instancier directement : utiliser IziProxy.start_local_proxy().

    Attributs : ``url`` (à placer dans HTTP(S)_PROXY, jeton inclus),
    ``address`` (sans jeton), ``host``, ``port``, ``token``, ``running``.

    Exemple :
        >>> with IziProxy().start_local_proxy() as local:
        ...     subprocess.run(["pip", "install", "x"],
        ...                    env=dict(os.environ, HTTPS_PROXY=local.url))
    """

    def __init__(self, izi, port=0, timeout=30.0, token=True):
        """
        Args:
            izi (IziProxy): Instance qui fournit la route et les identifiants
            port (int): Port d'écoute sur 127.0.0.1 (0 : port libre au hasard)
            timeout (float): Délai de connexion / lecture vers l'amont (secondes)
            token (bool|str): Jeton exigé des clients. True (défaut) : jeton
                aléatoire ; une chaîne : ce jeton (16 caractères ou plus parmi
                lettres, chiffres et ``._~-``) ; False : aucun contrôle, tout
                processus local peut alors utiliser votre identité
        """
        if token is True:
            token = secrets.token_urlsafe(24)
        elif not token:
            token = None
        elif not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise ValueError("token must be True, False or a string of at least 16 characters "
                             "among letters, digits and ._~-")
        self.token = token
        self.izi = izi
        self.timeout = timeout
        self._ntlm_adapter = None
        self._ntlm_generation = None
        self._lock = threading.Lock()
        try:
            self._server = _Server((LISTEN_HOST, port), _Handler)
        except OSError as exc:
            # Port déjà pris (autre proxy local, cntlm, seconde instance...)
            raise OSError(exc.errno, f"Cannot listen on {LISTEN_HOST}:{port} ({exc.strerror or exc}); "
                                     "choose another port with start_local_proxy(port=...) "
                                     "or port=0 for any free port") from exc
        self._server.local_proxy = self
        self.host, self.port = self._server.server_address[:2]
        self._thread = None

    def __repr__(self):
        state = "running" if self.running else "stopped"
        protection = "token" if self.token else "no token"
        return f"LocalProxy(address={self.address!r}, {protection}, {state})"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    @property
    def address(self):
        """Adresse du proxy sans jeton (http://127.0.0.1:port), pour l'affichage."""
        return f"http://{self.host}:{self.port}"

    @property
    def url(self):
        """URL à placer dans HTTP(S)_PROXY (jeton inclus s'il est exigé)."""
        if self.token is None:
            return self.address
        return f"http://{TOKEN_USERNAME}:{self.token}@{self.host}:{self.port}"

    def _authorized(self, headers):
        """Vérifie le jeton envoyé par le client (Proxy-Authorization Basic)."""
        if self.token is None:
            return True
        scheme, _, encoded = (_header(headers, "Proxy-Authorization") or "").strip().partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        _, _, password = decoded.partition(":")
        # Comparaison à temps constant : la durée ne renseigne pas sur le jeton
        return hmac.compare_digest(password.encode("utf-8"), self.token.encode("utf-8"))

    @property
    def running(self):
        """True tant que le proxy accepte des connexions."""
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """Démarre l'écoute dans un thread d'arrière-plan."""
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name=f"iziproxy-local-{self.port}",
                daemon=True,
            )
            self._thread.start()
            logger.info("Local proxy listening on %s (%s)", self.address,
                        "token required" if self.token else "no token: open to every local process")
        return self

    def serve_forever(self):
        """
        Bloque jusqu'à Ctrl+C ou stop(), puis arrête le proxy.

        Pour un script dont le seul rôle est de faire tourner le proxy local
        (remplaçant de cntlm) ; démarre le proxy s'il ne l'est pas encore.
        """
        self.start()
        thread = self._thread
        try:
            # join() par petites tranches : Ctrl+C reste pris en compte sous Windows
            while thread is not None and thread.is_alive():
                thread.join(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Arrête le proxy (les tunnels déjà ouverts se terminent seuls)."""
        # Un seul appelant effectue l'arrêt (stop() concurrent, serve_forever())
        with self._lock:
            thread, self._thread = self._thread, None
        if thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        thread.join()
        if self._ntlm_adapter is not None:
            self._ntlm_adapter.close()
        logger.info("Local proxy on %s stopped", self.address)

    # -------------------------------------------------------------- #
    # Choix de la route
    # -------------------------------------------------------------- #
    def _route(self, url):
        """
        Retourne (url_du_proxy|None, mode) pour une URL cible.

        mode : 'direct', 'ntlm' ou 'basic' (Basic sans identifiants = aucun en-tête)
        """
        proxy, mode = self.izi._route(url)
        if not proxy:
            return None, "direct"
        scheme = urlsplit(proxy).scheme.lower()
        if scheme not in ("http", "https"):
            raise _UnsupportedRoute(f"The local proxy cannot relay through a {scheme}:// proxy "
                                    f"(chosen for {url})")
        host, port = proxy_host_port(proxy)
        if port == self.port and _is_local_address(host):
            raise _LoopDetected(f"The proxy chosen for {url} is this local proxy ({self.address})")
        return proxy, "ntlm" if mode == "ntlm" else "basic"

    def _ntlm(self):
        """Adaptateur NTLM partagé, recréé si les identifiants ont été oubliés."""
        with self._lock:
            generation = self.izi._auth_generation
            if self._ntlm_adapter is None or self._ntlm_generation != generation:
                if self._ntlm_adapter is not None:
                    self._ntlm_adapter.close()
                self._ntlm_adapter = self.izi._create_ntlm_adapter()
                self._ntlm_generation = generation
            return self._ntlm_adapter

    def _basic_header(self, url, proxy):
        """En-tête Proxy-Authorization Basic (UTF-8), ou None."""
        resolved = self.izi._resolve(url)
        return basic_proxy_authorization(resolved.get(urlsplit(url).scheme) or proxy)

    def _connect(self, host, port, tls_host=None):
        sock = socket.create_connection((host, port), timeout=self.timeout)
        if tls_host:
            try:
                sock = self.izi._proxy_ssl_context().wrap_socket(sock, server_hostname=tls_host)
            except Exception:
                sock.close()
                raise
        return sock

    def _connect_proxy(self, proxy):
        host, port = proxy_host_port(proxy)
        return self._connect(host, port, tls_host=host if is_https_proxy(proxy) else None)

    # -------------------------------------------------------------- #
    # Tunnels
    # -------------------------------------------------------------- #
    def _open_tunnel(self, host, port, authority):
        """
        Ouvre la connexion amont d'un tunnel CONNECT.

        Returns:
            tuple: (socket, None) si le tunnel est prêt, ou (socket, réponse)
            si le proxy amont l'a refusé
        """
        url = f"https://{authority}/"
        proxy, mode = self._route(url)
        logger.debug("Local proxy: CONNECT %s via %s", authority, strip_credentials(proxy) or "direct")

        if mode == "direct":
            return self._connect(host, port), None

        if mode == "ntlm":
            sock, response = self._ntlm().open_tunnel(proxy, authority, self.timeout)
            return self._tunnel_result(sock, response)

        sock = self._connect_proxy(proxy)
        try:
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
            auth = self._basic_header(url, proxy)
            if auth:
                lines.append(f"Proxy-Authorization: {auth}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            # Les octets qui suivent un 200 (bannière SSH...) restent dans le socket
            response = read_tunnel_response(sock)
        except Exception:
            sock.close()
            raise
        return self._tunnel_result(sock, response)

    @staticmethod
    def _tunnel_result(sock, response):
        if response.status == 200:
            response.close()
            return sock, None
        return sock, response

    # -------------------------------------------------------------- #
    # Requêtes HTTP
    # -------------------------------------------------------------- #
    @staticmethod
    def _serialize(method, target, parts, headers, body, extra):
        lines = [f"{method} {target} HTTP/1.1"]
        connection_tokens = {t.strip().lower() for t in (_header(headers, "Connection") or "").split(",")}
        has_host = False
        for name, value in headers:
            lower = name.lower()
            if lower in _REQUEST_SKIP or lower in connection_tokens:
                continue
            has_host = has_host or lower == "host"
            lines.append(f"{name}: {value}")
        if not has_host:
            lines.append(f"Host: {parts.netloc.rsplit('@', 1)[-1]}")
        if body or method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(body)}")
        lines.extend(f"{name}: {value}" for name, value in extra)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    def _forward_http(self, method, target, parts, headers, body):
        """
        Envoie une requête HTTP vers sa route.

        Returns:
            tuple: (socket, http.client.HTTPResponse dont le corps reste à lire)
        """
        absolute = target.split("#", 1)[0]
        proxy, mode = self._route(absolute)
        logger.debug("Local proxy: %s %s via %s", method, absolute, strip_credentials(proxy) or "direct")

        if mode == "ntlm":
            def http_leg(sock, auth_header):
                extra = [("Proxy-Connection", "Keep-Alive"), ("Connection", "Keep-Alive")]
                if auth_header:
                    extra.append(("Proxy-Authorization", auth_header))
                sock.sendall(self._serialize(method, absolute, parts, headers, body, extra))
                return NtlmProxyAdapter._read_response(sock, method)

            sock, response = self._ntlm()._negotiate(proxy, self.timeout, http_leg)
            sock.settimeout(self.timeout)
            return sock, response

        if mode == "direct":
            sock = self._connect(parts.hostname, parts.port or 80)
            target = parts.path or "/"
            if parts.query:
                target += "?" + parts.query
            extra = [("Connection", "close")]
        else:
            sock = self._connect_proxy(proxy)
            target = absolute
            extra = [("Connection", "close")]
            auth = self._basic_header(absolute, proxy)
            if auth:
                extra.append(("Proxy-Authorization", auth))
        try:
            sock.sendall(self._serialize(method, target, parts, headers, body, extra))
            response = http.client.HTTPResponse(sock, method=method)
            response.begin()
        except Exception:
            sock.close()
            raise
        return sock, response
