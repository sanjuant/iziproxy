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
leurs variables d'environnement vers http://127.0.0.1:<port>.

Limites : une requête HTTP par connexion cliente (la réponse est renvoyée
avec « Connection: close ») ; le proxy n'exige aucune authentification de
ses clients et n'écoute que sur la boucle locale.
"""

import base64
import http.client
import logging
import socket
import socketserver
import ssl
import threading
from urllib.parse import urlsplit

from .ntlm_auth import NtlmProxyAdapter
from .proxy_utils import extract_credentials, normalize_proxy_url, proxy_host_port

logger = logging.getLogger("iziproxy")

LISTEN_HOST = "127.0.0.1"

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


class _BadRequest(Exception):
    """Requête cliente invalide (réponse 400)."""


class _LoopDetected(Exception):
    """La route choisie renvoie vers le proxy local lui-même."""


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
    while True:
        size_line = _read_line(rfile).split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError as exc:
            raise _BadRequest("Invalid chunk size") from exc
        if size == 0:
            # Trailers éventuels, terminés par une ligne vide
            while _read_line(rfile).strip():
                pass
            return b"".join(chunks)
        chunks.append(rfile.read(size))
        rfile.read(2)  # CRLF de fin de bloc


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
        try:
            length = int(length)
        except ValueError as exc:
            raise _BadRequest("Invalid Content-Length") from exc
        return rfile.read(length)
    return b""


def _split_authority(authority):
    """« hôte:port » ou « [ipv6]:port » -> (hôte, port)."""
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = authority.rpartition(":")
    if not host or not port.isdigit():
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
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _Handler(socketserver.StreamRequestHandler):
    """Traite une connexion cliente (une requête HTTP ou un tunnel)."""

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.local_proxy.timeout)

    # -------------------------------------------------------------- #
    # Réponses locales
    # -------------------------------------------------------------- #
    def _reply(self, status, reason, message=""):
        body = (message + "\n").encode("utf-8") if message else b""
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n")
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
            try:
                method, target, _version = line.decode("latin-1").strip().split(" ", 2)
            except ValueError as exc:
                raise _BadRequest("Invalid request line") from exc
            method = method.upper()
            headers = _read_headers(self.rfile)

            if method == "CONNECT":
                self._handle_connect(proxy, target)
            else:
                self._handle_http(proxy, method, target, headers)
        except _BadRequest as exc:
            self._reply(400, "Bad Request", str(exc))
        except _LoopDetected as exc:
            self._reply(508, "Loop Detected", str(exc))
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


class LocalProxy:
    """
    Proxy local qui relaie vers la route choisie par une instance IziProxy.

    Ne pas instancier directement : utiliser IziProxy.start_local_proxy().

    Exemple :
        >>> with IziProxy().start_local_proxy() as local:
        ...     subprocess.run(["pip", "install", "x"],
        ...                    env=dict(os.environ, HTTPS_PROXY=local.url))
    """

    def __init__(self, izi, port=0, timeout=30.0):
        """
        Args:
            izi (IziProxy): Instance qui fournit la route et les identifiants
            port (int): Port d'écoute sur 127.0.0.1 (0 : port libre au hasard)
            timeout (float): Délai de connexion / lecture vers l'amont (secondes)
        """
        self.izi = izi
        self.timeout = timeout
        self._ntlm_adapter = None
        self._lock = threading.Lock()
        self._server = _Server((LISTEN_HOST, port), _Handler)
        self._server.local_proxy = self
        self.host, self.port = self._server.server_address[:2]
        self._thread = None

    def __repr__(self):
        state = "running" if self.running else "stopped"
        return f"LocalProxy(url={self.url!r}, {state})"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    @property
    def url(self):
        """URL à placer dans HTTP(S)_PROXY."""
        return f"http://{self.host}:{self.port}"

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
            logger.info("Local proxy listening on %s", self.url)
        return self

    def stop(self):
        """Arrête le proxy (les tunnels déjà ouverts se terminent seuls)."""
        if self._thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()
        self._thread = None
        if self._ntlm_adapter is not None:
            self._ntlm_adapter.close()
        logger.info("Local proxy on %s stopped", self.url)

    # -------------------------------------------------------------- #
    # Choix de la route
    # -------------------------------------------------------------- #
    def _route(self, url):
        """
        Retourne (url_du_proxy|None, mode) pour une URL cible.

        mode : 'direct', 'ntlm' ou 'basic' (Basic sans identifiants = aucun en-tête)
        """
        proxies = self.izi._raw_proxies(url)
        scheme = urlsplit(url).scheme
        proxy = proxies.get(scheme) or proxies.get("https") or proxies.get("http")
        if not proxy:
            return None, "direct"
        host, port = proxy_host_port(proxy)
        if port == self.port and host in (LISTEN_HOST, "localhost", "::1"):
            raise _LoopDetected(f"The proxy chosen for {url} is this local proxy ({self.url})")
        if self.izi._uses_ntlm():
            return proxy, "ntlm"
        return proxy, "basic"

    def _ntlm(self):
        with self._lock:
            if self._ntlm_adapter is None:
                self._ntlm_adapter = self.izi._create_ntlm_adapter()
            return self._ntlm_adapter

    def _basic_header(self, url, proxy):
        """En-tête Proxy-Authorization Basic (UTF-8), ou None."""
        resolved = self.izi._resolve(url)
        candidate = resolved.get(urlsplit(url).scheme) or proxy
        username, password = extract_credentials(candidate)
        if not username:
            return None
        token = f"{username}:{password or ''}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")

    def _connect(self, host, port, tls_host=None):
        sock = socket.create_connection((host, port), timeout=self.timeout)
        if tls_host:
            try:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=tls_host)
            except Exception:
                sock.close()
                raise
        return sock

    def _connect_proxy(self, proxy):
        host, port = proxy_host_port(proxy)
        tls = normalize_proxy_url(proxy).lower().startswith("https://")
        return self._connect(host, port, tls_host=host if tls else None)

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
        logger.debug("Local proxy: CONNECT %s via %s", authority, proxy or "direct")

        if mode == "direct":
            return self._connect(host, port), None

        if mode == "ntlm":
            proxy_host, proxy_port = proxy_host_port(proxy)
            sock, response = self._ntlm().open_tunnel(proxy_host, proxy_port, authority, self.timeout)
            return self._tunnel_result(sock, response)

        sock = self._connect_proxy(proxy)
        try:
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
            auth = self._basic_header(url, proxy)
            if auth:
                lines.append(f"Proxy-Authorization: {auth}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            response = http.client.HTTPResponse(sock, method="CONNECT")
            response.begin()
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
        logger.debug("Local proxy: %s %s via %s", method, absolute, proxy or "direct")

        if mode == "ntlm":
            proxy_host, proxy_port = proxy_host_port(proxy)

            def http_leg(sock, auth_header):
                extra = [("Proxy-Connection", "Keep-Alive"), ("Connection", "Keep-Alive")]
                if auth_header:
                    extra.append(("Proxy-Authorization", auth_header))
                sock.sendall(self._serialize(method, absolute, parts, headers, body, extra))
                return NtlmProxyAdapter._read_response(sock, method)

            sock, response = self._ntlm()._negotiate(proxy_host, proxy_port, self.timeout, http_leg)
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
