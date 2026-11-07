"""
Serveurs locaux pour les tests d'intégration :
- un serveur « origine » HTTP / HTTPS qui renvoie ce qu'il reçoit ;
- un proxy HTTP réel (forme absolue + CONNECT) avec authentification
  facultative Basic, NTLM ou Negotiate.

Le proxy redirige tout nom d'hôte vers 127.0.0.1 : les tests utilisent des
noms fictifs (origin.test) qui ne peuvent être joints QUE via le proxy.
"""

import base64
import datetime
import gzip
import http.server
import json
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import time


# ---------------------------------------------------------------------- #
# Certificat auto-signé
# ---------------------------------------------------------------------- #
def make_self_signed_cert(directory):
    """Génère un certificat auto-signé et retourne (cert_path, key_path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("origin.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cert_path, key_path


# ---------------------------------------------------------------------- #
# Serveur origine
# ---------------------------------------------------------------------- #
class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _record(self, body):
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }
        self.server.requests.append(entry)
        return entry

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if status not in (204, 304):
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and status not in (204, 304):
            self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        entry = self._record(body)
        path = self.path.split("?", 1)[0]

        if path == "/cookie":
            self._send(200, b"cookies", [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/")])
        elif path == "/redirect":
            self._send(302, b"", [("Location", "/echo?redirected=1")])
        elif path == "/gzip":
            payload = gzip.compress(json.dumps(entry).encode())
            self._send(200, payload, [("Content-Type", "application/json"), ("Content-Encoding", "gzip")])
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"hello ", b"chunked ", b"world"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/nocontent":
            self._send(204)
        elif path == "/slow":
            time.sleep(2)
            self._send(200, b"slow")
        else:
            payload = json.dumps(entry).encode()
            self._send(200, payload, [("Content-Type", "application/json")])

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _handle


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OriginServer:
    """Serveur origine HTTP ou HTTPS sur 127.0.0.1."""

    def __init__(self, tls=False):
        self.httpd = _ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        self.httpd.requests = []
        self.tls = tls
        if tls:
            self._tmp = tempfile.mkdtemp()
            cert, key = make_self_signed_cert(self._tmp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()

    @property
    def requests(self):
        return self.httpd.requests

    def url(self, path="/echo", host="origin.test"):
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{host}:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------- #
# Proxy
# ---------------------------------------------------------------------- #
def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class ProxyHandler(socketserver.StreamRequestHandler):
    def _respond(self, status, reason, headers=(), body=b"", close=False):
        lines = [f"HTTP/1.1 {status} {reason}"]
        lines += [f"{k}: {v}" for k, v in headers]
        lines.append(f"Content-Length: {len(body)}")
        if close:
            lines.append("Connection: close")
        self.wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        self.wfile.flush()

    def _deny(self, challenge_headers, close=False):
        self.server.denied += 1
        self._respond(407, "Proxy Authentication Required", challenge_headers, b"<h1>407</h1>", close)

    def _check_auth(self, header, state):
        """Retourne True si la requête est autorisée (sinon répond 407)."""
        mode = self.server.auth
        if mode is None or state.get("authed"):
            return True

        if mode == "basic":
            expected = "Basic " + base64.b64encode(
                f"{self.server.username}:{self.server.password}".encode()).decode()
            if header == expected:
                return True
            self._deny([("Proxy-Authenticate", 'Basic realm="test"')])
            return False

        # NTLM / Negotiate
        import spnego

        offered = [("Proxy-Authenticate", "Negotiate")] if mode == "negotiate" else \
            [("Proxy-Authenticate", "NTLM"), ("Proxy-Authenticate", 'Basic realm="test"')]
        if not header:
            state.pop("ctx", None)
            self._deny(offered, close=self.server.close_on_challenge_request)
            return False
        scheme, _, token = header.partition(" ")
        if "ctx" not in state:
            state["ctx"] = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
        try:
            out = state["ctx"].step(base64.b64decode(token))
        except Exception:
            state.pop("ctx", None)
            self._deny(offered)
            return False
        if state["ctx"].complete:
            state["authed"] = True
            return True
        self._deny([("Proxy-Authenticate", f"{scheme} {base64.b64encode(out).decode()}")])
        return False

    def handle(self):
        state = {}
        while True:
            line = self.rfile.readline()
            if not line or not line.strip():
                return
            method, target, _ = line.decode("latin-1").split(" ", 2)
            headers = []
            while True:
                h = self.rfile.readline().decode("latin-1").rstrip("\r\n")
                if not h:
                    break
                name, _, value = h.partition(":")
                headers.append((name.strip(), value.strip()))
            hdict = {k.lower(): v for k, v in headers}
            length = int(hdict.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""

            self.server.log.append({"method": method, "target": target, "headers": hdict})

            if not self._check_auth(hdict.get("proxy-authorization"), state):
                continue

            # Cible de la sonde d'IziProxy : répondre tout de suite
            if "example.com" in target:
                self._respond(502, "Bad Gateway", close=True)
                return

            if method == "CONNECT":
                port = int(target.rsplit(":", 1)[1])
                try:
                    upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
                except OSError:
                    self._respond(502, "Bad Gateway", close=True)
                    return
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.wfile.flush()
                upstream.settimeout(None)
                t = threading.Thread(target=_pipe, args=(upstream, self.connection), daemon=True)
                t.start()
                _pipe(self.connection, upstream)
                t.join(5)
                return

            # Requête HTTP en forme absolue : relayer vers 127.0.0.1:port
            from urllib.parse import urlsplit

            parts = urlsplit(target)
            if not parts.scheme:
                self._respond(400, "Bad Request", close=True)
                return
            try:
                upstream = socket.create_connection(("127.0.0.1", parts.port or 80), timeout=5)
            except OSError:
                self._respond(502, "Bad Gateway", close=True)
                return
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            out = [f"{method} {path} HTTP/1.1"]
            for name, value in headers:
                if name.lower() in ("proxy-authorization", "proxy-connection", "connection"):
                    continue
                out.append(f"{name}: {value}")
            out.append("Connection: close")
            upstream.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
            try:
                while True:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    self.wfile.write(data)
                self.wfile.flush()
            finally:
                upstream.close()
            return


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyServer:
    """
    Proxy HTTP local.

    Args:
        auth: None, 'basic', 'ntlm' ou 'negotiate'
    """

    def __init__(self, auth=None, username="alice", password="S3cret!", domain="CORP",
                 close_on_challenge_request=False):
        self.server = _ThreadingTCPServer(("127.0.0.1", 0), ProxyHandler)
        self.server.auth = auth
        self.server.username = username
        self.server.password = password
        self.server.log = []
        self.server.denied = 0
        self.server.close_on_challenge_request = close_on_challenge_request
        self.username, self.password, self.domain = username, password, domain
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()

    @property
    def log(self):
        """Requêtes reçues, hors sonde d'authentification d'IziProxy."""
        return [entry for entry in self.server.log if "example.com" not in entry["target"]]

    @property
    def raw_log(self):
        return self.server.log

    @property
    def denied(self):
        return self.server.denied

    def close(self):
        self.server.shutdown()
        self.server.server_close()
