"""
Tests de non-régression de la revue complète du 2026-11-07 (bugs et
sécurité) : en-tête Proxy-Authorization ajouté par requests lors des
redirections, sonde d'authentification en échec, tunnels CONNECT dont le
serveur parle en premier, exceptions du chemin NTLM, validation de la
configuration.
"""

import http.server
import logging
import socket
import socketserver
import threading

import pytest
import requests

import iziproxy
from iziproxy import IziProxy, proxy_manager
from iziproxy.config_manager import ConfigManager
from iziproxy.env_detector import EnvironmentDetector

from test_hardening import raw_status, token_line


# ---------------------------------------------------------------------- #
# Serveurs factices
# ---------------------------------------------------------------------- #
class Redirector:
    """Serveur HTTP dont toute URL redirige (302) vers ``location``."""

    def __init__(self, location):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                # Le proxy de test ferme la connexion après chaque réponse
                self.send_header("Connection", "close")
                self.end_headers()

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ScriptedProxy:
    """
    Proxy amont factice. La sonde d'IziProxy (HEAD http://example.com/)
    reçoit une 502 (pas d'authentification exigée) ; les autres requêtes
    sont confiées à ``on_request(conn, head)``.
    """

    def __init__(self, on_request):
        self.on_request = on_request
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            conn.settimeout(10)
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    head += chunk
                if b"example.com" in head.split(b"\r\n", 1)[0]:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                self.on_request(conn, head)
            except OSError:
                pass

    def close(self):
        self.sock.close()


@pytest.fixture
def redirector():
    servers = []

    def factory(location):
        server = Redirector(location)
        servers.append(server)
        return server

    yield factory
    for server in servers:
        server.close()


# ---------------------------------------------------------------------- #
# Proxy-Authorization ajouté par requests lors d'une redirection
# ---------------------------------------------------------------------- #
def test_redirect_to_a_direct_host_does_not_leak_env_proxy_credentials(
        make_proxy, origin, redirector, monkeypatch):
    # requests (trust_env) recopie les identifiants de HTTP_PROXY dans un en-tête
    # Proxy-Authorization lors d'une redirection http:// ; IziProxy envoie la
    # nouvelle URL en direct : l'en-tête ne doit pas partir vers le site
    proxy = make_proxy()
    target = redirector(f"http://127.0.0.1:{origin.port}/echo")
    monkeypatch.setenv("HTTP_PROXY", f"http://alice:S3cret!@127.0.0.1:{proxy.port}")
    izi = IziProxy(proxy_url=proxy.url)
    with izi.create_session() as session:
        response = session.get(f"http://redirector.test:{target.port}/go", timeout=10)
    assert response.status_code == 200
    assert proxy.log, "the first request did not go through the proxy"
    assert "proxy-authorization" not in origin.requests[-1]["headers"]


def test_install_does_not_leak_the_local_proxy_token_on_redirects(make_proxy, origin, redirector):
    proxy = make_proxy()
    target = redirector(f"http://127.0.0.1:{origin.port}/echo")
    with iziproxy.install(proxy_url=proxy.url):
        response = requests.get(f"http://redirector.test:{target.port}/go", timeout=10)
    assert response.status_code == 200
    assert "proxy-authorization" not in origin.requests[-1]["headers"]


def test_redirect_through_an_unauthenticated_proxy_drops_the_header(make_proxy, origin, redirector,
                                                                    monkeypatch):
    # Même chose quand la nouvelle URL passe par un proxy sans identifiants
    proxy = make_proxy()
    target = redirector(origin.url())
    monkeypatch.setenv("HTTP_PROXY", "http://alice:S3cret!@other-proxy.test:3128")
    izi = IziProxy(proxy_url=proxy.url)
    with izi.create_session() as session:
        response = session.get(f"http://redirector.test:{target.port}/go", timeout=10)
    assert response.status_code == 200
    assert all("proxy-authorization" not in entry["headers"] for entry in proxy.log)
    assert "proxy-authorization" not in origin.requests[-1]["headers"]


# ---------------------------------------------------------------------- #
# Sonde d'authentification
# ---------------------------------------------------------------------- #
def test_failed_auth_probe_is_not_remembered(make_proxy, origin, monkeypatch):
    proxy = make_proxy(auth="basic")
    monkeypatch.setenv("IZIPROXY_USERNAME", proxy.username)
    monkeypatch.setenv("IZIPROXY_PASSWORD", proxy.password)
    monkeypatch.setattr(proxy_manager, "AUTH_PROBE_RETRY_DELAY", 0, raising=False)
    real_probe = proxy_manager.probe_proxy_auth
    calls = []

    def flaky_probe(*args, **kwargs):
        calls.append(args)
        # Première sonde : proxy injoignable (VPN pas encore établi, délai dépassé...)
        return (None, {}) if len(calls) == 1 else real_probe(*args, **kwargs)

    monkeypatch.setattr(proxy_manager, "probe_proxy_auth", flaky_probe)
    izi = IziProxy(proxy_url=proxy.url)
    assert izi.requires_auth is False
    with izi.create_session() as session:
        response = session.get(origin.url(), timeout=10)
    assert response.status_code == 200
    assert izi.requires_auth is True
    assert len(calls) == 2


def test_failed_auth_probe_is_retried_after_a_delay(make_proxy, monkeypatch):
    proxy = make_proxy(auth="basic")
    calls = []
    monkeypatch.setattr(proxy_manager, "probe_proxy_auth", lambda *a, **kw: calls.append(a) or (None, {}))
    izi = IziProxy(proxy_url=proxy.url)
    assert izi.requires_auth is False
    assert izi.requires_auth is False
    # Pas de nouvelle sonde (3 s de délai chacune) à chaque requête
    assert len(calls) == 1
    monkeypatch.setattr(proxy_manager, "AUTH_PROBE_RETRY_DELAY", 0)
    assert izi.requires_auth is False
    assert len(calls) == 2


# ---------------------------------------------------------------------- #
# Tunnels CONNECT : premiers octets envoyés par le serveur
# ---------------------------------------------------------------------- #
BANNER = b"SSH-2.0-iziproxy-test\r\n"


def _connect_and_read_banner(local, authority="ssh.test:22"):
    with socket.create_connection((local.host, local.port), timeout=5) as client:
        client.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode()
                       + token_line(local) + b"\r\n")
        data = b""
        try:
            while BANNER not in data:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
    return data


def test_server_first_bytes_sent_with_the_connect_response_are_relayed():
    def tunnel_with_banner(conn, head):
        # Réponse au CONNECT et bannière SSH dans le même envoi
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + BANNER)
        conn.recv(1)

    upstream = ScriptedProxy(tunnel_with_banner)
    try:
        with IziProxy(proxy_url=upstream.url).start_local_proxy(port=0) as local:
            data = _connect_and_read_banner(local)
    finally:
        upstream.close()
    assert data.startswith(b"HTTP/1.1 200")
    assert BANNER in data


def test_server_first_bytes_are_relayed_through_an_ntlm_tunnel(make_proxy):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm", coalesce_connect=True)
    banner_server = socket.create_server(("127.0.0.1", 0))

    def serve_banner():
        conn, _ = banner_server.accept()
        with conn:
            conn.sendall(BANNER)
            conn.settimeout(5)
            try:
                conn.recv(1)
            except OSError:
                pass

    threading.Thread(target=serve_banner, daemon=True).start()
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password, domain=proxy.domain)
    try:
        with izi.start_local_proxy(port=0) as local:
            data = _connect_and_read_banner(local, f"banner.test:{banner_server.getsockname()[1]}")
    finally:
        banner_server.close()
    assert data.startswith(b"HTTP/1.1 200")
    assert BANNER in data


# ---------------------------------------------------------------------- #
# Exceptions du chemin NTLM
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_ntlm_connection_errors_are_requests_exceptions(scheme):
    pytest.importorskip("spnego")

    def hang_up(conn, head):
        conn.close()

    upstream = ScriptedProxy(hang_up)
    izi = IziProxy(proxy_url=upstream.url, auth_type="ntlm", username="alice", password="x", domain="CORP")
    try:
        with izi.create_session() as session:
            with pytest.raises(requests.exceptions.ConnectionError):
                session.get(f"{scheme}://origin.test/", timeout=5)
    finally:
        upstream.close()


def test_streamed_ntlm_response_closes_its_socket(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password, domain=proxy.domain)
    with izi.create_session() as session:
        response = session.get(origin.url(), stream=True, timeout=10)
        sock = response.raw._connection.sock
        assert response.content
        response.close()
    assert sock.fileno() == -1


# ---------------------------------------------------------------------- #
# Configuration
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("value", ["negotiate", "Negotiate", "NTLM"])
def test_negotiate_auth_type_uses_windows_authentication(value):
    pytest.importorskip("spnego")
    izi = IziProxy(proxy_url="http://127.0.0.1:9", auth_type=value, username="alice", password="x")
    assert izi.auth_type == "ntlm"


def test_negotiate_auth_type_reaches_a_negotiate_proxy(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="negotiate")
    izi = IziProxy(proxy_url=proxy.url, auth_type="negotiate", username=proxy.username,
                   password=proxy.password, domain=proxy.domain)
    with izi.create_session() as session:
        assert session.get(origin.url(), timeout=10).status_code == 200


@pytest.mark.parametrize("value", ["digest", "kerberos", "bearer"])
def test_unknown_auth_type_is_refused(value):
    with pytest.raises(ValueError):
        IziProxy(auth_type=value)


def test_unknown_auth_type_in_configuration_is_refused(tmp_path):
    config = tmp_path / "conf.yml"
    config.write_text("environments:\n  local:\n    proxy_url: http://127.0.0.1:9\n    auth_type: digest\n")
    with pytest.raises(ValueError):
        IziProxy(config_path=str(config), environment="local").auth_type  # noqa: B018


def test_missing_explicit_config_falling_back_to_cwd_is_flagged(tmp_path, caplog):
    # Le répertoire courant est tmp_path/work (voir conftest)
    with open("iziproxy.yml", "w", encoding="utf-8") as file:
        file.write("environments:\n  local:\n    proxy_url: http://evil.test:8080\n")
    with caplog.at_level(logging.WARNING, logger="iziproxy"):
        manager = ConfigManager(config_path=str(tmp_path / "missing.yml"))
    assert manager.loaded_from.endswith("iziproxy.yml")
    assert "current directory" in caplog.text


def test_empty_configuration_sections_do_not_crash(tmp_path, monkeypatch):
    config = tmp_path / "conf.yml"
    config.write_text("credentials:\nsystem_proxy:\nenvironment_detection:\n"
                      "environments:\n  local:\n    proxy_url: http://127.0.0.1:9\n    requires_auth: true\n")
    monkeypatch.setenv("IZIPROXY_USERNAME", "alice")
    monkeypatch.setenv("IZIPROXY_PASSWORD", "secret")
    izi = IziProxy(config_path=str(config), environment="local", auth_type="basic")
    username, password, _ = izi.get_credentials()
    assert (username, password.get_password()) == ("alice", "secret")


def test_single_string_detection_rules_are_not_split_into_characters():
    config = {"environment_detection": {
        "hostname_patterns": {"prod": "srv-prod"},
        "hostname_regex": {"dev": "^build-"},
        "ip_ranges": {"dev": "10.0.0.0/8"},
    }}
    detector = EnvironmentDetector(config)
    detector.system_info = {"hostname": "my-laptop", "ip": "10.1.2.3"}
    # Avant : « srv-prod » devenait s, r, v, -, p... et « my-laptop » contient « - »
    assert detector._detect_by_hostname() == "local"
    assert detector._detect_by_ip() == "dev"
    detector.system_info["hostname"] = "srv-prod-01"
    assert detector._detect_by_hostname() == "prod"


@pytest.mark.parametrize("raw", [
    b"POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\nContent-Length: \xb2\r\n",
    b"CONNECT host:\xb2 HTTP/1.1\r\nHost: x\r\n",
])
def test_non_ascii_digits_are_rejected_with_400(raw):
    with IziProxy().start_local_proxy(port=0) as local:
        assert raw_status(local, raw + token_line(local) + b"\r\n") == b"400"


def test_local_proxy_rejects_ambiguous_connect_targets():
    with IziProxy().start_local_proxy(port=0) as local:
        for authority in ("user@host:443", "host/path:443", "[::1:443"):
            raw = f"CONNECT {authority} HTTP/1.1\r\nHost: x\r\n".encode() + token_line(local) + b"\r\n"
            assert raw_status(local, raw) == b"400", authority
