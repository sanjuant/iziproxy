"""
Tests de non-régression de la revue de sécurité du 2026-11-07 : choix de
l'authentification avec un PAC, proxys autorisés à recevoir les
identifiants, variables d'environnement, analyse des URLs, durcissement du
proxy local et du téléchargement PAC.
"""

import http.client
import os
import socket
import textwrap
import threading
import urllib.error
import urllib.request

import pytest

import iziproxy
from iziproxy import IziProxy, local_proxy
from iziproxy.config_manager import ConfigManager
from iziproxy.env_detector import EnvironmentDetector
from iziproxy.password_manager import PasswordManager
from iziproxy.proxy_detector import ProxyDetector, _SafeRedirectHandler
from iziproxy.proxy_utils import extract_credentials, has_credentials, should_bypass, strip_credentials
from iziproxy.secure_config import SecureProxyConfig

from test_hardening import raw_status, token_line


def write_pac(tmp_path, proxy):
    """PAC : DIRECT pour la cible par défaut (www.example.com), proxy sinon."""
    pac = tmp_path / "proxy.pac"
    pac.write_text(textwrap.dedent(f"""
        function FindProxyForURL(url, host) {{
            if (host == "www.example.com") return "DIRECT";
            return "PROXY 127.0.0.1:{proxy.port}";
        }}
    """))
    return pac


def http_pac(monkeypatch, tmp_path, proxy):
    """PAC « téléchargé » depuis http://pac.test (contenu fourni localement)."""
    text = write_pac(tmp_path, proxy).read_text()
    monkeypatch.setattr(ProxyDetector, "fetch_pac", staticmethod(lambda url, verify=True: text))
    return "http://pac.test/proxy.pac"


# ---------------------------------------------------------------------- #
# Authentification avec un PAC
# ---------------------------------------------------------------------- #
def test_pac_direct_for_default_target_still_authenticates(make_proxy, origin, tmp_path):
    pytest.importorskip("pypac")
    proxy = make_proxy(auth="basic")
    izi = IziProxy(pac_url=str(write_pac(tmp_path, proxy)), username=proxy.username,
                   password=proxy.password)

    assert izi.create_session().get(origin.url()).status_code == 200
    assert proxy.log[-1]["headers"].get("proxy-authorization", "").startswith("Basic ")


def test_pac_auth_is_probed_on_the_first_proxied_url(make_proxy, origin, tmp_path, memory_keyring):
    pytest.importorskip("pypac")
    proxy = make_proxy(auth="basic")
    memory_keyring.set_password("iziproxy_local-basic", "__username__", proxy.username)
    memory_keyring.set_password("iziproxy_local-basic", proxy.username, proxy.password)
    izi = IziProxy(pac_url=str(write_pac(tmp_path, proxy)), interactive=False, environment="local")

    # Rien à sonder pour la cible par défaut : la décision reste ouverte
    assert izi.requires_auth is False
    assert izi._auth is None
    assert izi.create_session().get(origin.url()).status_code == 200
    assert izi.requires_auth is True


# ---------------------------------------------------------------------- #
# Proxys autorisés à recevoir les identifiants
# ---------------------------------------------------------------------- #
def test_http_pac_proxy_does_not_receive_credentials(make_proxy, origin, tmp_path, monkeypatch, caplog):
    pytest.importorskip("pypac")
    proxy = make_proxy(auth="basic")
    izi = IziProxy(pac_url=http_pac(monkeypatch, tmp_path, proxy),
                   username=proxy.username, password=proxy.password)

    assert izi.create_session().get(origin.url()).status_code == 407
    assert all("proxy-authorization" not in entry["headers"] for entry in proxy.raw_log)
    assert "Credentials withheld" in caplog.text
    assert izi.proxy_for(origin.url()) == proxy.url


def test_auth_proxies_allows_an_http_pac_proxy(make_proxy, origin, tmp_path, monkeypatch):
    pytest.importorskip("pypac")
    proxy = make_proxy(auth="basic")
    izi = IziProxy(pac_url=http_pac(monkeypatch, tmp_path, proxy), auth_proxies=["127.0.0.1"],
                   username=proxy.username, password=proxy.password)

    assert izi.create_session().get(origin.url()).status_code == 200


def test_auth_proxies_also_restricts_explicit_proxies(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, auth_proxies="proxy.corp.example",
                   username=proxy.username, password=proxy.password)

    assert izi.get_proxy_dict(origin.url()) == {"http": proxy.url, "https": proxy.url}
    assert izi.create_session().get(origin.url()).status_code == 407


def test_auth_proxies_from_configuration(tmp_path):
    config = tmp_path / "conf.yml"
    config.write_text("auth_proxies: ['*.corp.example']\n")
    izi = IziProxy(config_path=str(config))
    assert izi._auth_proxy_rules() == ["*.corp.example"]


@pytest.mark.parametrize("pac_url, verify, trusted", [
    ("https://pac.corp/proxy.pac", True, True),
    ("https://pac.corp/proxy.pac", False, False),
    ("http://pac.corp/proxy.pac", True, False),
    ("file:///etc/proxy.pac", True, True),
])
def test_pac_trust_depends_on_the_channel(pac_url, verify, trusted):
    assert IziProxy(verify=verify)._pac_is_trusted(pac_url) is trusted


def test_local_pac_file_is_trusted(tmp_path):
    pac = tmp_path / "proxy.pac"
    pac.write_text("function FindProxyForURL(u, h) { return 'DIRECT'; }")
    assert IziProxy()._pac_is_trusted(str(pac))


# ---------------------------------------------------------------------- #
# Variables d'environnement
# ---------------------------------------------------------------------- #
def test_switching_from_local_to_direct_env_restores_variables(make_proxy, tmp_path, monkeypatch):
    pytest.importorskip("pypac")
    proxy = make_proxy()
    monkeypatch.setenv("HTTPS_PROXY", "http://original:3128")
    izi = IziProxy(pac_url=str(write_pac(tmp_path, proxy)))

    local_values = izi.set_environment_variables(local_proxy=True)
    assert os.environ["HTTPS_PROXY"] == local_values["HTTPS_PROXY"]

    # PAC : DIRECT pour la cible par défaut, donc aucune variable à définir
    assert izi.set_environment_variables() == {}
    assert os.environ["HTTPS_PROXY"] == "http://original:3128"
    assert "HTTP_PROXY" not in os.environ
    izi.clear_environment_variables()
    assert os.environ["HTTPS_PROXY"] == "http://original:3128"


def test_uninstall_restores_env_even_when_nothing_was_set(make_proxy, tmp_path):
    pytest.importorskip("pypac")
    proxy = make_proxy()
    izi = IziProxy(pac_url=str(write_pac(tmp_path, proxy)))
    installation = iziproxy.install(izi, local_proxy=False, requests=False, urllib=False)
    assert installation.environment == {}
    installation.uninstall()
    assert izi._saved_env is None and izi.proxy_detector.env_overrides == {}


def test_uninstall_keeps_local_proxies_started_by_the_user(make_proxy):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)
    mine = izi.start_local_proxy(port=0)
    try:
        iziproxy.install(izi).uninstall()
        assert mine.running
    finally:
        mine.stop()


# ---------------------------------------------------------------------- #
# Analyse des URLs et exclusions
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("url, bypass", [
    ("http://host/", False),
    ("http://host:8080/", True),
    ("https://host:8080/", True),
    ("https://host/", False),
])
def test_no_proxy_port_uses_scheme_default(url, bypass):
    assert should_bypass(url, "host:8080") is bypass


def test_no_proxy_default_port_entry_matches_implicit_port():
    assert should_bypass("https://host/", "host:443")
    assert not should_bypass("http://host/", "host:443")


def test_at_sign_in_path_is_not_a_credential_separator():
    url = "http://proxy:8080/a@b"
    assert strip_credentials(url) == url
    assert not has_credentials(url)
    assert extract_credentials(url) == (None, None)
    assert SecureProxyConfig({"http": url})["http"] == url


def test_credentials_are_still_found_in_the_authority():
    url = "http://user:p%40ss@proxy:8080/path@x"
    assert strip_credentials(url) == "http://proxy:8080/path@x"
    assert extract_credentials(url) == ("user", "p@ss")
    assert "p%40ss" not in str(SecureProxyConfig({"http": url}))


def test_get_proxy_dict_has_no_misleading_no_proxy_key(make_proxy):
    proxy = make_proxy()
    assert IziProxy(proxy_url=proxy.url, no_proxy="*.corp").get_proxy_dict() == {
        "http": proxy.url, "https": proxy.url}


# ---------------------------------------------------------------------- #
# httpoxy
# ---------------------------------------------------------------------- #
def test_uppercase_http_proxy_is_ignored_in_cgi(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://attacker:8080")
    monkeypatch.setenv("REQUEST_METHOD", "GET")
    assert ProxyDetector()._detect_env_vars() == {}
    monkeypatch.delenv("REQUEST_METHOD")
    assert ProxyDetector()._detect_env_vars()["http"] == "http://attacker:8080"


# ---------------------------------------------------------------------- #
# Proxy local
# ---------------------------------------------------------------------- #
def test_oversized_body_gives_413(origin, monkeypatch):
    monkeypatch.setattr(local_proxy, "MAX_BODY", 10)
    with IziProxy().start_local_proxy(port=0) as local:
        raw = (f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"Content-Length: 11\r\n\r\nhello world")
        assert raw_status(local, raw) == b"413"
        raw = (f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"Transfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n")
        assert raw_status(local, raw) == b"413"
    assert origin.requests == []


@pytest.mark.parametrize("size", [b"0x5", b"-5", b"+5"])
def test_invalid_chunk_size_gives_400(origin, size):
    with IziProxy().start_local_proxy(port=0) as local:
        raw = (f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"Transfer-Encoding: chunked\r\n\r\n" + size + b"\r\nhello\r\n0\r\n\r\n")
        assert raw_status(local, raw) == b"400"


@pytest.mark.parametrize("raw", [
    b"GET http://127.0.0.1:1/a\rInjected: x HTTP/1.1\r\n",
    b"CONNECT a\rb:443 HTTP/1.1\r\n",
])
def test_control_characters_in_request_line_give_400(raw):
    with IziProxy().start_local_proxy(port=0) as local:
        assert raw_status(local, raw + token_line(local) + b"\r\n") == b"400"


def test_control_characters_in_headers_give_400(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        raw = (f"GET {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"X-Test: a\rInjected: b\r\n\r\n")
        assert raw_status(local, raw) == b"400"
    assert origin.requests == []


def test_expect_100_continue_is_answered(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        with socket.create_connection((local.host, local.port), timeout=5) as sock:
            sock.sendall(f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
                         + b"Content-Length: 5\r\nExpect: 100-continue\r\n\r\n")
            assert sock.recv(64).startswith(b"HTTP/1.1 100 Continue")
            sock.sendall(b"hello")
            assert b" 200 " in sock.recv(64)
    assert origin.requests[-1]["body"] == "hello"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "localhost", "0.0.0.0", "::1", "[::1]",
                                  "app.localhost"])
def test_loop_detection_covers_local_addresses(host):
    assert local_proxy._is_local_address(host)


def test_loop_through_unspecified_address_is_detected():
    with IziProxy().start_local_proxy(port=0) as local:
        izi = IziProxy(proxy_url=f"http://0.0.0.0:{local.port}")
        izi._auth = {"required": False, "type": "basic"}
        local.izi = izi
        with pytest.raises(local_proxy._LoopDetected):
            local._route("http://origin.test/")


def test_connections_beyond_the_limit_get_503(monkeypatch):
    monkeypatch.setattr(local_proxy, "MAX_CONNECTIONS", 1)
    with IziProxy().start_local_proxy(port=0) as local:
        held = socket.create_connection((local.host, local.port), timeout=5)
        try:
            with socket.create_connection((local.host, local.port), timeout=5) as second:
                assert second.recv(64).split(b" ")[1] == b"503"
        finally:
            held.close()


# ---------------------------------------------------------------------- #
# Téléchargement PAC
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("old, new, allowed", [
    ("https://pac/a", "http://pac/b", False),
    ("https://pac/a", "https://other/b", True),
    ("http://pac/a", "https://pac/b", True),
    ("http://pac/a", "ftp://pac/b", False),
])
def test_pac_redirects_never_downgrade(old, new, allowed):
    handler = _SafeRedirectHandler()
    request = urllib.request.Request(old)
    if allowed:
        assert handler.redirect_request(request, None, 302, "Found", {}, new).full_url == new
    else:
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(request, None, 302, "Found", {}, new)


def test_oversized_pac_is_ignored(origin, monkeypatch):
    from iziproxy import proxy_detector

    monkeypatch.setattr(proxy_detector, "MAX_PAC_SIZE", 10)
    assert ProxyDetector.fetch_pac(origin.url(host="127.0.0.1")) is None


def test_unavailable_pac_is_retried(monkeypatch, tmp_path):
    pytest.importorskip("pypac")
    from iziproxy import proxy_detector

    calls = []

    def fetch(url, verify=True):
        calls.append(url)
        return None if len(calls) == 1 else "function FindProxyForURL(u, h) { return 'PROXY p:8080'; }"

    monkeypatch.setattr(ProxyDetector, "fetch_pac", staticmethod(fetch))
    izi = IziProxy(pac_url="https://pac.test/proxy.pac")
    assert izi.get_proxy_url("https://a.test/") is None

    monkeypatch.setattr(proxy_detector, "PAC_RETRY_DELAY", 0)
    assert izi.get_proxy_url("https://a.test/") == "http://p:8080"
    assert len(calls) == 2


# ---------------------------------------------------------------------- #
# http.client
# ---------------------------------------------------------------------- #
def test_http_connection_uses_absolute_form_for_http_targets(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)
    conn = izi.http_connection(origin.url())
    try:
        conn.request("GET", "/echo?x=1")
        response = conn.getresponse()
        assert response.status == 200
        response.read()
    finally:
        conn.close()
    entry = proxy.log[-1]
    assert entry["method"] == "GET"
    assert entry["target"] == f"http://origin.test:{origin.port}/echo?x=1"
    assert entry["headers"]["host"] == f"origin.test:{origin.port}"
    assert entry["headers"]["proxy-authorization"].startswith("Basic ")
    assert isinstance(conn, http.client.HTTPConnection)


# ---------------------------------------------------------------------- #
# Divers
# ---------------------------------------------------------------------- #
def test_dotenv_files_are_merged(tmp_path, monkeypatch):
    project = tmp_path / "project.env"
    project.write_text("DATABASE_URL=x\nIZIPROXY_DOMAIN=CORP\n")
    home = tmp_path / "home.env"
    home.write_text("IZIPROXY_USERNAME=alice\nIZIPROXY_DOMAIN=OTHER\n")
    monkeypatch.setattr(ConfigManager, "DOTENV_PATHS", [str(project), str(home)])
    values = ConfigManager()._load_dotenv()
    assert values["IZIPROXY_USERNAME"] == "alice"
    assert values["IZIPROXY_DOMAIN"] == "CORP"


@pytest.mark.parametrize("hostname, expected", [
    ("contest-prod", "prod"),
    ("srv-prod-devices", "prod"),
    ("dev01-web", "dev"),
    ("latest-build", "local"),
])
def test_default_hostname_words_match_whole_segments(hostname, expected):
    detector = EnvironmentDetector({"environment_detection": {"method": "hostname"}})
    detector.system_info["hostname"] = hostname
    assert detector.detect_environment() == expected


def test_configured_hostname_patterns_are_substrings_and_win():
    detector = EnvironmentDetector({"environment_detection": {
        "method": "hostname", "hostname_patterns": {"prod": ["-dev"]}}})
    detector.system_info["hostname"] = "app-dev01"
    assert detector.detect_environment() == "prod"


def test_ntlm_adapters_are_rebuilt_after_clear_auth_cache(monkeypatch):
    class Fake:
        closed = False

        def close(self):
            self.closed = True

    # Port fermé : la sonde d'authentification échoue tout de suite
    izi = IziProxy(proxy_url="http://127.0.0.1:1")
    monkeypatch.setattr(izi, "_create_ntlm_adapter", lambda **kwargs: Fake())
    adapter = izi.create_session().get_adapter("https://")
    first = adapter._ntlm()
    assert adapter._ntlm() is first
    izi.clear_auth_cache()
    second = adapter._ntlm()
    assert second is not first and first.closed

    with izi.start_local_proxy(port=0) as local:
        before = local._ntlm()
        izi.refresh()
        assert local._ntlm() is not before and before.closed


def test_tkinter_prompt_is_skipped_outside_the_main_thread(monkeypatch):
    manager = PasswordManager.__new__(PasswordManager)
    manager.logger = __import__("logging").getLogger("iziproxy")
    used = []
    monkeypatch.setattr(manager, "_get_credentials_windows_complete", lambda *a: None)
    monkeypatch.setattr(manager, "_get_credentials_tkinter_dialog", lambda *a: used.append("tk"))
    monkeypatch.setattr(manager, "_get_credentials_cli", lambda *a: ("u", "p", None))

    result = {}
    thread = threading.Thread(target=lambda: result.update(v=manager._get_credentials_gui("t")))
    thread.start()
    thread.join()
    assert result["v"] == ("u", "p", None) and used == []
