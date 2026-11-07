"""
Tests du proxy local de relais : un client qui ne connaît que les variables
d'environnement (urllib, curl) doit traverser un proxy NTLM ou Basic.

Les URLs « origin.test » ne se résolvent pas : une requête qui aboutit a
forcément traversé le proxy d'entreprise de test.
"""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request

import pytest

from iziproxy import IziProxy, LocalProxy
from iziproxy.proxy_utils import basic_proxy_authorization


def env_opener():
    """Client urllib configuré uniquement par les variables d'environnement."""
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    # ProxyHandler() sans argument lit HTTP(S)_PROXY / NO_PROXY
    return urllib.request.build_opener(urllib.request.ProxyHandler(),
                                       urllib.request.HTTPSHandler(context=insecure))


def explicit_opener(proxy_url):
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))


def via_local(local, url):
    """Requête en forme absolue envoyée explicitement au proxy local
    (urllib pourrait contourner tout proxy pour 127.0.0.1)."""
    conn = http.client.HTTPConnection(local.host, local.port, timeout=10)
    try:
        conn.request("GET", url, headers=token_header(local))
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def token_header(local):
    """En-tête Proxy-Authorization portant le jeton du proxy local."""
    auth = basic_proxy_authorization(local.url)
    return {"Proxy-Authorization": auth} if auth else {}


def raw_request(local, raw):
    """Envoie une requête brute (jeton ajouté après la ligne de requête) ; renvoie le statut."""
    line, sep, rest = raw.partition(b"\r\n")
    if sep:
        headers = b"".join(f"{k}: {v}\r\n".encode() for k, v in token_header(local).items())
        raw = line + sep + headers + rest
    with socket.create_connection((local.host, local.port), timeout=5) as sock:
        sock.sendall(raw)
        return sock.recv(64).split(b" ")[1]


def fetch_json(opener, url, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {})
    with opener.open(request, timeout=10) as response:
        return response.status, json.loads(response.read())


@pytest.fixture
def ntlm_izi(make_proxy):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username,
                   password=proxy.password, domain=proxy.domain)
    yield izi, proxy
    izi.clear_environment_variables()
    izi.stop_local_proxies()


# ---------------------------------------------------------------------- #
# NTLM via les variables d'environnement
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_env_only_client_reaches_origin_through_ntlm(ntlm_izi, origin, tls_origin, scheme):
    izi, proxy = ntlm_izi
    server = origin if scheme == "http" else tls_origin

    values = izi.set_environment_variables(local_proxy=True)

    assert os.environ["HTTPS_PROXY"] == os.environ["http_proxy"] == values["HTTP_PROXY"]
    assert values["HTTP_PROXY"].startswith("http://iziproxy:")
    status, data = fetch_json(env_opener(), server.url("/echo?q=1"))

    assert status == 200
    assert data["path"] == "/echo?q=1"
    # Les identifiants ne sortent jamais du proxy d'entreprise
    assert "proxy-authorization" not in data["headers"]
    assert any(e["headers"].get("proxy-authorization", "").startswith("NTLM ") for e in proxy.log)
    assert proxy.log[-1]["method"] == ("CONNECT" if scheme == "https" else "GET")


def test_post_body_and_headers_are_relayed(ntlm_izi, origin):
    izi, _ = ntlm_izi
    izi.set_environment_variables(local_proxy=True)

    status, data = fetch_json(env_opener(), origin.url("/echo"), data="héllo".encode(),
                              headers={"X-Custom": "1", "Content-Type": "text/plain"})

    assert status == 200
    assert data["method"] == "POST"
    assert data["body"] == "héllo"
    assert data["headers"]["x-custom"] == "1"
    assert data["headers"]["host"] == f"origin.test:{origin.port}"


def test_chunked_response_and_status_are_relayed(ntlm_izi, origin):
    izi, _ = ntlm_izi
    local = izi.start_local_proxy(port=0)
    opener = explicit_opener(local.url)

    with opener.open(origin.url("/chunked"), timeout=10) as response:
        assert response.read() == b"hello chunked world"
    with opener.open(origin.url("/nocontent"), timeout=10) as response:
        assert response.status == 204


def test_several_requests_reuse_the_local_proxy(ntlm_izi, tls_origin):
    izi, proxy = ntlm_izi
    izi.set_environment_variables(local_proxy=True)
    first = os.environ["HTTPS_PROXY"]
    izi.set_environment_variables(local_proxy=True)
    assert os.environ["HTTPS_PROXY"] == first

    opener = env_opener()
    for _ in range(3):
        assert fetch_json(opener, tls_origin.url())[0] == 200
    # Le schéma détecté est réutilisé : un seul sondage sans identifiants
    assert len([e for e in proxy.log if "proxy-authorization" not in e["headers"]]) == 1


def test_wrong_ntlm_password_gives_502(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password="wrong", domain=proxy.domain)
    with izi.start_local_proxy(port=0) as local:
        with pytest.raises(urllib.error.HTTPError) as info:
            explicit_opener(local.url).open(origin.url(), timeout=10)
    assert info.value.code == 502
    assert b"rejected" in info.value.read()


def test_curl_through_ntlm(ntlm_izi, tls_origin):
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl not available")
    izi, _ = ntlm_izi
    izi.set_environment_variables(local_proxy=True)

    result = subprocess.run([curl, "-sk", "--max-time", "10", tls_origin.url("/echo?curl=1")],
                            capture_output=True, env=dict(os.environ), timeout=30)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["path"] == "/echo?curl=1"


# ---------------------------------------------------------------------- #
# Routes : exclusions, Basic, proxy sans authentification
# ---------------------------------------------------------------------- #
def test_excluded_host_goes_direct(ntlm_izi, origin):
    izi, proxy = ntlm_izi
    with izi.start_local_proxy(port=0) as local:
        # 127.0.0.1 est toujours exclu : le proxy local s'y connecte directement
        status, body = via_local(local, origin.url(host="127.0.0.1"))
    assert status == 200
    assert json.loads(body)["path"] == "/echo"
    assert proxy.log == []
    assert len(origin.requests) == 1


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_basic_credentials_are_injected(make_proxy, origin, tls_origin, scheme):
    proxy = make_proxy(auth="basic")
    server = origin if scheme == "http" else tls_origin
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)
    try:
        izi.set_environment_variables(local_proxy=True)
        status, data = fetch_json(env_opener(), server.url())
    finally:
        izi.clear_environment_variables()

    assert status == 200
    assert "proxy-authorization" not in data["headers"]
    assert proxy.log[-1]["headers"]["proxy-authorization"].startswith("Basic ")


def test_upstream_refusal_is_relayed(make_proxy, tls_origin):
    proxy = make_proxy(auth="basic")
    # Pas d'identifiants et pas de saisie : le 407 du proxy amont est relayé
    izi = IziProxy(proxy_url=proxy.url, auth_type="basic", interactive=False)
    with izi.start_local_proxy(port=0) as local:
        with pytest.raises(OSError) as info:
            env = urllib.request.build_opener(urllib.request.ProxyHandler({"https": local.url}))
            env.open(tls_origin.url(), timeout=10)
    assert "407" in str(info.value)


def test_unauthenticated_proxy_and_direct_configuration(make_proxy, origin):
    proxy = make_proxy()
    with IziProxy(proxy_url=proxy.url).start_local_proxy(port=0) as local:
        assert fetch_json(explicit_opener(local.url), origin.url())[0] == 200
    assert len(proxy.log) == 1

    # Sans aucun proxy configuré, le proxy local se connecte directement
    with IziProxy().start_local_proxy(port=0) as local:
        assert via_local(local, origin.url(host="127.0.0.1"))[0] == 200


# ---------------------------------------------------------------------- #
# Cycle de vie et robustesse
# ---------------------------------------------------------------------- #
def test_clear_environment_variables_stops_the_local_proxy(ntlm_izi, monkeypatch):
    izi, _ = ntlm_izi
    monkeypatch.setenv("HTTPS_PROXY", "http://previous:1")
    izi.set_environment_variables(local_proxy=True)
    port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])

    izi.clear_environment_variables()

    assert os.environ["HTTPS_PROXY"] == "http://previous:1"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()


def test_switching_to_direct_variables_stops_the_local_proxy(make_proxy):
    izi = IziProxy(proxy_url=make_proxy().url)
    local_url = izi.set_environment_variables(local_proxy=True)["HTTPS_PROXY"]
    port = int(local_url.rsplit(":", 1)[1])

    izi.set_environment_variables()

    assert os.environ["HTTPS_PROXY"] == izi.get_proxy_url()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
    izi.clear_environment_variables()


def test_handle_api_and_context_manager(make_proxy):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)
    with izi:
        local = izi.start_local_proxy(port=0)
        assert isinstance(local, LocalProxy)
        assert local.running and local.host == "127.0.0.1" and local.port > 0
        assert local.address == f"http://127.0.0.1:{local.port}"
        assert local.url == f"http://iziproxy:{local.token}@127.0.0.1:{local.port}"
        assert "running" in repr(local) and local.token not in repr(local)
    # IziProxy.__exit__ arrête les proxys locaux
    assert not local.running
    local.stop()  # idempotent


def test_explicit_port(make_proxy):
    proxy = make_proxy()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    with IziProxy(proxy_url=proxy.url).start_local_proxy(port=free_port) as local:
        assert local.port == free_port


def test_loop_to_itself_is_detected(make_proxy, origin):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    izi = IziProxy(proxy_url=f"http://127.0.0.1:{port}", auth_type="basic", interactive=False)
    izi._auth = {"required": False, "type": "basic"}  # pas de sondage d'un proxy inexistant
    with izi.start_local_proxy(port=port) as local:
        with pytest.raises(urllib.error.HTTPError) as info:
            explicit_opener(local.url).open(origin.url(), timeout=10)
    assert info.value.code == 508


@pytest.mark.parametrize("raw, status", [
    (b"GET /relative HTTP/1.1\r\nHost: x\r\n\r\n", b"400"),
    (b"CONNECT nowhere HTTP/1.1\r\n\r\n", b"400"),
    (b"garbage\r\n\r\n", b"400"),
])
def test_invalid_requests_get_400(make_proxy, raw, status):
    proxy = make_proxy()
    with IziProxy(proxy_url=proxy.url).start_local_proxy(port=0) as local:
        assert raw_request(local, raw) == status


def test_unreachable_target_gives_502(make_proxy):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    with IziProxy().start_local_proxy(port=0, timeout=3) as local:
        status, _ = via_local(local, f"http://127.0.0.1:{dead_port}/")
    assert status == 502


def test_default_port_is_cntlm_port(make_proxy):
    from iziproxy.local_proxy import DEFAULT_PORT

    assert DEFAULT_PORT == 3128
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", DEFAULT_PORT))
        except OSError:
            pytest.skip("port 3128 already in use on this machine")
    with IziProxy(proxy_url=make_proxy().url).start_local_proxy() as local:
        assert local.port == DEFAULT_PORT
        assert local.address == "http://127.0.0.1:3128"


def test_busy_port_gives_clear_error(make_proxy):
    izi = IziProxy(proxy_url=make_proxy().url)
    with izi.start_local_proxy(port=0) as first:
        with pytest.raises(OSError, match="port=0"):
            izi.start_local_proxy(port=first.port)


def test_serve_forever_returns_after_stop(make_proxy):
    import threading

    local = IziProxy(proxy_url=make_proxy().url).start_local_proxy(port=0)
    threading.Timer(0.3, local.stop).start()
    local.serve_forever()
    assert not local.running
