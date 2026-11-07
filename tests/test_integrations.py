"""
Tests de bout en bout des adaptateurs pour les clients HTTP autres que
requests, à travers un vrai proxy local (sans authentification, Basic, NTLM).

Les URLs « origin.test » ne se résolvent pas : une réponse prouve le passage
par le proxy. Les URLs 127.0.0.1 doivent partir en direct.
"""

import asyncio
import json
import ssl
import threading
import urllib.request

import pytest

from iziproxy import IziProxy

AUTH_MODES = [None, "basic", "ntlm"]


def unverified_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@pytest.fixture(params=AUTH_MODES, ids=["open", "basic", "ntlm"])
def routed(request, make_proxy):
    """(proxy de test, IziProxy configuré pour lui) pour chaque mode d'authentification."""
    if request.param == "ntlm":
        pytest.importorskip("spnego")
    proxy = make_proxy(auth=request.param)
    kwargs = {}
    if request.param:
        kwargs = dict(username=proxy.username, password=proxy.password, domain=proxy.domain)
    izi = IziProxy(proxy_url=proxy.url, **kwargs)
    yield proxy, izi
    izi.stop_local_proxies()


@pytest.fixture(params=["http", "https"])
def server(request, origin, tls_origin):
    return origin if request.param == "http" else tls_origin


def check(proxy, data):
    """La requête a traversé le proxy et aucun en-tête de proxy n'a fui."""
    assert data["path"] == "/echo?client=1"
    assert "proxy-authorization" not in data["headers"]
    assert proxy.log, "the request did not go through the proxy"


# ---------------------------------------------------------------------- #
# proxy_for : la primitive commune
# ---------------------------------------------------------------------- #
def test_proxy_for_routes(make_proxy):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username="u", password="p@ss", no_proxy="*.corp")
    assert izi.proxy_for("http://127.0.0.1/") is None
    assert izi.proxy_for("https://app.corp/") is None
    assert izi.proxy_for("https://example.org/") == proxy.url.replace("http://", "http://u:p%40ss@")
    assert izi.proxy_for("wss://example.org/socket") == izi.proxy_for("https://example.org/")


def test_proxy_for_ntlm_uses_shared_local_proxy(make_proxy):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    with IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password,
                  domain=proxy.domain) as izi:
        first = izi.proxy_for("https://example.org/")
        assert first.startswith("http://127.0.0.1:") and first != proxy.url
        assert izi.proxy_for("http://other.example/") == first
    assert izi._shared_local_proxy is None


def test_proxy_for_direct_without_proxy():
    assert IziProxy().proxy_for("https://example.org/") is None


# ---------------------------------------------------------------------- #
# httpx
# ---------------------------------------------------------------------- #
def test_httpx_sync(routed, server):
    pytest.importorskip("httpx")
    proxy, izi = routed
    with izi.httpx_client(verify=False) as client:
        check(proxy, client.get(server.url("/echo?client=1")).json())


def test_httpx_async(routed, server):
    pytest.importorskip("httpx")
    proxy, izi = routed

    async def run():
        async with izi.httpx_async_client(verify=False) as client:
            return (await client.get(server.url("/echo?client=1"))).json()

    check(proxy, asyncio.run(run()))


def test_httpx_bypass_and_env_ignored(make_proxy, origin, monkeypatch):
    pytest.importorskip("httpx")
    proxy = make_proxy()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # ne doit pas être utilisé
    with IziProxy(proxy_url=proxy.url).httpx_client() as client:
        assert client.get(origin.url(host="127.0.0.1")).status_code == 200
        assert client.get(origin.url()).status_code == 200
    assert len(proxy.log) == 1


def test_httpx_rejects_conflicting_options():
    pytest.importorskip("httpx")
    with pytest.raises(TypeError):
        IziProxy().httpx_client(proxy="http://x")


# ---------------------------------------------------------------------- #
# aiohttp
# ---------------------------------------------------------------------- #
def test_aiohttp(routed, server):
    pytest.importorskip("aiohttp")
    proxy, izi = routed

    async def run():
        async with izi.aiohttp_session() as session:
            async with session.get(server.url("/echo?client=1"), ssl=False) as response:
                return json.loads(await response.text())

    check(proxy, asyncio.run(run()))


def test_aiohttp_bypass(make_proxy, origin):
    pytest.importorskip("aiohttp")
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)

    async def run():
        async with izi.aiohttp_session() as session:
            async with session.get(origin.url(host="127.0.0.1")) as response:
                return response.status

    assert asyncio.run(run()) == 200
    assert proxy.log == []
    izi.stop_local_proxies()


def test_aiohttp_direct_without_proxy(origin):
    pytest.importorskip("aiohttp")

    async def run():
        async with IziProxy().aiohttp_session() as session:
            assert session._default_proxy is None
            async with session.get(origin.url(host="127.0.0.1")) as response:
                return response.status

    assert asyncio.run(run()) == 200


# ---------------------------------------------------------------------- #
# urllib3
# ---------------------------------------------------------------------- #
def test_urllib3(routed, server):
    proxy, izi = routed
    pool = izi.urllib3_pool_manager(cert_reqs="CERT_NONE")
    response = pool.request("GET", server.url("/echo?client=1"))
    check(proxy, json.loads(response.data))
    pool.clear()


def test_urllib3_bypass(make_proxy, origin):
    proxy = make_proxy()
    pool = IziProxy(proxy_url=proxy.url).urllib3_pool_manager()
    assert pool.request("GET", origin.url(host="127.0.0.1")).status == 200
    assert proxy.log == []


# ---------------------------------------------------------------------- #
# urllib.request
# ---------------------------------------------------------------------- #
def test_urllib(routed, server):
    proxy, izi = routed
    opener = izi.urllib_opener(urllib.request.HTTPSHandler(context=unverified_context()))
    with opener.open(server.url("/echo?client=1"), timeout=10) as response:
        check(proxy, json.loads(response.read()))


def test_urllib_global_opener_and_redirect(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)
    previous = urllib.request._opener
    try:
        izi.install_urllib_opener()
        with urllib.request.urlopen(origin.url("/redirect"), timeout=10) as response:
            data = json.loads(response.read())
        assert data["path"] == "/echo?redirected=1"
        assert "proxy-authorization" not in data["headers"]
    finally:
        urllib.request.install_opener(previous)


def test_urllib_bypass_ignores_env(make_proxy, origin, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    opener = IziProxy(proxy_url=proxy.url).urllib_opener()
    with opener.open(origin.url(host="127.0.0.1"), timeout=10) as response:
        assert response.status == 200
    assert proxy.log == []


# ---------------------------------------------------------------------- #
# http.client
# ---------------------------------------------------------------------- #
def test_http_client(routed, server):
    proxy, izi = routed
    connection = izi.http_connection(server.url(""), timeout=10, context=unverified_context())
    connection.request("GET", "/echo?client=1")
    data = json.loads(connection.getresponse().read())
    connection.close()
    check(proxy, data)


def test_http_client_direct(make_proxy, origin):
    proxy = make_proxy()
    connection = IziProxy(proxy_url=proxy.url).http_connection(origin.url("", host="127.0.0.1"))
    connection.request("GET", "/echo")
    assert connection.getresponse().status == 200
    assert connection._tunnel_host is None
    assert proxy.log == []


# ---------------------------------------------------------------------- #
# websockets
# ---------------------------------------------------------------------- #
@pytest.fixture
def ws_server():
    pytest.importorskip("websockets")
    from websockets.sync.server import serve

    def echo(connection):
        for message in connection:
            connection.send(f"echo:{message}")

    server = serve(echo, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.socket.getsockname()[1]
    server.shutdown()


def test_websockets(routed, ws_server):
    from websockets.sync.client import connect

    proxy, izi = routed
    uri = f"ws://origin.test:{ws_server}/"
    with connect(uri, proxy=izi.websocket_proxy(uri), open_timeout=10) as ws:
        ws.send("hi")
        assert ws.recv(timeout=10) == "echo:hi"
    assert proxy.log[-1]["method"] == "CONNECT"


def test_websockets_direct(make_proxy, ws_server):
    from websockets.sync.client import connect

    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)
    uri = f"ws://127.0.0.1:{ws_server}/"
    assert izi.websocket_proxy(uri) is None
    with connect(uri, proxy=izi.websocket_proxy(uri), open_timeout=10) as ws:
        ws.send("x")
        assert ws.recv(timeout=10) == "echo:x"
    assert proxy.log == []


# ---------------------------------------------------------------------- #
# gRPC
# ---------------------------------------------------------------------- #
@pytest.fixture
def grpc_server():
    grpc = pytest.importorskip("grpc")
    from concurrent import futures

    def echo(request, context):
        return b"echo:" + request

    handler = grpc.method_handlers_generic_handler(
        "test.Echo", {"Call": grpc.unary_unary_rpc_method_handler(echo)})
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((handler,))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield port
    server.stop(None)


def test_grpc(routed, grpc_server):
    import grpc

    proxy, izi = routed
    target = f"origin.test:{grpc_server}"
    options = izi.grpc_channel_options(target, secure=False)
    with grpc.insecure_channel(target, options=options) as channel:
        call = channel.unary_unary("/test.Echo/Call")
        assert call(b"ping", timeout=10) == b"echo:ping"
    assert proxy.log[-1]["method"] == "CONNECT"


def test_grpc_direct_option(make_proxy):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url, no_proxy="*.corp")
    assert izi.grpc_channel_options("dns:///api.corp:443") == [("grpc.enable_http_proxy", 0)]
    assert izi.grpc_channel_options("api.example:443") == [("grpc.http_proxy", proxy.url)]


# ---------------------------------------------------------------------- #
# Navigateurs
# ---------------------------------------------------------------------- #
def test_browser_helpers_use_local_proxy(make_proxy, origin):
    pytest.importorskip("selenium")
    proxy = make_proxy(auth="basic")
    with IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password) as izi:
        playwright = izi.playwright_proxy()
        selenium = izi.selenium_proxy()
        assert playwright["server"] == izi.local_proxy_url()
        assert selenium.http_proxy == selenium.ssl_proxy == playwright["server"].split("://")[1]

        # Le proxy local fourni aux navigateurs authentifie réellement les requêtes
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": playwright["server"]}))
        with opener.open(origin.url(), timeout=10) as response:
            assert response.status == 200


def test_browser_helpers_direct():
    pytest.importorskip("selenium")
    izi = IziProxy()
    assert izi.playwright_proxy() is None
    assert izi.selenium_proxy().proxy_type["string"] == "DIRECT"
