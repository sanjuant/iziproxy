"""
Tests de durcissement : jeton du proxy local, validation des requêtes
clientes, absence d'identifiants dans les journaux et avertissements de
configuration.
"""

import base64
import http.client
import logging
import socket

import pytest

from iziproxy import IziProxy, LocalProxy
from iziproxy.proxy_utils import basic_proxy_authorization


def send(local, method, url, headers=None, body=None):
    """Requête en forme absolue envoyée au proxy local ; renvoie (statut, en-têtes, corps)."""
    conn = http.client.HTTPConnection(local.host, local.port, timeout=10)
    try:
        conn.request(method, url, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def raw_status(local, raw):
    """Envoie des octets bruts au proxy local et renvoie le code de statut."""
    with socket.create_connection((local.host, local.port), timeout=5) as sock:
        sock.sendall(raw)
        return sock.recv(64).split(b" ")[1]


def token_line(local):
    return f"Proxy-Authorization: {basic_proxy_authorization(local.url)}\r\n".encode()


# ---------------------------------------------------------------------- #
# Jeton du proxy local
# ---------------------------------------------------------------------- #
def test_local_proxy_rejects_clients_without_the_token(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        status, headers, _ = send(local, "GET", origin.url(host="127.0.0.1"))
    assert status == 407
    assert headers["Proxy-Authenticate"].startswith("Basic ")
    assert origin.requests == []


@pytest.mark.parametrize("value", [
    "Basic " + base64.b64encode(b"iziproxy:wrong-token-wrong-token").decode(),
    "Basic not-base64!",
    "Bearer abc",
])
def test_local_proxy_rejects_a_wrong_token(origin, value):
    with IziProxy().start_local_proxy(port=0) as local:
        status, _, _ = send(local, "GET", origin.url(host="127.0.0.1"),
                            headers={"Proxy-Authorization": value})
    assert status == 407
    assert origin.requests == []


def test_local_proxy_accepts_the_token_and_does_not_forward_it(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        status, _, _ = send(local, "GET", origin.url(host="127.0.0.1"),
                            headers={"Proxy-Authorization": basic_proxy_authorization(local.url)})
    assert status == 200
    # Le jeton est propre au saut client -> proxy local : jamais relayé
    assert "proxy-authorization" not in {k.lower() for k in origin.requests[0]["headers"]}


def test_token_can_be_disabled_or_chosen():
    izi = IziProxy()
    with izi.start_local_proxy(port=0, token=False) as open_proxy:
        assert open_proxy.token is None
        assert open_proxy.url == open_proxy.address
    chosen = "a-fixed-token-1234567890"
    with izi.start_local_proxy(port=0, token=chosen) as local:
        assert local.url == f"http://iziproxy:{chosen}@127.0.0.1:{local.port}"


@pytest.mark.parametrize("token", ["short", "with space in the token", "accents-éééééééééééé", 42])
def test_invalid_tokens_are_refused(token):
    with pytest.raises(ValueError):
        LocalProxy(IziProxy(), token=token)


def test_tokenless_proxy_serves_clients_without_header(origin):
    with IziProxy().start_local_proxy(port=0, token=False) as local:
        status, _, _ = send(local, "GET", origin.url(host="127.0.0.1"))
    assert status == 200


def test_each_local_proxy_has_its_own_token():
    izi = IziProxy()
    with izi.start_local_proxy(port=0) as first, izi.start_local_proxy(port=0) as second:
        assert first.token != second.token


# ---------------------------------------------------------------------- #
# Validation des requêtes clientes
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("length", [b"-1", b"+5", b"abc"])
def test_invalid_content_length_gives_400(origin, length):
    with IziProxy().start_local_proxy(port=0) as local:
        raw = (f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"Content-Length: " + length + b"\r\n\r\nhello")
        assert raw_status(local, raw) == b"400"
    assert origin.requests == []


def test_truncated_body_gives_400(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        with socket.create_connection((local.host, local.port), timeout=5) as sock:
            sock.sendall(f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
                         + b"Content-Length: 100\r\n\r\nonly a few bytes")
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(64).split(b" ")[1] == b"400"
    assert origin.requests == []


def test_invalid_chunk_terminator_gives_400(origin):
    with IziProxy().start_local_proxy(port=0) as local:
        raw = (f"POST {origin.url(host='127.0.0.1')} HTTP/1.1\r\n".encode() + token_line(local)
               + b"Transfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n")
        assert raw_status(local, raw) == b"400"


def test_socks_route_gives_a_clear_502():
    izi = IziProxy(proxy_url="socks5h://127.0.0.1:9", interactive=False)
    izi._auth = {"required": False, "type": "basic"}  # pas de sondage
    with izi.start_local_proxy(port=0) as local:
        status, _, body = send(local, "GET", "http://example.test/",
                               headers={"Proxy-Authorization": basic_proxy_authorization(local.url)})
    assert status == 502
    assert b"socks5h" in body


# ---------------------------------------------------------------------- #
# Identifiants absents des affichages
# ---------------------------------------------------------------------- #
def test_repr_does_not_detect_nor_leak(monkeypatch):
    izi = IziProxy(proxy_url="http://user:s3cret@proxy.invalid:8080")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("repr() must not trigger detection")

    monkeypatch.setattr(izi.proxy_detector, "detect_system_proxy", forbidden)
    assert "not resolved" in repr(izi)

    izi._proxy_settings()
    text = repr(izi)
    assert "proxy.invalid:8080" in text and "s3cret" not in text and "user" not in text


def test_local_proxy_debug_logs_hide_upstream_credentials(make_proxy, origin, caplog):
    proxy = make_proxy(auth="basic")
    url_with_creds = proxy.url.replace("http://", f"http://{proxy.username}:{proxy.password}@")
    izi = IziProxy(proxy_url=url_with_creds)
    caplog.set_level(logging.DEBUG, logger="iziproxy")
    with izi.start_local_proxy(port=0) as local:
        status, _, _ = send(local, "GET", origin.url(),
                            headers={"Proxy-Authorization": basic_proxy_authorization(local.url)})
    assert status == 200
    assert proxy.password not in caplog.text
    assert local.token not in caplog.text


# ---------------------------------------------------------------------- #
# Configuration
# ---------------------------------------------------------------------- #
def test_verify_path_must_exist(tmp_path):
    with pytest.raises(ValueError, match="CA bundle not found"):
        IziProxy(verify=str(tmp_path / "missing.pem"))
    bundle = tmp_path / "ca.pem"
    bundle.write_text("")
    assert IziProxy(verify=str(bundle)).verify == str(bundle)


def test_config_from_current_directory_that_picks_the_proxy_is_flagged(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "iziproxy.yml").write_text(
        "environments:\n  local:\n    proxy_url: http://evil.example:8080\nverify: false\n",
        encoding="utf-8")
    caplog.set_level(logging.WARNING, logger="iziproxy")

    IziProxy(environment="local")

    assert "current directory" in caplog.text
    assert "proxy_url" in caplog.text and "verify" in caplog.text


def test_harmless_or_explicit_config_is_not_flagged(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    caplog.set_level(logging.WARNING, logger="iziproxy")

    (tmp_path / "iziproxy.yml").write_text("no_proxy: '*.corp'\n", encoding="utf-8")
    IziProxy()
    (tmp_path / "chosen.yml").write_text(
        "environments:\n  local:\n    proxy_url: http://proxy.corp:8080\n", encoding="utf-8")
    IziProxy(config_path=str(tmp_path / "chosen.yml"))

    assert "current directory" not in caplog.text
