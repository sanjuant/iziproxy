"""
Tests de bout en bout de l'authentification NTLM / Negotiate, avec un proxy
local qui vérifie réellement les jetons (pyspnego côté serveur).
"""

import pytest
import requests

from iziproxy import IziProxy, NtlmAuthenticationError

pytest.importorskip("spnego")


@pytest.fixture
def ntlm_proxy(make_proxy):
    return make_proxy(auth="ntlm")


def ntlm_session(proxy, password=None, **kwargs):
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username,
                   password=password or proxy.password, domain=proxy.domain, **kwargs)
    return izi, izi.create_session()


def test_auth_type_is_detected_from_proxy_headers(ntlm_proxy):
    izi, _ = ntlm_session(ntlm_proxy)
    assert izi.requires_auth is True
    assert izi.auth_type == "ntlm"


def test_https_through_ntlm_tunnel(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    response = session.get(tls_origin.url("/echo?q=1"), verify=False)
    assert response.status_code == 200
    assert response.json()["path"] == "/echo?q=1"
    assert "proxy-authorization" not in response.json()["headers"]
    assert ntlm_proxy.log[-1]["method"] == "CONNECT"


def test_http_through_ntlm_proxy(ntlm_proxy, origin):
    _, session = ntlm_session(ntlm_proxy)
    response = session.get(origin.url("/echo"))
    assert response.status_code == 200
    assert "proxy-authorization" not in response.json()["headers"]


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_post_body_and_headers(ntlm_proxy, origin, tls_origin, scheme):
    server = origin if scheme == "http" else tls_origin
    _, session = ntlm_session(ntlm_proxy)
    response = session.post(server.url("/echo"), json={"hello": "wörld"},
                            headers={"X-Custom": "1"}, verify=False)
    data = response.json()
    assert data["method"] == "POST"
    assert data["body"] == '{"hello": "w\\u00f6rld"}'
    assert data["headers"]["x-custom"] == "1"


def test_case_insensitive_headers_cookies_and_redirects(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)

    response = session.get(tls_origin.url("/cookie"), verify=False)
    assert response.headers["content-length"] == response.headers["Content-Length"]
    assert session.cookies.get("a") == "1"
    assert session.cookies.get("b") == "2"

    redirected = session.get(tls_origin.url("/redirect"), verify=False)
    assert redirected.status_code == 200
    assert redirected.json()["path"] == "/echo?redirected=1"
    assert len(redirected.history) == 1
    # Les cookies de la session sont renvoyés
    assert "a=1" in redirected.json()["headers"]["cookie"]


def test_gzip_chunked_head_and_no_content(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    assert session.get(tls_origin.url("/gzip"), verify=False).json()["path"] == "/gzip"
    assert session.get(tls_origin.url("/chunked"), verify=False).text == "hello chunked world"
    head = session.head(tls_origin.url("/echo"), verify=False, timeout=5)
    assert head.status_code == 200 and head.content == b""
    assert session.get(tls_origin.url("/nocontent"), verify=False, timeout=5).status_code == 204


def test_streaming(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    with session.get(tls_origin.url("/chunked"), verify=False, stream=True) as response:
        assert b"".join(response.iter_content(4)) == b"hello chunked world"


def test_certificate_is_verified_by_default(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    with pytest.raises(requests.exceptions.SSLError):
        session.get(tls_origin.url())


def test_read_timeout(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    with pytest.raises(requests.exceptions.ReadTimeout):
        session.get(tls_origin.url("/slow"), verify=False, timeout=(5, 0.5))


def test_wrong_password(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy, password="wrong")
    with pytest.raises(NtlmAuthenticationError):
        session.get(tls_origin.url(), verify=False)


def test_excluded_host_goes_direct(ntlm_proxy, origin):
    _, session = ntlm_session(ntlm_proxy)
    assert session.get(origin.url(host="127.0.0.1")).status_code == 200
    assert ntlm_proxy.log == []


def test_negotiate_only_proxy(make_proxy, tls_origin):
    proxy = make_proxy(auth="negotiate")
    _, session = ntlm_session(proxy)
    assert session.get(tls_origin.url(), verify=False).status_code == 200


def test_proxy_closing_connection_after_first_407(make_proxy, tls_origin):
    proxy = make_proxy(auth="ntlm", close_on_challenge_request=True)
    _, session = ntlm_session(proxy)
    assert session.get(tls_origin.url(), verify=False).status_code == 200


def test_several_requests_reuse_detected_scheme(ntlm_proxy, tls_origin):
    _, session = ntlm_session(ntlm_proxy)
    for _ in range(3):
        assert session.get(tls_origin.url(), verify=False).status_code == 200
    # Seule la première requête sonde le proxy sans identifiants
    unauthenticated = [e for e in ntlm_proxy.log if "proxy-authorization" not in e["headers"]]
    assert len(unauthenticated) == 1


def test_patch_requests_with_ntlm(ntlm_proxy, tls_origin):
    izi, _ = ntlm_session(ntlm_proxy)
    izi.patch_requests()
    assert requests.get(tls_origin.url(), verify=False).status_code == 200
