"""
Proxys joints en TLS (URL https://) : sonde, NTLM via requests (y compris
TLS dans TLS vers une cible HTTPS), proxy local et urllib.

Le certificat du proxy de test est auto-signé : les tests le déclarent de
confiance avec l'option verify d'IziProxy.
"""

import json
import ssl
import urllib.request

import pytest
import requests

from iziproxy import IziProxy


def insecure_env_opener():
    """Client urllib qui lit HTTP(S)_PROXY ; la cible HTTPS de test n'est pas vérifiée."""
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.ProxyHandler(),
                                       urllib.request.HTTPSHandler(context=insecure))


def get_json(opener, url):
    with opener.open(url, timeout=10) as response:
        return response.status, json.loads(response.read())


@pytest.fixture
def ntlm_tls_proxy(make_proxy):
    pytest.importorskip("spnego")
    return make_proxy(auth="ntlm", tls=True)


def ntlm_izi(proxy, **kwargs):
    kwargs.setdefault("verify", proxy.cert_path)
    return IziProxy(proxy_url=proxy.url, username=proxy.username,
                    password=proxy.password, domain=proxy.domain, **kwargs)


def basic_izi(proxy, **kwargs):
    kwargs.setdefault("verify", proxy.cert_path)
    return IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password, **kwargs)


def test_probe_speaks_tls_to_the_proxy(make_proxy):
    proxy = make_proxy(auth="basic", tls=True)
    izi = IziProxy(proxy_url=proxy.url, verify=proxy.cert_path)
    assert proxy.url.startswith("https://")
    assert izi.requires_auth is True
    assert izi.auth_type == "basic"


def test_ntlm_http_target_through_tls_proxy(ntlm_tls_proxy, origin):
    response = ntlm_izi(ntlm_tls_proxy).create_session().get(origin.url("/echo?q=1"))
    assert response.status_code == 200
    assert response.json()["path"] == "/echo?q=1"
    assert ntlm_tls_proxy.log[-1]["method"] == "GET"


def test_ntlm_https_target_tls_in_tls(ntlm_tls_proxy, tls_origin):
    session = ntlm_izi(ntlm_tls_proxy).create_session()
    response = session.post(tls_origin.url("/echo"), json={"a": 1}, verify=False)
    assert response.status_code == 200
    assert response.json()["body"] == '{"a": 1}'
    assert ntlm_tls_proxy.log[-1]["method"] == "CONNECT"


def test_untrusted_proxy_certificate_is_refused(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm", tls=True)
    izi = ntlm_izi(proxy, verify=True, auth_type="ntlm")
    with pytest.raises(requests.exceptions.ProxyError, match="TLS handshake with proxy"):
        izi.create_session().get(origin.url())
    assert proxy.log == []


def test_untrusted_certificate_is_reported_by_the_probe(make_proxy, caplog):
    proxy = make_proxy(auth="basic", tls=True)
    assert IziProxy(proxy_url=proxy.url).requires_auth is False
    assert "TLS handshake with proxy" in caplog.text


def test_verify_false_skips_the_proxy_certificate(ntlm_tls_proxy, origin):
    response = ntlm_izi(ntlm_tls_proxy, verify=False).create_session().get(origin.url())
    assert response.status_code == 200


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_basic_through_requests_uses_iziproxy_verify(make_proxy, origin, tls_origin, scheme):
    """requests seul vérifierait le proxy avec certifi : IziProxy impose son propre contexte."""
    proxy = make_proxy(auth="basic", tls=True)
    server = origin if scheme == "http" else tls_origin
    response = basic_izi(proxy).create_session().get(server.url("/echo?q=5"), verify=False)
    assert response.json()["path"] == "/echo?q=5"
    assert proxy.log[-1]["headers"]["proxy-authorization"].startswith("Basic ")


def test_basic_through_requests_refuses_an_untrusted_proxy(make_proxy, origin):
    proxy = make_proxy(auth="basic", tls=True)
    izi = basic_izi(proxy, verify=True)
    with pytest.raises(requests.exceptions.ProxyError, match="certifi|CERTIFICATE|certificat"):
        izi.create_session().get(origin.url())


def test_httpx_and_urllib3_use_iziproxy_verify(make_proxy, origin):
    pytest.importorskip("httpx")
    proxy = make_proxy(auth="basic", tls=True)
    izi = basic_izi(proxy)
    with izi.httpx_client() as client:
        assert client.get(origin.url("/echo?lib=httpx")).json()["path"] == "/echo?lib=httpx"
    response = izi.urllib3_pool_manager().request("GET", origin.url("/echo?lib=urllib3"))
    assert json.loads(response.data)["path"] == "/echo?lib=urllib3"


def test_invalid_verify_value():
    with pytest.raises(ValueError, match="Invalid verify value"):
        IziProxy(verify=3)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_local_proxy_relays_to_tls_ntlm_proxy(ntlm_tls_proxy, origin, tls_origin, scheme):
    server = origin if scheme == "http" else tls_origin
    izi = ntlm_izi(ntlm_tls_proxy)
    try:
        izi.set_environment_variables(local_proxy=True)
        status, data = get_json(insecure_env_opener(), server.url("/echo?q=2"))
    finally:
        izi.clear_environment_variables()
    assert (status, data["path"]) == (200, "/echo?q=2")
    assert ntlm_tls_proxy.log[-1]["method"] == ("CONNECT" if scheme == "https" else "GET")


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_local_proxy_relays_to_tls_basic_proxy(make_proxy, origin, tls_origin, scheme):
    proxy = make_proxy(auth="basic", tls=True)
    server = origin if scheme == "http" else tls_origin
    izi = basic_izi(proxy)
    with izi.start_local_proxy() as local:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": local.url, "https": local.url}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        )
        status, data = get_json(opener, server.url("/echo?q=3"))
    assert (status, data["path"]) == (200, "/echo?q=3")
    assert proxy.log[-1]["headers"]["proxy-authorization"].startswith("Basic ")


def test_urllib_opener_goes_through_the_local_proxy(make_proxy, origin):
    proxy = make_proxy(auth="basic", tls=True)
    izi = basic_izi(proxy)
    try:
        status, data = get_json(izi.urllib_opener(), origin.url("/echo?q=4"))
    finally:
        izi.stop_local_proxies()
    assert (status, data["path"]) == (200, "/echo?q=4")
    assert proxy.log[-1]["method"] == "GET"


# ---------------------------------------------------------------------- #
# Fichier PAC servi en HTTPS
# ---------------------------------------------------------------------- #
def test_https_pac_with_untrusted_certificate_is_ignored(tls_origin, caplog):
    from iziproxy.proxy_detector import ProxyDetector

    pac_url = f"https://127.0.0.1:{tls_origin.port}/proxy.pac"
    assert ProxyDetector.fetch_pac(pac_url) is None
    assert "certificate could not be verified" in caplog.text
    # Aucun second essai sans vérification
    assert len(tls_origin.requests) == 0


def test_https_pac_with_trusted_ca(tls_origin):
    from iziproxy.proxy_detector import ProxyDetector

    pac_url = f"https://127.0.0.1:{tls_origin.port}/proxy.pac"
    assert "/proxy.pac" in ProxyDetector.fetch_pac(pac_url, verify=tls_origin.cert_path)
    assert "/proxy.pac" in ProxyDetector.fetch_pac(pac_url, verify=False)


def test_iziproxy_verify_reaches_the_pac_download(tls_origin, monkeypatch):
    from iziproxy.proxy_detector import ProxyDetector

    seen = []
    monkeypatch.setattr(ProxyDetector, "fetch_pac",
                        staticmethod(lambda url, verify=True: seen.append(verify)))
    izi = IziProxy(pac_url=f"https://127.0.0.1:{tls_origin.port}/proxy.pac", verify=tls_origin.cert_path)
    pytest.importorskip("pypac")
    izi.get_proxy_url()
    assert seen == [tls_origin.cert_path]


# ---------------------------------------------------------------------- #
# Autorités du système
# ---------------------------------------------------------------------- #
def test_truststore_is_used_when_installed():
    truststore = pytest.importorskip("truststore")
    from iziproxy.proxy_utils import build_ssl_context

    assert isinstance(build_ssl_context(), truststore.SSLContext)
    # Une autorité explicite remplace celles du système, comme dans requests
    assert not isinstance(build_ssl_context(False), truststore.SSLContext)


def test_openssl_store_without_truststore(monkeypatch):
    import sys

    from iziproxy.proxy_utils import build_ssl_context

    monkeypatch.setitem(sys.modules, "truststore", None)
    ctx = build_ssl_context()
    assert type(ctx) is ssl.SSLContext
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
