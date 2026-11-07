"""
Tests de iziproxy.install() : après un seul appel, chaque client HTTP du
processus (et ses sous-processus) doit traverser le proxy d'entreprise de
test sans autre configuration.

Les URLs « origin.test » ne se résolvent pas : une requête qui aboutit a
forcément traversé le proxy.
"""

import json
import os
import subprocess
import sys
import urllib.request

import pytest
import requests

import iziproxy
from iziproxy import IziProxy


@pytest.fixture(autouse=True)
def always_uninstall():
    yield
    iziproxy.uninstall()


@pytest.fixture
def ntlm_proxy(make_proxy):
    pytest.importorskip("spnego")
    return make_proxy(auth="ntlm")


def install_ntlm(proxy, **kwargs):
    return iziproxy.install(proxy_url=proxy.url, username=proxy.username,
                            password=proxy.password, domain=proxy.domain, **kwargs)


# ---------------------------------------------------------------------- #
# Une ligne, tous les clients
# ---------------------------------------------------------------------- #
def test_requests_and_urllib_work_after_one_call(ntlm_proxy, origin):
    install_ntlm(ntlm_proxy)

    assert requests.get(origin.url("/echo?lib=requests")).json()["path"] == "/echo?lib=requests"
    with urllib.request.urlopen(origin.url("/echo?lib=urllib"), timeout=10) as response:
        assert json.loads(response.read())["path"] == "/echo?lib=urllib"


def test_httpx_reads_the_environment(ntlm_proxy, origin):
    httpx = pytest.importorskip("httpx")
    install_ntlm(ntlm_proxy)

    assert httpx.get(origin.url("/echo?lib=httpx"), timeout=10).json()["path"] == "/echo?lib=httpx"


def test_aiohttp_with_trust_env(ntlm_proxy, origin):
    aiohttp = pytest.importorskip("aiohttp")
    import asyncio

    install_ntlm(ntlm_proxy)

    async def fetch():
        async with aiohttp.ClientSession(trust_env=True) as session:
            async with session.get(origin.url("/echo?lib=aiohttp")) as response:
                return await response.json()

    assert asyncio.run(fetch())["path"] == "/echo?lib=aiohttp"


def test_subprocess_inherits_the_configuration(ntlm_proxy, origin):
    install_ntlm(ntlm_proxy)
    code = ("import json, urllib.request;"
            f"print(json.loads(urllib.request.urlopen({origin.url('/echo?lib=child')!r}, timeout=10).read())['path'])")

    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            env=dict(os.environ), timeout=30)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "/echo?lib=child"


def test_no_password_in_the_environment(make_proxy):
    proxy = make_proxy(auth="basic")
    installation = iziproxy.install(proxy_url=proxy.url, username=proxy.username,
                                    password=proxy.password)

    assert installation.local_proxy_url.startswith("http://127.0.0.1:")
    assert os.environ["HTTPS_PROXY"] == installation.local_proxy_url
    assert proxy.password not in " ".join(os.environ.values())


# ---------------------------------------------------------------------- #
# Ce qui est configuré, et comment l'annuler
# ---------------------------------------------------------------------- #
def test_installation_reports_what_was_done(ntlm_proxy):
    installation = install_ntlm(ntlm_proxy)

    assert installation.active
    assert installation.requests_patched and installation.urllib_patched
    assert set(installation.environment) >= {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
    assert isinstance(installation.proxy, IziProxy)
    assert iziproxy.current() is installation
    text = installation.describe()
    assert ntlm_proxy.url in text and "(ntlm)" in text and installation.local_proxy_url in text
    assert "requests, urllib, environment" in str(installation)


def test_uninstall_restores_everything(ntlm_proxy, origin, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://previous:1")
    original_init = requests.Session.__init__
    original_opener = urllib.request._opener

    installation = install_ntlm(ntlm_proxy)
    local_url = installation.local_proxy_url
    iziproxy.uninstall()

    assert os.environ["HTTPS_PROXY"] == "http://previous:1"
    assert "HTTP_PROXY" not in os.environ
    assert requests.Session.__init__ is original_init
    assert urllib.request._opener is original_opener
    assert iziproxy.current() is None
    assert installation.describe() == "uninstalled"
    with pytest.raises(OSError):
        urllib.request.build_opener(urllib.request.ProxyHandler({"http": local_url})).open(
            origin.url(), timeout=3)
    iziproxy.uninstall()  # sans effet


def test_refresh_after_install_keeps_the_corporate_proxy(make_proxy, origin, monkeypatch):
    """Proxy trouvé dans HTTP_PROXY : après install(), refresh() ne doit pas boucler sur le proxy local."""
    proxy = make_proxy(auth="basic")
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    monkeypatch.setenv("IZIPROXY_USERNAME", proxy.username)
    monkeypatch.setenv("IZIPROXY_PASSWORD", proxy.password)

    installation = iziproxy.install()
    assert os.environ["HTTP_PROXY"] == installation.local_proxy_url
    installation.proxy.refresh()

    assert installation.proxy.get_proxy_url() == proxy.url
    assert requests.get(origin.url("/echo")).status_code == 200
    iziproxy.uninstall()
    assert os.environ["HTTP_PROXY"] == proxy.url


def test_context_manager(ntlm_proxy, origin):
    with install_ntlm(ntlm_proxy) as installation:
        assert installation.active
        assert requests.get(origin.url()).status_code == 200
    assert iziproxy.current() is None
    assert "HTTPS_PROXY" not in os.environ


def test_second_install_replaces_the_first(make_proxy, origin):
    first_proxy, second_proxy = make_proxy(), make_proxy()
    first = iziproxy.install(proxy_url=first_proxy.url)
    second = iziproxy.install(proxy_url=second_proxy.url)

    assert first.describe() == "uninstalled"
    assert iziproxy.current() is second
    requests.get(origin.url())
    assert len(first_proxy.log) == 0 and len(second_proxy.log) == 1


# ---------------------------------------------------------------------- #
# Sans proxy, rien ne change
# ---------------------------------------------------------------------- #
def test_without_proxy_nothing_changes():
    original_init = requests.Session.__init__
    original_opener = urllib.request._opener

    installation = iziproxy.install()

    assert not installation.active
    assert "no proxy found" in installation.describe()
    assert requests.Session.__init__ is original_init
    assert urllib.request._opener is original_opener
    assert "HTTPS_PROXY" not in os.environ
    assert installation.proxy.get_proxy_url() is None


# ---------------------------------------------------------------------- #
# Réglages spécifiques
# ---------------------------------------------------------------------- #
def test_choose_what_to_configure(make_proxy, origin):
    proxy = make_proxy()
    original_init = requests.Session.__init__

    installation = iziproxy.install(proxy_url=proxy.url, requests=False, env_vars=False)

    assert requests.Session.__init__ is original_init
    assert "HTTPS_PROXY" not in os.environ
    assert installation.local_proxy_url is None
    assert "urllib" in installation.describe()
    with urllib.request.urlopen(origin.url(), timeout=10) as response:
        assert response.status == 200


def test_existing_instance(make_proxy, origin):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)

    assert iziproxy.install(izi).proxy is izi
    with pytest.raises(TypeError):
        iziproxy.install(izi, proxy_url=proxy.url)


def test_direct_environment_variables_with_basic(make_proxy):
    proxy = make_proxy(auth="basic")
    installation = iziproxy.install(proxy_url=proxy.url, username=proxy.username,
                                    password=proxy.password, local_proxy=False)

    assert installation.local_proxy_url is None
    assert os.environ["HTTPS_PROXY"].startswith("http://alice:")


def test_direct_environment_variables_refused_with_ntlm(ntlm_proxy):
    with pytest.raises(ValueError, match="local_proxy=True"):
        install_ntlm(ntlm_proxy, local_proxy=False)
    # Rien ne reste configuré après l'échec
    assert iziproxy.current() is None
    assert "HTTPS_PROXY" not in os.environ
