"""
Tests d'intégration d'IziProxy avec un vrai proxy local.

Les URLs « origin.test » ne se résolvent pas : une requête qui aboutit a
forcément traversé le proxy. Les URLs 127.0.0.1 sont toujours directes.
"""

import os
import textwrap

import pytest
import requests

from iziproxy import IziProxy


def write_config(text):
    with open("iziproxy.yml", "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(text))


# ---------------------------------------------------------------------- #
# Proxy sans authentification
# ---------------------------------------------------------------------- #
def test_session_http_through_proxy(make_proxy, origin):
    proxy = make_proxy()
    session = IziProxy(proxy_url=proxy.url).create_session()

    response = session.get(origin.url("/echo?x=1"))

    assert response.status_code == 200
    assert response.json()["path"] == "/echo?x=1"
    assert proxy.log[-1]["target"] == origin.url("/echo?x=1")


def test_session_https_through_connect(make_proxy, tls_origin):
    proxy = make_proxy()
    session = IziProxy(proxy_url=proxy.url).create_session()

    response = session.get(tls_origin.url("/echo"), verify=False)

    assert response.json()["path"] == "/echo"
    assert proxy.log[-1]["method"] == "CONNECT"
    assert proxy.log[-1]["target"] == f"origin.test:{tls_origin.port}"


def test_no_auth_probe_detects_open_proxy(make_proxy):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)
    assert izi.requires_auth is False
    assert izi.get_credentials() == (None, None, None)


def test_proxy_from_config_file(make_proxy, origin):
    proxy = make_proxy()
    write_config(f"""
        environments:
          dev:
            proxy_url: "{proxy.url}"
            requires_auth: false
    """)
    izi = IziProxy(environment="dev")
    assert izi.get_proxy_url() == proxy.url
    assert izi.create_session().get(origin.url()).status_code == 200


def test_proxy_from_environment_variables(make_proxy, origin, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    izi = IziProxy()
    assert izi.get_proxy_dict()["https"] == proxy.url
    assert izi.create_session().get(origin.url()).status_code == 200


def test_direct_connection_when_no_proxy(origin):
    izi = IziProxy()
    assert izi.get_proxy_dict() == {}
    assert izi.get_proxy_url() is None
    assert izi.create_session().get(origin.url(host="127.0.0.1")).status_code == 200


# ---------------------------------------------------------------------- #
# Exclusions
# ---------------------------------------------------------------------- #
def test_loopback_is_never_proxied(make_proxy, origin):
    proxy = make_proxy()
    session = IziProxy(proxy_url=proxy.url).create_session()
    assert session.get(origin.url(host="127.0.0.1")).status_code == 200
    assert proxy.log == []


def test_no_proxy_rules_are_applied_per_request(make_proxy, origin):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url, no_proxy="*.internal,<local>")

    assert izi.get_proxy_dict("http://app.internal/") == {}
    assert izi.get_proxy_dict("http://intranet/") == {}
    assert izi.get_proxy_dict("http://example.com/")["http"] == proxy.url

    session = izi.create_session()
    session.get(origin.url())
    assert len(proxy.log) == 1
    # Un hôte exclu est contacté directement (ici il ne se résout pas)
    with pytest.raises(requests.exceptions.ConnectionError):
        session.get(f"http://app.internal:{origin.port}/echo", timeout=3)
    assert len(proxy.log) == 1


def test_system_no_proxy_is_honoured(make_proxy, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.setenv("NO_PROXY", ".corp.example")
    izi = IziProxy()
    assert izi.get_proxy_dict("https://wiki.corp.example/") == {}
    assert izi.get_proxy_dict("https://example.org/")["https"] == proxy.url


# ---------------------------------------------------------------------- #
# Authentification Basic
# ---------------------------------------------------------------------- #
def test_basic_auth_https_credentials_only_sent_to_proxy(make_proxy, tls_origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)

    response = izi.create_session().get(tls_origin.url(), verify=False)

    assert response.status_code == 200
    assert "proxy-authorization" in proxy.log[-1]["headers"]
    # L'en-tête ne doit jamais atteindre le site cible
    assert "proxy-authorization" not in response.json()["headers"]
    assert "authorization" not in response.json()["headers"]


def test_basic_auth_http(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)
    response = izi.create_session().get(origin.url())
    assert response.status_code == 200
    assert "proxy-authorization" not in response.json()["headers"]


def test_basic_auth_special_characters(make_proxy, origin):
    password = "p@ss:w/rd%41é"
    proxy = make_proxy(auth="basic", username="DOM\\bob", password=password)
    izi = IziProxy(proxy_url=proxy.url, username="DOM\\bob", password=password)
    assert izi.create_session().get(origin.url()).status_code == 200


def test_auth_is_autodetected_and_credentials_found_in_env(make_proxy, origin, monkeypatch):
    """requires_auth absent de la configuration : le 407 est détecté par sondage."""
    proxy = make_proxy(auth="basic")
    monkeypatch.setenv("IZI_USERNAME", proxy.username)
    monkeypatch.setenv("IZI_PASSWORD", proxy.password)

    izi = IziProxy(proxy_url=proxy.url)

    assert izi.requires_auth is True
    assert izi.auth_type == "basic"
    assert izi.create_session().get(origin.url()).status_code == 200


def test_credentials_from_keyring(make_proxy, origin, memory_keyring):
    proxy = make_proxy(auth="basic")
    write_config(f"""
        environments:
          local:
            proxy_url: "{proxy.url}"
            requires_auth: true
            auth_type: basic
    """)
    memory_keyring.set_password("iziproxy_local-basic", "__username__", proxy.username)
    memory_keyring.set_password("iziproxy_local-basic", proxy.username, proxy.password)

    izi = IziProxy(environment="local")
    assert izi.create_session().get(origin.url()).status_code == 200


def test_wrong_basic_credentials(make_proxy, origin, tls_origin):
    proxy = make_proxy(auth="basic")
    session = IziProxy(proxy_url=proxy.url, username="alice", password="nope").create_session()
    assert session.get(origin.url()).status_code == 407
    with pytest.raises(requests.exceptions.ProxyError):
        session.get(tls_origin.url(), verify=False)


def test_get_proxy_dict_works_with_plain_requests(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password)
    response = requests.get(origin.url(), proxies=izi.get_proxy_dict())
    assert response.status_code == 200


def test_missing_credentials_do_not_prompt_when_non_interactive(make_proxy, origin):
    proxy = make_proxy(auth="basic")
    izi = IziProxy(proxy_url=proxy.url, interactive=False)
    assert izi.requires_auth is True
    assert izi.create_session().get(origin.url()).status_code == 407


def test_interactive_prompt_is_used_and_stored(make_proxy, origin, monkeypatch, memory_keyring):
    from iziproxy.password_manager import PasswordManager

    proxy = make_proxy(auth="basic")
    calls = []

    def fake_prompt(self, **kwargs):
        calls.append(kwargs)
        return proxy.username, proxy.password, None

    monkeypatch.setattr(PasswordManager, "get_credentials_interactive", fake_prompt)
    izi = IziProxy(proxy_url=proxy.url)

    assert izi.create_session().get(origin.url()).status_code == 200
    assert len(calls) == 1
    assert memory_keyring.get_password("iziproxy_local-basic", proxy.username) == proxy.password

    # Une seconde instance retrouve le mot de passe sans redemander
    assert IziProxy(proxy_url=proxy.url).create_session().get(origin.url()).status_code == 200
    assert len(calls) == 1

    IziProxy(proxy_url=proxy.url).reset_credentials()
    assert memory_keyring.get_password("iziproxy_local-basic", proxy.username) is None


# ---------------------------------------------------------------------- #
# PAC
# ---------------------------------------------------------------------- #
def test_pac_file_is_evaluated_per_host(make_proxy, origin, tmp_path):
    pytest.importorskip("pypac")
    proxy = make_proxy()
    pac = tmp_path / "proxy.pac"
    pac.write_text(textwrap.dedent(f"""
        function FindProxyForURL(url, host) {{
            if (dnsDomainIs(host, ".direct.test")) return "DIRECT";
            return "PROXY 127.0.0.1:{proxy.port}; DIRECT";
        }}
    """))
    izi = IziProxy(pac_url=str(pac))

    assert izi.get_proxy_dict("http://a.direct.test/") == {}
    assert izi.get_proxy_url("http://origin.test/") == proxy.url
    assert izi.create_session().get(origin.url()).status_code == 200
    assert len(proxy.log) == 1


# ---------------------------------------------------------------------- #
# Variables d'environnement et patch
# ---------------------------------------------------------------------- #
def test_environment_variables_are_restored(make_proxy, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("NO_PROXY", "previous")
    izi = IziProxy(proxy_url=proxy.url, no_proxy="*.corp")

    values = izi.set_environment_variables()

    assert os.environ["HTTPS_PROXY"] == proxy.url
    assert ".corp" in values["NO_PROXY"].split(",")
    assert "localhost" in os.environ["no_proxy"]

    izi.clear_environment_variables()
    assert "HTTPS_PROXY" not in os.environ
    assert os.environ["NO_PROXY"] == "previous"


def test_patch_requests_covers_module_functions_and_new_sessions(make_proxy, origin):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)

    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get(origin.url(), timeout=3)

    izi.patch_requests()
    assert requests.get(origin.url()).status_code == 200
    assert requests.Session().get(origin.url()).status_code == 200
    assert len(proxy.log) == 2

    izi.unpatch_requests()
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get(origin.url(), timeout=3)


def test_context_manager_unpatches(make_proxy):
    proxy = make_proxy()
    original = requests.Session.__init__
    with IziProxy(proxy_url=proxy.url) as izi:
        izi.patch_requests()
        assert requests.Session.__init__ is not original
    assert requests.Session.__init__ is original


# ---------------------------------------------------------------------- #
# Divers
# ---------------------------------------------------------------------- #
def test_proxy_host_and_port():
    izi = IziProxy(proxy_url="proxy.corp.example:3128")
    assert izi.get_proxy_host() == "proxy.corp.example"
    assert izi.get_proxy_port() == 3128
    assert IziProxy(proxy_url="http://proxy.corp.example").get_proxy_port() == 80


def test_secrets_are_masked_in_repr_and_config():
    izi = IziProxy(proxy_url="http://proxy.invalid:8080", username="u", password="topsecret",
                   environment="dev")
    config = izi.get_proxy_config()
    assert "topsecret" not in repr(config)
    assert "topsecret" not in repr(izi)
    assert "topsecret" in config.get_real_config()["http"]


def test_refresh_redetects(make_proxy, monkeypatch):
    proxy = make_proxy()
    izi = IziProxy()
    assert izi.get_proxy_dict() == {}
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    assert izi.refresh().get_proxy_url() == proxy.url


def test_debug_logging_is_visible(capsys):
    IziProxy(debug=True)
    assert "IziProxy initialized" in capsys.readouterr().err
