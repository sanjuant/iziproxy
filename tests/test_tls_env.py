"""
Variables TLS des sous-processus (iziproxy.tls_env) : export des autorités
du système, variables d'autorités, révocation « au mieux » pour git sous
Windows, restauration exacte.

Le magasin Windows et la plateforme sont simulés : les tests ne dépendent
pas de la machine.
"""

import logging
import os
import ssl
import time
from types import SimpleNamespace

import pytest

import iziproxy
from iziproxy import IziProxy, tls_env

# cache_dir() réel (le conftest le remplace pendant chaque test)
REAL_CACHE_DIR = tls_env.cache_dir
CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"
TLS_NAMES = tls_env.CA_VARS + ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                               "GIT_CONFIG_KEY_2", "GIT_CONFIG_VALUE_2")


def set_platform(monkeypatch, name):
    """Plateforme vue par tls_env seulement (le reste du processus n'est pas trompé)."""
    monkeypatch.setattr(tls_env, "sys", SimpleNamespace(platform=name))


def pem(der):
    return ssl.DER_cert_to_PEM_cert(der)


@pytest.fixture
def windows_store(monkeypatch):
    """Simule Windows et son magasin de certificats ; calls compte les lectures."""
    stores = {
        "ROOT": [(b"root-all-purposes", "x509_asn", True),
                 (b"root-server-auth", "x509_asn", {tls_env.SERVER_AUTH_OID}),
                 (b"root-code-signing", "x509_asn", {CODE_SIGNING_OID}),
                 (b"pkcs7-blob", "pkcs_7_asn", True)],
        "CA": [(b"intermediate", "x509_asn", True),
               (b"root-all-purposes", "x509_asn", True)],
    }
    calls = []

    def enum_certificates(store):
        calls.append(store)
        return stores[store]

    set_platform(monkeypatch, "win32")
    monkeypatch.setattr(tls_env, "_enum_certificates", enum_certificates)
    monkeypatch.setattr(tls_env, "_certifi_pems", lambda: pem(b"certifi-root"))
    return calls


@pytest.fixture(autouse=True)
def clean_tls_vars(monkeypatch):
    for name in TLS_NAMES:
        monkeypatch.delenv(name, raising=False)
    yield
    iziproxy.uninstall()


# ---------------------------------------------------------------------- #
# Export des autorités
# ---------------------------------------------------------------------- #
def test_windows_export_keeps_server_auth_certificates(windows_store):
    path = tls_env.system_ca_bundle()

    assert path == os.path.join(tls_env.cache_dir(), tls_env.BUNDLE_NAME)
    content = open(path, encoding="ascii").read()
    for kept in (b"root-all-purposes", b"root-server-auth", b"intermediate", b"certifi-root"):
        assert pem(kept) in content
    assert pem(b"root-code-signing") not in content
    assert content.count(pem(b"root-all-purposes")) == 1
    assert content.count("BEGIN CERTIFICATE") == 4
    assert windows_store == ["ROOT", "CA"]
    # Écriture atomique : aucun fichier temporaire ne reste
    assert os.listdir(tls_env.cache_dir()) == [tls_env.BUNDLE_NAME]


def test_export_is_reused_then_refreshed_after_a_day(windows_store):
    path = tls_env.system_ca_bundle()
    assert tls_env.system_ca_bundle() == path
    assert windows_store == ["ROOT", "CA"]

    old = time.time() - tls_env.MAX_AGE - 60
    os.utime(path, (old, old))
    assert tls_env.system_ca_bundle() == path
    assert windows_store == ["ROOT", "CA", "ROOT", "CA"]
    assert os.path.getmtime(path) > old


def test_export_failure_logs_a_warning_and_returns_none(windows_store, monkeypatch, caplog):
    def broken(store):
        raise OSError("access denied")

    monkeypatch.setattr(tls_env, "_enum_certificates", broken)
    with caplog.at_level(logging.WARNING, logger="iziproxy"):
        assert tls_env.system_ca_bundle() is None
    assert "Could not export the system CA bundle" in caplog.text
    assert tls_env.tls_environment(True, {}).keys() == {"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
                                                        "GIT_CONFIG_VALUE_0"}


def test_empty_store_is_a_failure(windows_store, monkeypatch):
    monkeypatch.setattr(tls_env, "_enum_certificates", lambda store: [])
    assert tls_env.system_ca_bundle() is None
    assert not os.path.exists(os.path.join(tls_env.cache_dir(), tls_env.BUNDLE_NAME))


def test_linux_uses_the_distribution_bundle(monkeypatch, tmp_path):
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(pem(b"distro-root"))
    set_platform(monkeypatch, "linux")
    monkeypatch.setattr(tls_env, "SYSTEM_BUNDLES", ("/nonexistent/ca.pem", str(bundle)))
    monkeypatch.setattr(ssl, "get_default_verify_paths",
                        lambda: ssl.DefaultVerifyPaths(None, None, None, None, None, None))

    assert tls_env.system_ca_bundle() == str(bundle)

    monkeypatch.setattr(tls_env, "SYSTEM_BUNDLES", ())
    import certifi

    assert tls_env.system_ca_bundle() == certifi.where()


def test_cache_dir_follows_the_platform(monkeypatch, tmp_path):
    set_platform(monkeypatch, "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert REAL_CACHE_DIR() == os.path.join(str(tmp_path / "local"), "iziproxy")
    set_platform(monkeypatch, "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert REAL_CACHE_DIR() == os.path.join(str(tmp_path / "xdg"), "iziproxy")


# ---------------------------------------------------------------------- #
# Choix des variables
# ---------------------------------------------------------------------- #
def test_user_values_are_never_replaced(windows_store):
    values = tls_env.tls_environment(True, {"PIP_CERT": "/mine.pem", "SSL_CERT_FILE": ""})

    bundle = tls_env.system_ca_bundle()
    assert "PIP_CERT" not in values
    # Une variable vide compte comme absente
    for name in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        assert values[name] == bundle


def test_no_export_when_every_variable_is_set(windows_store):
    original = dict.fromkeys(tls_env.CA_FILE_VARS, "/mine.pem")
    git_names = {"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"}
    assert set(tls_env.tls_environment(True, original)) == git_names
    assert windows_store == []


def test_verify_false_sets_no_ca_variable(windows_store):
    values = tls_env.tls_environment(False, {})
    assert not set(values) & set(tls_env.CA_VARS)
    assert windows_store == []


def test_verify_path_replaces_the_export(windows_store, tmp_path):
    ca_file = tmp_path / "corp.pem"
    ca_file.write_text(pem(b"corp"))
    values = tls_env.tls_environment(str(ca_file), {})
    assert {name: values[name] for name in tls_env.CA_FILE_VARS} == dict.fromkeys(tls_env.CA_FILE_VARS,
                                                                                  str(ca_file))
    assert "SSL_CERT_DIR" not in values
    assert windows_store == []

    values = tls_env.tls_environment(str(tmp_path), {})
    assert set(values) & set(tls_env.CA_VARS) == {"REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_DIR"}
    assert values["SSL_CERT_DIR"] == str(tmp_path)


def test_git_revocation_is_appended_to_existing_git_config(windows_store):
    original = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_KEY_1": "user.name", "GIT_CONFIG_VALUE_1": "me"}
    values = tls_env.tls_environment(False, original)
    assert values == {"GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_2": "http.schannelCheckRevoke",
                      "GIT_CONFIG_VALUE_2": "best-effort"}


@pytest.mark.parametrize("original", [
    {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.schannelcheckrevoke", "GIT_CONFIG_VALUE_0": "true"},
    {"GIT_CONFIG_COUNT": "many"},
    {"GIT_CONFIG_COUNT": "-1"},
])
def test_git_revocation_left_alone(windows_store, original):
    assert tls_env.tls_environment(False, original) == {}


def test_no_git_variable_outside_windows(monkeypatch):
    set_platform(monkeypatch, "linux")
    assert tls_env.tls_environment(False, {}) == {}


# ---------------------------------------------------------------------- #
# set_environment_variables() / install()
# ---------------------------------------------------------------------- #
def snapshot():
    return {name: os.environ.get(name) for name in TLS_NAMES}


def test_set_environment_variables_defines_and_restores(windows_store, make_proxy, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/user/node.pem")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "0")
    before = snapshot()
    izi = IziProxy(proxy_url=proxy.url)

    values = izi.set_environment_variables()
    bundle = tls_env.system_ca_bundle()
    for name in ("REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
        assert values[name] == os.environ[name] == bundle
    assert os.environ["NODE_EXTRA_CA_CERTS"] == "/user/node.pem"
    assert "NODE_EXTRA_CA_CERTS" not in values
    assert os.environ["GIT_CONFIG_COUNT"] == "1"
    assert os.environ["GIT_CONFIG_KEY_0"] == "http.schannelCheckRevoke"
    assert os.environ["GIT_CONFIG_VALUE_0"] == "best-effort"
    assert os.environ["HTTPS_PROXY"] == proxy.url

    # Un second appel décide sur les valeurs d'origine : pas d'empilement
    izi.set_environment_variables()
    assert os.environ["GIT_CONFIG_COUNT"] == "1"

    izi.clear_environment_variables()
    assert snapshot() == before


def test_tls_env_false_restores_a_previous_call(windows_store, make_proxy):
    proxy = make_proxy()
    before = snapshot()
    izi = IziProxy(proxy_url=proxy.url)

    izi.set_environment_variables()
    assert os.environ["SSL_CERT_FILE"]
    values = izi.set_environment_variables(tls_env=False)
    assert not set(values) & set(TLS_NAMES)
    assert snapshot() == before
    izi.clear_environment_variables()
    assert snapshot() == before


def test_verify_false_keeps_git_setting_only(windows_store, make_proxy):
    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url, verify=False)

    values = izi.set_environment_variables()
    assert not set(values) & set(tls_env.CA_VARS)
    assert values["GIT_CONFIG_KEY_0"] == "http.schannelCheckRevoke"
    izi.clear_environment_variables()


def test_export_failure_does_not_break_install(windows_store, make_proxy, monkeypatch):
    def broken(store):
        raise PermissionError("denied")

    monkeypatch.setattr(tls_env, "_enum_certificates", broken)
    proxy = make_proxy()

    installation = iziproxy.install(proxy_url=proxy.url)
    assert installation.active
    assert os.environ["HTTPS_PROXY"] == installation.local_proxy_url
    assert "SSL_CERT_FILE" not in os.environ


def test_install_and_uninstall(windows_store, make_proxy, monkeypatch):
    proxy = make_proxy()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/user/requests.pem")
    before = snapshot()

    installation = iziproxy.install(proxy_url=proxy.url)
    assert os.environ["REQUESTS_CA_BUNDLE"] == "/user/requests.pem"
    assert installation.environment["SSL_CERT_FILE"] == os.environ["SSL_CERT_FILE"]
    assert os.environ["GIT_CONFIG_COUNT"] == "1"

    installation.uninstall()
    assert snapshot() == before


def test_install_opt_out(windows_store, make_proxy):
    proxy = make_proxy()
    before = snapshot()

    installation = iziproxy.install(proxy_url=proxy.url, tls_env=False)
    assert installation.active
    assert snapshot() == before
    assert windows_store == []


def test_nothing_without_proxy(windows_store):
    before = snapshot()
    installation = iziproxy.install()
    assert not installation.active
    assert IziProxy().set_environment_variables() == {}
    assert snapshot() == before


# ---------------------------------------------------------------------- #
# requests du processus : les variables d'IziProxy ne s'appliquent pas
# ---------------------------------------------------------------------- #
def session_verify(session, verify=None, url="https://example.com/"):
    """verify que requests utiliserait pour une requête de la session."""
    return session.merge_environment_settings(url, {}, False, verify, None)["verify"]


def test_own_ca_variables_reach_subprocesses_not_in_process_requests(windows_store, make_proxy):
    import requests

    proxy = make_proxy()
    izi = IziProxy(proxy_url=proxy.url)
    izi.set_environment_variables()
    bundle = tls_env.system_ca_bundle()
    assert os.environ["REQUESTS_CA_BUNDLE"] == os.environ["CURL_CA_BUNDLE"] == bundle

    session = izi.create_session()
    # Magasin du système en direct (truststore), pas l'export d'un jour
    assert session_verify(session) is True
    assert session_verify(session, verify=True) is True
    # Choix explicites conservés
    assert session_verify(session, verify="/explicit.pem") == "/explicit.pem"
    assert session_verify(session, verify=False) is False
    session.verify = "/session.pem"
    assert session_verify(session) == "/session.pem"
    # Une session non configurée par IziProxy lit toujours l'environnement
    assert session_verify(requests.Session()) == bundle
    # trust_env=False : rien à corriger
    session.trust_env = False
    assert session_verify(session) == "/session.pem"
    izi.clear_environment_variables()


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_explicit_verify_path_still_applies_in_process(windows_store, make_proxy, tmp_path, kind):
    proxy = make_proxy()
    if kind == "file":
        ca = tmp_path / "ca.pem"
        ca.write_text("placeholder", encoding="ascii")
    else:
        ca = tmp_path / "certs"
        ca.mkdir()
    izi = IziProxy(proxy_url=proxy.url, verify=str(ca))
    izi.set_environment_variables()
    assert os.environ["REQUESTS_CA_BUNDLE"] == str(ca)
    # Choix explicite de l'utilisateur : requests le lit comme sans IziProxy
    assert izi.create_session().merge_environment_settings(
        "https://example.com/", {}, False, None, None)["verify"] == str(ca)
    izi.clear_environment_variables()


@pytest.mark.parametrize("name", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_user_ca_variable_still_applies_in_process(windows_store, make_proxy, monkeypatch, name):
    proxy = make_proxy()
    monkeypatch.setenv(name, "/user/ca.pem")
    izi = IziProxy(proxy_url=proxy.url)
    izi.set_environment_variables()
    # CURL_CA_BUNDLE seul : IziProxy définit REQUESTS_CA_BUNDLE, lu en
    # premier par requests ; la valeur de l'utilisateur reste celle utilisée
    assert session_verify(izi.create_session()) == "/user/ca.pem"
    izi.clear_environment_variables()


def test_value_changed_after_install_is_honoured(windows_store, make_proxy, monkeypatch):
    import requests

    proxy = make_proxy()
    iziproxy.install(proxy_url=proxy.url)
    session = requests.Session()  # configurée par patch_requests()
    assert session_verify(session) is True
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/later.pem")
    assert session_verify(session) == "/later.pem"
    monkeypatch.delenv("REQUESTS_CA_BUNDLE")
    iziproxy.uninstall()
    # Après uninstall, plus aucune correction : l'environnement fait foi
    monkeypatch.setenv("CURL_CA_BUNDLE", "/after.pem")
    assert session_verify(session) == "/after.pem"
