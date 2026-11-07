"""
Configuration pytest : isolation complète de la machine de test et
serveurs locaux réels (proxy, origine HTTP/HTTPS).
"""

import os
import sys

import keyring
import keyring.errors
import pytest
from keyring.backend import KeyringBackend

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.dirname(__file__))

from servers import OriginServer, ProxyServer  # noqa: E402

ISOLATED_VARS = [
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "IZIPROXY_USERNAME", "IZIPROXY_PASSWORD", "IZIPROXY_DOMAIN", "IZIPROXY_ENV",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
]


class MemoryKeyring(KeyringBackend):
    """Trousseau en mémoire : les tests ne touchent jamais au vrai trousseau."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.store:
            raise keyring.errors.PasswordDeleteError(username)
        del self.store[(service, username)]


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Neutralise l'environnement, le registre, le trousseau et les invites."""
    for name in ISOLATED_VARS:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    from iziproxy.proxy_detector import ProxyDetector
    from iziproxy.password_manager import PasswordManager

    monkeypatch.setattr(ProxyDetector, "_detect_system_settings", lambda self: {})

    def no_prompt(*args, **kwargs):
        raise AssertionError("unexpected interactive prompt")

    monkeypatch.setattr(PasswordManager, "get_credentials_interactive", no_prompt)

    backend = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)

    yield backend

    keyring.set_keyring(previous)
    from iziproxy import proxy_manager
    from iziproxy.logger import disable_debug_logging

    owner = proxy_manager._ACTIVE_PATCH["owner"]
    if owner is not None:
        owner.unpatch_requests()
    disable_debug_logging()


@pytest.fixture
def memory_keyring(isolated):
    return isolated


@pytest.fixture
def origin():
    server = OriginServer()
    yield server
    server.close()


@pytest.fixture
def tls_origin():
    server = OriginServer(tls=True)
    yield server
    server.close()


@pytest.fixture
def make_proxy(monkeypatch, tmp_path):
    """
    Fabrique de proxys locaux ; NTLM_USER_FILE est préparé pour NTLM.

    Avec tls=True, le certificat auto-signé du proxy est dans cert_path (à
    passer en verify=).
    """
    servers = []

    def factory(auth=None, **kwargs):
        server = ProxyServer(auth=auth, **kwargs)
        if auth in ("ntlm", "negotiate"):
            users = tmp_path / "ntlm_users.txt"
            users.write_text(f"{server.domain}:{server.username}:{server.password}\n")
            monkeypatch.setenv("NTLM_USER_FILE", str(users))
        servers.append(server)
        return server

    yield factory
    for server in servers:
        server.close()
