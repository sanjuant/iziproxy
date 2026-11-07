"""Tests de la configuration, des identifiants et de la détection d'environnement."""

import textwrap

import pytest

from iziproxy.config_manager import ConfigManager
from iziproxy.env_detector import EnvironmentDetector, normalize_environment
from iziproxy.secure_config import SecurePassword


def write(path, text):
    path.write_text(textwrap.dedent(text), encoding="utf-8")


# ---------------------------------------------------------------------- #
# Configuration
# ---------------------------------------------------------------------- #
def test_defaults_without_file():
    manager = ConfigManager()
    assert manager.loaded_from is None
    assert manager.get_environment_config("dev") == {"proxy_url": None, "requires_auth": None}
    assert manager.get_environment_config("unknown") == {}


def test_yaml_is_merged_with_defaults(tmp_path):
    write(tmp_path / "work" / "iziproxy.yml", """
        environments:
          prod:
            proxy_url: http://prod:8080
            auth_type: ntlm
        system_proxy:
          detect_pac: false
    """)
    config = ConfigManager().get_config()
    assert config["environments"]["prod"] == {"proxy_url": "http://prod:8080", "requires_auth": None,
                                              "auth_type": "ntlm"}
    assert config["environments"]["dev"]["proxy_url"] is None
    assert config["system_proxy"] == {"use_system_proxy": True, "detect_env_vars": True, "detect_pac": False}


def test_explicit_path_and_home_lookup(tmp_path):
    custom = tmp_path / "custom.yaml"
    write(custom, "environments: {dev: {proxy_url: 'http://custom:1'}}")
    assert ConfigManager(str(custom)).get_environment_config("dev")["proxy_url"] == "http://custom:1"

    write(tmp_path / "home" / ".iziproxy.yml", "environments: {dev: {proxy_url: 'http://home:1'}}")
    assert ConfigManager().get_environment_config("dev")["proxy_url"] == "http://home:1"


@pytest.mark.parametrize("content", ["", "just a string", "environments: [1, 2", "- a\n- b"])
def test_invalid_yaml_falls_back_to_defaults(tmp_path, content):
    (tmp_path / "work" / "iziproxy.yml").write_text(content)
    assert ConfigManager().get_environment_config("dev")["proxy_url"] is None


def test_defaults_are_not_shared_between_instances():
    first = ConfigManager()
    first.get_config()["environments"]["dev"]["proxy_url"] = "mutated"
    assert ConfigManager().get_environment_config("dev")["proxy_url"] is None


# ---------------------------------------------------------------------- #
# Identifiants
# ---------------------------------------------------------------------- #
def test_no_credentials_when_auth_not_required():
    assert ConfigManager().get_credentials("dev") == (None, None, None)


def test_credentials_from_env_vars(monkeypatch):
    monkeypatch.setenv("IZIPROXY_USERNAME", "envuser")
    monkeypatch.setenv("IZIPROXY_PASSWORD", "envpass")
    monkeypatch.setenv("IZIPROXY_DOMAIN", "CORP")
    user, password, domain = ConfigManager().get_credentials("dev", auth_required=True)
    assert (user, password.get_password(), domain) == ("envuser", "envpass", "CORP")


@pytest.mark.parametrize("name", ["IZI_USERNAME", "PROXY_USERNAME", "izi_username"])
def test_other_credential_variables_are_ignored(monkeypatch, name):
    monkeypatch.setattr("getpass.getuser", lambda: "sessionuser")
    monkeypatch.setenv(name, "envuser")
    assert ConfigManager().get_credentials("dev", auth_required=True, prompt=False)[0] == "sessionuser"


def test_credentials_from_dotenv(tmp_path):
    write(tmp_path / "work" / ".env", """
        # commentaire
        export IZIPROXY_USERNAME=dotuser
        IZIPROXY_PASSWORD="p=ss#word"
    """)
    user, password, _ = ConfigManager().get_credentials("dev", auth_required=True, prompt=False)
    assert (user, password.get_password()) == ("dotuser", "p=ss#word")


def test_env_vars_override_dotenv(tmp_path, monkeypatch):
    write(tmp_path / "work" / ".env", "IZIPROXY_USERNAME=dotuser\nIZIPROXY_PASSWORD=dotpass\n")
    monkeypatch.setenv("IZIPROXY_PASSWORD", "envpass")
    user, password, _ = ConfigManager().get_credentials("dev", auth_required=True)
    assert (user, password.get_password()) == ("dotuser", "envpass")


def test_credentials_from_keyring(memory_keyring):
    memory_keyring.set_password("iziproxy_dev-ntlm", "__username__", "kuser")
    memory_keyring.set_password("iziproxy_dev-ntlm", "kuser", "kpass")
    memory_keyring.set_password("iziproxy_dev-ntlm", "__domain__", "KDOM")
    user, password, domain = ConfigManager().get_credentials("dev", auth_required=True, auth_type="ntlm")
    assert (user, password.get_password(), domain) == ("kuser", "kpass", "KDOM")


def test_keyring_password_for_session_user(memory_keyring, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "sessionuser")
    memory_keyring.set_password("iziproxy_dev-basic", "sessionuser", "spass")
    user, password, _ = ConfigManager().get_credentials("dev", auth_required=True)
    assert (user, password.get_password()) == ("sessionuser", "spass")


def test_prompt_disabled_returns_partial_credentials(monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "sessionuser")
    assert ConfigManager().get_credentials("dev", auth_required=True, prompt=False) == ("sessionuser", None, None)


def test_requires_auth_from_config(tmp_path, monkeypatch):
    write(tmp_path / "work" / "iziproxy.yml", "environments: {dev: {requires_auth: true}}")
    monkeypatch.setenv("IZIPROXY_USERNAME", "u")
    monkeypatch.setenv("IZIPROXY_PASSWORD", "p")
    assert ConfigManager().get_credentials("dev")[0] == "u"


def test_interactive_credentials_are_stored_and_deleted(monkeypatch, memory_keyring):
    from iziproxy.password_manager import PasswordManager

    monkeypatch.setattr(PasswordManager, "get_credentials_interactive",
                        lambda self, **kw: ("iuser", "ipass", "IDOM"))
    manager = ConfigManager()
    user, password, domain = manager.get_credentials("prod", auth_required=True, auth_type="ntlm")
    assert (user, password.get_password(), domain) == ("iuser", "ipass", "IDOM")
    assert memory_keyring.get_password("iziproxy_prod-ntlm", "iuser") == "ipass"

    manager.delete_credentials("prod", auth_type="ntlm")
    assert memory_keyring.store == {}


def test_cancelled_prompt_is_not_stored(monkeypatch, memory_keyring):
    from iziproxy.password_manager import PasswordManager

    monkeypatch.setattr(PasswordManager, "get_credentials_interactive", lambda self, **kw: (None, None, None))
    monkeypatch.setattr("getpass.getuser", lambda: "me")
    assert ConfigManager().get_credentials("dev", auth_required=True) == ("me", None, None)
    assert memory_keyring.store == {}


def test_keyring_failure_is_tolerated(monkeypatch):
    import keyring

    def broken(*args):
        raise RuntimeError("no backend")

    monkeypatch.setattr(keyring, "get_password", broken)
    monkeypatch.setattr("getpass.getuser", lambda: "me")
    assert ConfigManager().get_credentials("dev", auth_required=True, prompt=False) == ("me", None, None)


def test_windows_session_info(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr("getpass.getuser", lambda: "jdoe")
    monkeypatch.setenv("USERDOMAIN", "CORP")
    monkeypatch.setenv("COMPUTERNAME", "PC-42")
    assert ConfigManager()._get_current_session_info() == ("jdoe", "CORP")

    monkeypatch.setenv("USERDOMAIN", "PC-42")
    assert ConfigManager()._get_current_session_info() == ("jdoe", None)


def test_unix_session_info_keeps_getpass_user(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("getpass.getuser", lambda: "jdoe")
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setattr("socket.getfqdn", lambda: "host.corp.example")
    assert ConfigManager()._get_current_session_info() == ("jdoe", "corp.example")


# ---------------------------------------------------------------------- #
# Environnement
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("value, expected", [
    ("prod", "prod"), ("Production", "prod"), ("staging", "dev"), ("UAT", "dev"),
    ("local", "local"), ("", None), ("/home/devops/.shrc", None), ("whatever", None),
])
def test_normalize_environment(value, expected):
    assert normalize_environment(value) == expected


def test_env_var_detection(monkeypatch):
    monkeypatch.setenv("IZIPROXY_ENV", "production")
    assert EnvironmentDetector().detect_environment() == "prod"


@pytest.mark.parametrize("name", ["APP_ENV", "ENVIRONMENT", "STAGE", "PROXY_ENV"])
def test_only_iziproxy_env_is_read(monkeypatch, name):
    monkeypatch.setenv(name, "production")
    detector = EnvironmentDetector({"environment_detection": {"method": "env_var"}})
    assert detector.detect_environment() == "local"


def test_unknown_iziproxy_env_value_is_reported(monkeypatch, caplog):
    monkeypatch.setenv("IZIPROXY_ENV", "moon")
    detector = EnvironmentDetector({"environment_detection": {"method": "env_var"}})
    assert detector.detect_environment() == "local"
    assert "Unknown IZIPROXY_ENV value" in caplog.text


def test_sh_env_variable_is_ignored(monkeypatch):
    monkeypatch.setenv("ENV", "/home/devops/.shrc")
    detector = EnvironmentDetector({"environment_detection": {"method": "env_var"}})
    assert detector.detect_environment() == "local"


@pytest.mark.parametrize("hostname, expected", [
    ("desktop-ab12cd", "local"),
    ("srv-staging-01", "dev"),
    ("prod-web-01", "prod"),
    ("random-host", "local"),
])
def test_hostname_detection(hostname, expected):
    detector = EnvironmentDetector({"environment_detection": {"method": "hostname"}})
    detector.system_info["hostname"] = hostname
    assert detector.detect_environment() == expected


def test_ip_detection():
    config = {"environment_detection": {"method": "ip", "ip_ranges": {
        "dev": ["10.0.0.0/8"], "prod": ["192.168.1.10-192.168.1.20"]}}}
    detector = EnvironmentDetector(config)
    detector.system_info["ip"] = "192.168.1.15"
    assert detector.detect_environment() == "prod"
    detector.system_info["ip"] = "10.2.3.4"
    assert detector.detect_environment(force_refresh=True) == "dev"


def test_ask_without_terminal_defaults_to_local(monkeypatch):
    monkeypatch.setattr("sys.stdin", None)
    assert EnvironmentDetector({"environment_detection": {"method": "ask"}}).detect_environment() == "local"


# ---------------------------------------------------------------------- #
# SecurePassword / SecureProxyConfig
# ---------------------------------------------------------------------- #
def test_secure_password():
    secret = SecurePassword("hunter2")
    assert str(secret) == repr(secret).split("'")[1] == "***********"
    assert secret.get_password() == "hunter2"
    assert SecurePassword(secret).get_password() == "hunter2"
    assert secret == SecurePassword("hunter2")


def test_secure_proxy_config_masks_and_restores():
    from iziproxy import SecureProxyConfig

    config = SecureProxyConfig({
        "http": "http://user:p%40ss@proxy:8080",
        "https": "socks5h://user:secret@proxy:1080",
        "no_proxy": "localhost",
    })
    assert "p%40ss" not in str(config) and "secret" not in repr(config)
    assert config["https"] == "socks5h://user:***********@proxy:1080"
    assert config.get_real_config() == {
        "http": "http://user:p%40ss@proxy:8080",
        "https": "socks5h://user:secret@proxy:1080",
        "no_proxy": "localhost",
    }
    user, password = config.get_credentials("http")
    assert (user, password.get_password()) == ("user", "p@ss")
