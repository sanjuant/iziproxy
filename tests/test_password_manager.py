"""Tests de la saisie interactive (sans afficher de fenêtre)."""

import pytest

from iziproxy.password_manager import CANCELLED, PasswordManager


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.setattr(PasswordManager, "_detect_gui_environment", lambda self: False)
    return PasswordManager()


def test_cli_prompt_with_defaults(manager, monkeypatch):
    answers = iter(["", "CORP2"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda prompt: "pw")
    assert manager._get_credentials_cli("CORP", "jdoe", "ntlm") == ("jdoe", "pw", "CORP2")


def test_cli_prompt_basic_has_no_domain(manager, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "bob")
    monkeypatch.setattr("getpass.getpass", lambda prompt: "pw")
    assert manager._get_credentials_cli(None, None, "basic") == ("bob", "pw", None)


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_cli_prompt_cancelled(manager, monkeypatch, error):
    def raise_error(prompt):
        raise error

    monkeypatch.setattr("builtins.input", raise_error)
    assert manager._get_credentials_cli(None, None, "basic") == (None, None, None)


def test_cli_prompt_requires_password(manager, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "bob")
    monkeypatch.setattr("getpass.getpass", lambda prompt: "")
    assert manager._get_credentials_cli(None, None, "basic") == (None, None, None)


def test_gui_cancel_does_not_open_another_prompt(manager, monkeypatch):
    calls = []
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(PasswordManager, "_get_credentials_windows_complete",
                        lambda self, *a: calls.append("windows") or CANCELLED)
    monkeypatch.setattr(PasswordManager, "_get_credentials_tkinter_dialog",
                        lambda self, *a: calls.append("tk") or ("x", "y", None))
    monkeypatch.setattr(PasswordManager, "_get_credentials_cli",
                        lambda self, *a: calls.append("cli") or ("x", "y", None))
    assert manager._get_credentials_gui("t", None, None, "basic") == (None, None, None)
    assert calls == ["windows"]


def test_gui_falls_back_when_unavailable(manager, monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(PasswordManager, "_get_credentials_tkinter_dialog", lambda self, *a: None)
    monkeypatch.setattr(PasswordManager, "_get_credentials_cli", lambda self, *a: ("cli", "pw", None))
    assert manager._get_credentials_gui("t", None, None, "basic") == ("cli", "pw", None)


@pytest.mark.parametrize("value, auth, expected", [
    ("CORP\\jdoe", "ntlm", ("jdoe", "CORP")),
    ("jdoe@corp.example", "ntlm", ("jdoe", "corp.example")),
    ("CORP\\jdoe", "basic", ("CORP\\jdoe", None)),
])
def test_split_domain(value, auth, expected):
    assert PasswordManager._split_domain(value, auth) == expected
