"""
Tests de la commande ``iziproxy`` (serve, setup, setup --undo).

Aucune configuration réelle n'est touchée : HOME, APPDATA, XDG_CONFIG_HOME
et la configuration globale de git pointent vers des répertoires temporaires.
"""

import os
import shutil
import stat
import subprocess
import sys

import pytest

from iziproxy import cli, tool_setup
from iziproxy.tool_setup import SetupError, update_curlrc, update_ini

WINDOWS = sys.platform == "win32"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture(autouse=True)
def user_dirs(monkeypatch, tmp_path):
    """Répertoires de l'utilisateur et configuration git temporaires."""
    appdata = tmp_path / "appdata"
    xdg = tmp_path / "xdg"
    appdata.mkdir()
    xdg.mkdir()
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    gitconfig = tmp_path / "gitconfig"
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    # Export du magasin du système : rapide et déterministe dans les tests
    monkeypatch.setattr(tool_setup, "export_ca_bundle", _fake_export)
    return {"appdata": appdata, "xdg": xdg, "gitconfig": gitconfig}


def _fake_export(path):
    with open(path, "w", encoding="ascii") as handle:
        handle.write("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    return 1


def _git_get(key):
    result = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def _read(path):
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


# ---------------------------------------------------------------------- #
# Jeton
# ---------------------------------------------------------------------- #
def test_token_generated_once_and_private():
    token = tool_setup.load_token()
    assert tool_setup.load_token() == token
    assert len(token) >= 16
    path = tool_setup.token_path()
    assert os.path.dirname(path) == tool_setup.config_dir()
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_token_permissions_tightened():
    tool_setup.load_token()
    os.chmod(tool_setup.token_path(), 0o644)
    tool_setup.load_token()
    assert stat.S_IMODE(os.stat(tool_setup.token_path()).st_mode) == 0o600


def test_invalid_token_file_rejected():
    _write(tool_setup.token_path(), "short\n")
    with pytest.raises(SetupError, match="Invalid local proxy token"):
        tool_setup.load_token()


def test_config_dir_per_platform(user_dirs):
    assert tool_setup.config_dir(windows=True) == os.path.join(str(user_dirs["appdata"]), "iziproxy")
    assert tool_setup.curlrc_path(windows=True) == os.path.join(str(user_dirs["appdata"]), "_curlrc")
    assert tool_setup.pip_config_path(windows=True) == os.path.join(str(user_dirs["appdata"]), "pip", "pip.ini")
    assert tool_setup.curlrc_path(windows=False) == os.path.join(os.path.expanduser("~"), ".curlrc")
    assert tool_setup.pip_config_path(windows=False) == os.path.join(str(user_dirs["xdg"]), "pip", "pip.conf")


# ---------------------------------------------------------------------- #
# Édition des fichiers
# ---------------------------------------------------------------------- #
def test_update_curlrc_replaces_proxy_and_keeps_the_rest():
    original = '# mine\nproxy = "http://old:3128"\n-x http://other:8080\nretry = 3\nssl-revoke-best-effort\n'
    updated = update_curlrc(original, "http://iziproxy:tok@127.0.0.1:3128", True)
    assert "old" not in updated and "other" not in updated
    assert "# mine\n" in updated and "retry = 3\n" in updated
    assert updated.count("ssl-revoke-best-effort") == 1
    assert 'proxy = "http://iziproxy:tok@127.0.0.1:3128"\n' in updated
    # Idempotent : un second setup ne duplique pas le bloc
    assert update_curlrc(updated, "http://iziproxy:tok@127.0.0.1:3128", True) == updated


def test_update_curlrc_without_revoke_keeps_existing_option():
    updated = update_curlrc("ssl-revoke-best-effort", "http://p", False)
    assert updated.startswith("ssl-revoke-best-effort\n")
    assert updated.endswith('proxy = "http://p"\n')


def test_update_ini_new_and_existing_sections():
    assert update_ini(None, "global", {"proxy": "P", "cert": "C"}) == "[global]\nproxy = P\ncert = C\n"
    original = "[global]\n# keep\nproxy = old\ntimeout = 60\n\n[install]\nproxy = untouched\n"
    updated = update_ini(original, "global", {"proxy": "P", "cert": "C"})
    assert updated == "[global]\nproxy = P\ncert = C\n# keep\ntimeout = 60\n\n[install]\nproxy = untouched\n"
    other = update_ini("[install]\nuser = true", "global", {"proxy": "P"})
    assert other == "[install]\nuser = true\n\n[global]\nproxy = P\n"


def test_update_ini_keeps_crlf():
    updated = update_ini("[global]\r\ntimeout = 60\r\n", "global", {"proxy": "P"})
    assert updated == "[global]\r\nproxy = P\r\ntimeout = 60\r\n"


def test_plan_windows_specific_settings():
    changes, _ = tool_setup.plan(tools=("curl",), token="t" * 20, windows=True)
    assert "ssl-revoke-best-effort" in changes[0].value
    changes, _ = tool_setup.plan(tools=("curl",), token="t" * 20, windows=False)
    assert "ssl-revoke-best-effort" not in changes[0].value


@needs_git
def test_plan_git_keys_per_platform():
    keys = [c.target for c in tool_setup.plan(tools=("git",), token="t" * 20, windows=True)[0]]
    assert keys == ["http.proxy", "https.proxy", "http.schannelCheckRevoke"]
    keys = [c.target for c in tool_setup.plan(tools=("git",), token="t" * 20, windows=False)[0]]
    assert keys == ["http.proxy", "https.proxy"]


def test_plan_rejects_unknown_tool():
    with pytest.raises(ValueError, match="npm"):
        tool_setup.plan(tools=("npm",), token="t" * 20)


def test_git_missing_is_skipped(monkeypatch):
    monkeypatch.setattr(tool_setup, "_git_available", lambda: False)
    changes, skipped = tool_setup.plan(token="t" * 20)
    assert {c.tool for c in changes} == {"curl", "pip"}
    assert skipped == ["git: not found in PATH"]


# ---------------------------------------------------------------------- #
# Commande setup
# ---------------------------------------------------------------------- #
@needs_git
def test_setup_writes_everything_and_undo_restores(capsys):
    curlrc = tool_setup.curlrc_path()
    pipconf = tool_setup.pip_config_path()
    _write(curlrc, "retry = 3\nproxy = http://old:3128\n")
    subprocess.run(["git", "config", "--global", "http.proxy", "http://previous:8080"], check=True)

    assert cli.main(["setup", "--yes"]) == 0
    out = capsys.readouterr().out
    token = tool_setup.load_token()
    url = f"http://iziproxy:{token}@127.0.0.1:3128"
    assert token not in out
    assert "***" in out

    assert _git_get("http.proxy") == url
    assert _git_get("https.proxy") == url
    assert _git_get("http.schannelCheckRevoke") == ("best-effort" if WINDOWS else None)
    assert f'proxy = "{url}"' in _read(curlrc)
    assert "retry = 3" in _read(curlrc)
    assert ("ssl-revoke-best-effort" in _read(curlrc)) == WINDOWS
    ca_path = os.path.join(tool_setup.config_dir(), "ca-bundle.pem")
    assert _read(pipconf) == f"[global]\nproxy = {url}\ncert = {ca_path}\n"
    assert "BEGIN CERTIFICATE" in _read(ca_path)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(tool_setup.backup_path()).st_mode) == 0o600

    assert cli.main(["setup", "--undo"]) == 0
    assert _git_get("http.proxy") == "http://previous:8080"
    assert _git_get("https.proxy") is None
    assert _git_get("http.schannelCheckRevoke") is None
    assert _read(curlrc) == "retry = 3\nproxy = http://old:3128\n"
    assert not os.path.exists(pipconf)
    assert not os.path.exists(ca_path)
    assert not os.path.exists(tool_setup.backup_path())

    assert cli.main(["setup", "--undo"]) == 0
    assert "Nothing to undo" in capsys.readouterr().out


def test_second_setup_keeps_first_backup():
    curlrc = tool_setup.curlrc_path()
    _write(curlrc, "verbose\n")
    assert cli.main(["setup", "--yes", "--only", "curl"]) == 0
    assert cli.main(["setup", "--yes", "--only", "curl,pip", "--port", "8888"]) == 0
    assert "127.0.0.1:8888" in _read(curlrc)
    assert "3128" not in _read(curlrc)
    assert cli.main(["setup", "--undo"]) == 0
    assert _read(curlrc) == "verbose\n"
    assert not os.path.exists(tool_setup.pip_config_path())


def test_undo_only_one_tool():
    assert cli.main(["setup", "--yes", "--only", "curl,pip"]) == 0
    assert cli.main(["setup", "--undo", "--only", "pip"]) == 0
    assert not os.path.exists(tool_setup.pip_config_path())
    assert os.path.exists(tool_setup.curlrc_path())
    assert tool_setup.has_backup()
    assert cli.main(["setup", "--undo"]) == 0
    assert not os.path.exists(tool_setup.curlrc_path())
    assert not tool_setup.has_backup()


def test_undo_keeps_copy_of_file_edited_after_setup(capsys):
    curlrc = tool_setup.curlrc_path()
    assert cli.main(["setup", "--yes", "--only", "curl"]) == 0
    _write(curlrc, _read(curlrc) + "insecure\n")
    assert cli.main(["setup", "--undo"]) == 0
    assert not os.path.exists(curlrc)
    assert "insecure" in _read(curlrc + tool_setup.UNDO_COPY_SUFFIX)
    assert "edited since setup" in capsys.readouterr().out


@pytest.mark.parametrize("answer", ["n", "", EOFError])
def test_setup_aborts_without_confirmation(monkeypatch, capsys, answer):
    def fake_input(prompt):
        if answer is EOFError:
            raise EOFError
        return answer

    monkeypatch.setattr("builtins.input", fake_input)
    assert cli.main(["setup", "--only", "curl,pip"]) == 1
    assert "Aborted" in capsys.readouterr().out
    assert not os.path.exists(tool_setup.curlrc_path())
    assert not os.path.exists(tool_setup.pip_config_path())
    assert not tool_setup.has_backup()


def test_setup_confirmed(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert cli.main(["setup", "--only", "curl"]) == 0
    assert os.path.exists(tool_setup.curlrc_path())
    assert not os.path.exists(tool_setup.pip_config_path())


def test_setup_never_writes_a_password(monkeypatch):
    # Même avec des identifiants dans l'environnement, seul le jeton est écrit
    monkeypatch.setenv("IZIPROXY_PASSWORD", "S3cret-Password")
    assert cli.main(["setup", "--yes", "--only", "curl,pip"]) == 0
    for path in (tool_setup.curlrc_path(), tool_setup.pip_config_path(), tool_setup.backup_path()):
        assert "S3cret-Password" not in _read(path)


@pytest.mark.parametrize("argv", [["setup", "--only", "npm"], ["setup", "--only", ""], ["serve", "--port", "0"],
                                  ["serve", "--port", "x"]])
def test_invalid_arguments(argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_setup_reports_setup_error(monkeypatch, capsys):
    _write(tool_setup.token_path(), "bad")
    assert cli.main(["setup", "--yes"]) == 1
    assert "Invalid local proxy token" in capsys.readouterr().err


# ---------------------------------------------------------------------- #
# Commande serve
# ---------------------------------------------------------------------- #
class _FakeLocal:
    def __init__(self, port, token):
        self.port = port
        self.token = token
        self.address = f"http://127.0.0.1:{port}"
        self.served = False

    def serve_forever(self):
        self.served = True


def test_serve_uses_persisted_token_and_hides_it(monkeypatch, capsys):
    from iziproxy.proxy_manager import IziProxy

    started = []

    def fake_start(self, port, token):
        started.append(_FakeLocal(port, token))
        return started[-1]

    monkeypatch.setattr(IziProxy, "start_local_proxy", fake_start)
    assert cli.main(["serve", "--port", "8888"]) == 0
    token = tool_setup.load_token()
    assert started[0].token == token and started[0].port == 8888 and started[0].served
    out = capsys.readouterr().out
    assert token not in out
    assert "http://127.0.0.1:8888" in out
    assert "iziproxy setup --port 8888" in out


def test_serve_port_taken(monkeypatch, capsys):
    from iziproxy.proxy_manager import IziProxy

    def fake_start(self, port, token):
        raise OSError(98, "Cannot listen on 127.0.0.1:3128")

    monkeypatch.setattr(IziProxy, "start_local_proxy", fake_start)
    assert cli.main(["serve"]) == 1
    assert "Cannot listen" in capsys.readouterr().err


def test_serve_real_proxy_accepts_the_persisted_token():
    from iziproxy.proxy_manager import IziProxy

    token = tool_setup.load_token()
    with IziProxy(proxy_url="http://127.0.0.1:9").start_local_proxy(port=0, token=token) as local:
        assert local.token == token


# ---------------------------------------------------------------------- #
# Export PEM
# ---------------------------------------------------------------------- #
def test_export_ca_bundle_real(tmp_path):
    from iziproxy.ca_bundle import export_ca_bundle

    path = tmp_path / "out" / "ca.pem"
    count = export_ca_bundle(str(path))
    text = path.read_text(encoding="ascii")
    assert count > 10
    assert text.count("BEGIN CERTIFICATE") == count


def test_split_pems():
    from iziproxy.ca_bundle import split_pems

    text = "junk\n-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\nx\n" \
           "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n"
    assert split_pems(text) == ["-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
                                "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n"]
