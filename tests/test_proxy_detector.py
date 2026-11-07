"""Tests de la détection des proxys système et des fichiers PAC."""

import textwrap

import pytest

from iziproxy import proxy_detector as module
from iziproxy.proxy_detector import ProxyDetector, parse_pac_result


def test_env_vars(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "proxy:8080")
    monkeypatch.setenv("NO_PROXY", "localhost,.corp")
    settings = ProxyDetector().detect_system_proxy()
    assert settings == {"http": "http://proxy:8080", "https": "http://proxy:8080", "no_proxy": "localhost,.corp"}


def test_lowercase_env_vars_win(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://upper:1")
    monkeypatch.setenv("https_proxy", "http://lower:2")
    assert ProxyDetector().detect_system_proxy()["https"] == "http://lower:2"


def test_all_proxy_is_ignored(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "http://all:3128")
    assert ProxyDetector({"use_system_proxy": True}).detect_system_proxy().get("http") is None


def test_env_overrides_replace_the_environment(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    detector = ProxyDetector()
    detector.env_overrides = {"HTTP_PROXY": "http://original:8080", "http_proxy": "http://original:8080"}
    assert detector.detect_system_proxy()["http"] == "http://original:8080"


def test_env_vars_can_be_disabled(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy:8080")
    assert ProxyDetector({"detect_env_vars": False}).detect_system_proxy() == {}
    assert ProxyDetector({"use_system_proxy": False}).detect_system_proxy() == {}


def test_system_settings_used_when_no_env(monkeypatch):
    monkeypatch.setattr(ProxyDetector, "_detect_system_settings",
                        lambda self: {"http": "http://sys:80", "https": "http://sys:80", "no_proxy": "<local>"})
    assert ProxyDetector().detect_system_proxy()["http"] == "http://sys:80"


def test_pac_url_kept_without_manual_proxy(monkeypatch):
    monkeypatch.setattr(ProxyDetector, "_detect_system_settings",
                        lambda self: {"pac_url": "http://pac/proxy.pac"})
    assert ProxyDetector().detect_system_proxy() == {"pac_url": "http://pac/proxy.pac"}
    assert ProxyDetector({"detect_pac": False}).detect_system_proxy() == {}


def test_failing_source_does_not_break_detection(monkeypatch):
    def boom(self):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(ProxyDetector, "_detect_system_settings", boom)
    assert ProxyDetector().detect_system_proxy() == {}


@pytest.mark.parametrize("value, expected", [
    ("proxy:8080", {"http": "http://proxy:8080", "https": "http://proxy:8080"}),
    ("http://proxy:8080", {"http": "http://proxy:8080", "https": "http://proxy:8080"}),
    ("http=web:80;https=secure:443;ftp=ftp:21",
     {"http": "http://web:80", "https": "http://secure:443"}),
    ("http=web:80", {"http": "http://web:80", "https": "http://web:80"}),
    ("socks=sock:1080", {"http": "socks4://sock:1080", "https": "socks4://sock:1080"}),
    ("", {}),
])
def test_parse_windows_proxy_server(value, expected):
    assert ProxyDetector.parse_windows_proxy_server(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("PROXY p:8080; DIRECT", "http://p:8080"),
    ("proxy p:8080", "http://p:8080"),
    ("DIRECT", None),
    ("DIRECT; PROXY p:8080", None),
    ("HTTPS secure:443", "https://secure:443"),
    ("SOCKS5 s:1080", "socks5h://s:1080"),
    ("SOCKS s:1080", "socks4://s:1080"),
    ("", None),
    (None, None),
])
def test_parse_pac_result(value, expected):
    assert parse_pac_result(value) == expected


def test_macos_scutil(monkeypatch):
    output = textwrap.dedent("""
        <dictionary> {
          ExceptionsList : <array> {
            0 : *.local
            1 : 169.254/16
          }
          HTTPEnable : 1
          HTTPPort : 8080
          HTTPProxy : proxy.corp
          HTTPSEnable : 1
          HTTPSPort : 8443
          HTTPSProxy : sproxy.corp
          ProxyAutoConfigEnable : 0
        }
    """)
    monkeypatch.setattr(module, "_run", lambda command: output)
    assert ProxyDetector()._detect_macos_proxy() == {
        "http": "http://proxy.corp:8080",
        "https": "http://sproxy.corp:8443",
        "no_proxy": "*.local,169.254/16",
    }


def test_gnome_manual(monkeypatch):
    values = {
        ("org.gnome.system.proxy", "mode"): "'manual'",
        ("org.gnome.system.proxy.http", "host"): "'proxy.corp'",
        ("org.gnome.system.proxy.http", "port"): "3128",
        ("org.gnome.system.proxy.https", "host"): "''",
        ("org.gnome.system.proxy.https", "port"): "0",
        ("org.gnome.system.proxy", "ignore-hosts"): "['localhost', '*.corp']",
    }
    monkeypatch.setattr(module, "_run", lambda cmd: values.get((cmd[2], cmd[3])))
    assert ProxyDetector._detect_gnome_proxy() == {
        "http": "http://proxy.corp:3128",
        "https": "http://proxy.corp:3128",
        "no_proxy": "localhost,*.corp",
    }


def test_kde_manual(monkeypatch):
    values = {"ProxyType": "1", "httpProxy": "http://proxy.corp 8080", "httpsProxy": "",
              "NoProxyFor": "localhost,.corp"}
    monkeypatch.setattr(module, "_run", lambda cmd: values.get(cmd[-1]) if cmd[0] == "kreadconfig5" else None)
    assert ProxyDetector._detect_kde_proxy() == {"http": "http://proxy.corp:8080", "no_proxy": "localhost,.corp"}


def test_pac_file_from_path(tmp_path):
    pytest.importorskip("pypac")
    pac = tmp_path / "proxy.pac"
    pac.write_text(
        'function FindProxyForURL(url, host) {'
        ' if (shExpMatch(host, "*.intra")) return "DIRECT";'
        ' return "PROXY p1:8080; PROXY p2:8080"; }'
    )
    detector = ProxyDetector()
    assert detector.find_proxy_for_url("https://www.example.org/", str(pac)) == "http://p1:8080"
    assert detector.find_proxy_for_url("https://app.intra/", str(pac)) is None
    assert pac.as_uri() not in detector._pac_cache
    assert detector.find_proxy_for_url("https://x.org/", pac.as_uri()) == "http://p1:8080"


def test_unreachable_pac_means_direct():
    pytest.importorskip("pypac")
    assert ProxyDetector().find_proxy_for_url("https://x.org/", "http://127.0.0.1:1/none.pac") is None
