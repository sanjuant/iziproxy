"""Tests des fonctions utilitaires (exclusions, URLs, timeouts)."""

import pytest
import requests
from urllib3.util import Timeout

from iziproxy.proxy_utils import (
    extract_credentials,
    has_credentials,
    inject_credentials,
    no_proxy_for_env,
    normalize_proxy_url,
    parse_no_proxy,
    parse_proxy_authenticate,
    proxy_host_port,
    should_bypass,
    split_timeout,
    strip_credentials,
)


@pytest.mark.parametrize("value, expected", [
    (None, []),
    ("", []),
    ("a.com, b.com", ["a.com", "b.com"]),
    ("<local>;*.corp.com;10.*", ["<local>", "*.corp.com", "10.*"]),
    ("a.com a.com\tB.COM", ["a.com", "b.com"]),
    (["x", " y "], ["x", "y"]),
])
def test_parse_no_proxy(value, expected):
    assert parse_no_proxy(value) == expected


@pytest.mark.parametrize("url, rules, expected", [
    ("http://localhost:8000/", "", True),
    ("http://127.0.0.5/", "", True),
    ("http://[::1]:80/", "", True),
    ("https://example.com/", "", False),
    ("https://example.com/", "*", True),
    ("http://intranet/", "<local>", True),
    ("http://intranet.corp/", "<local>", False),
    ("https://wiki.corp.com/", "*.corp.com", True),
    ("https://corp.com/", "*.corp.com", True),
    ("https://notcorp.com/", "*.corp.com", False),
    ("https://wiki.corp.com/", ".corp.com", True),
    ("https://wiki.corp.com/", "corp.com", True),
    ("https://evilcorp.com/", "corp.com", False),
    ("http://10.1.2.3/", "10.*", True),
    ("http://10.1.2.3/", "10.0.0.0/8", True),
    ("http://11.1.2.3/", "10.0.0.0/8", False),
    ("http://srv.corp.com:8080/", "srv.corp.com:8080", True),
    ("http://srv.corp.com:9090/", "srv.corp.com:8080", False),
    ("http://WIKI.Corp.Com/", "*.corp.com", True),
    ("http://intra.corp/", "http://intra.corp", True),
])
def test_should_bypass(url, rules, expected):
    assert should_bypass(url, rules) is expected


def test_loopback_bypass_can_be_disabled():
    assert should_bypass("http://localhost/", "", include_loopback=False) is False


def test_no_proxy_for_env_is_curl_compatible():
    value = no_proxy_for_env("<local>;*.corp.com;.lan;10.0.0.0/8")
    assert value.split(",") == [".corp.com", ".lan", "10.0.0.0/8", "localhost", "127.0.0.1", "::1"]


def test_normalize_proxy_url():
    assert normalize_proxy_url("proxy:8080") == "http://proxy:8080"
    assert normalize_proxy_url(" https://proxy ") == "https://proxy"
    assert normalize_proxy_url("") is None
    assert normalize_proxy_url(None) is None


def test_credentials_roundtrip_with_special_characters():
    url = inject_credentials("http://proxy:8080", "DOM\\user", "p@ss:w/%41")
    assert url == "http://DOM%5Cuser:p%40ss%3Aw%2F%2541@proxy:8080"
    assert has_credentials(url)
    assert extract_credentials(url) == ("DOM\\user", "p@ss:w/%41")
    assert strip_credentials(url) == "http://proxy:8080"
    # requests décode de la même façon
    assert requests.utils.get_auth_from_url(url) == ("DOM\\user", "p@ss:w/%41")


def test_inject_replaces_existing_credentials():
    url = inject_credentials("http://old:pw@proxy:8080", "new", "pw2")
    assert url == "http://new:pw2@proxy:8080"


def test_has_credentials_ignores_at_in_path():
    assert not has_credentials("http://proxy:8080/a@b")


def test_proxy_host_port_defaults():
    assert proxy_host_port("http://p") == ("p", 80)
    assert proxy_host_port("https://p") == ("p", 443)
    assert proxy_host_port("p:3128") == ("p", 3128)
    assert proxy_host_port(None) == (None, None)


def test_split_timeout():
    assert split_timeout(None) == (None, None)
    assert split_timeout(5) == (5, 5)
    assert split_timeout((1, 2)) == (1, 2)
    assert split_timeout(Timeout(connect=3, read=4)) == (3, 4)


def test_parse_proxy_authenticate():
    headers = [
        ("Proxy-Authenticate", "NTLM"),
        ("Proxy-Authenticate", 'Basic realm="corp"'),
        ("proxy-authenticate", "Negotiate abc=="),
        ("Content-Length", "0"),
    ]
    assert parse_proxy_authenticate(headers) == {"ntlm": "", "basic": 'realm="corp"', "negotiate": "abc=="}
