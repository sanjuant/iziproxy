"""
Suites de la revue complète du 2026-11-07 : délai maximal des fichiers PAC,
préférence pour Negotiate et réutilisation des connexions NTLM.
"""

import logging
import sys
import textwrap
import threading
import time
import urllib.request

import pytest

from iziproxy import IziProxy, pac_evaluator, proxy_detector
from iziproxy.proxy_detector import ProxyDetector


# ---------------------------------------------------------------------- #
# Délai maximal des PAC
# ---------------------------------------------------------------------- #
def write_pac(tmp_path, body):
    pac = tmp_path / "proxy.pac"
    pac.write_text(textwrap.dedent(body))
    return str(pac)


LOOPING_FOR_ONE_HOST = """
    function FindProxyForURL(url, host) {
        if (host == "loop.test") { while (true) {} }
        return "PROXY p1:8080";
    }
"""


def test_looping_pac_is_stopped_without_freezing_the_process(tmp_path, monkeypatch, caplog):
    pytest.importorskip("pypac")
    monkeypatch.setattr(pac_evaluator, "PAC_EVAL_TIMEOUT", 1.0)
    pac = write_pac(tmp_path, LOOPING_FOR_ONE_HOST)
    detector = ProxyDetector()
    assert detector.evaluate_pac("http://ok.test/", pac) == ("http://p1:8080", True)
    worker = detector._pac_cache[pac][0]

    # dukpy garde le GIL : évalué dans ce processus, le PAC bloquerait aussi ce thread
    ticks = []
    stop = threading.Event()

    def tick():
        while not stop.is_set():
            ticks.append(time.monotonic())
            time.sleep(0.05)

    ticker = threading.Thread(target=tick, daemon=True)
    ticker.start()
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="iziproxy"):
        assert detector.evaluate_pac("http://loop.test/", pac) == (None, False)
    elapsed = time.monotonic() - started
    stop.set()
    ticker.join()

    assert 0.9 <= elapsed < 5
    assert len(ticks) >= 10, "the looping PAC blocked the other threads"
    assert "endless loop" in caplog.text
    assert not worker.alive
    assert worker._process.poll() is not None

    # PAC écarté pendant PAC_RETRY_DELAY : connexion directe sans nouvelle attente
    started = time.monotonic()
    assert detector.evaluate_pac("http://ok.test/", pac) == (None, False)
    assert time.monotonic() - started < 0.5
    # Puis rechargé
    monkeypatch.setattr(proxy_detector, "PAC_RETRY_DELAY", 0)
    assert detector.evaluate_pac("http://ok.test/", pac) == ("http://p1:8080", True)


def test_pac_looping_while_loading_is_ignored(tmp_path, monkeypatch, caplog):
    pytest.importorskip("pypac")
    monkeypatch.setattr(pac_evaluator, "PAC_EVAL_TIMEOUT", 1.0)
    pac = write_pac(tmp_path, """
        while (true) {}
        function FindProxyForURL(url, host) { return "PROXY p1:8080"; }
    """)
    with caplog.at_level(logging.WARNING, logger="iziproxy"):
        assert ProxyDetector().evaluate_pac("http://ok.test/", pac) == (None, False)
    assert "did not finish" in caplog.text


def test_javascript_errors_keep_the_pac_usable(tmp_path):
    pytest.importorskip("pypac")
    pac = write_pac(tmp_path, """
        function FindProxyForURL(url, host) {
            if (host == "bad.test") { throw new Error("boom"); }
            return "PROXY p1:8080";
        }
    """)
    detector = ProxyDetector()
    assert detector.evaluate_pac("http://bad.test/", pac) == (None, False)
    assert detector.evaluate_pac("http://ok.test/", pac) == ("http://p1:8080", True)


def test_clear_cache_stops_the_pac_process(tmp_path):
    pytest.importorskip("pypac")
    pac = write_pac(tmp_path, LOOPING_FOR_ONE_HOST)
    detector = ProxyDetector()
    detector.evaluate_pac("http://ok.test/", pac)
    worker = detector._pac_cache[pac][0]
    detector.clear_cache()
    assert worker._process.wait(timeout=5) is not None


def test_frozen_applications_evaluate_the_pac_in_process(tmp_path, monkeypatch):
    pytest.importorskip("pypac")
    # Application PyInstaller : sys.executable n'est pas un interpréteur Python
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    pac = write_pac(tmp_path, LOOPING_FOR_ONE_HOST)
    detector = ProxyDetector()
    assert detector.evaluate_pac("http://ok.test/", pac) == ("http://p1:8080", True)
    assert isinstance(detector._pac_cache[pac][0], pac_evaluator._InProcessEvaluator)


@pytest.mark.parametrize("executable, expected", [
    (r"C:\Program Files\Blender\blender.exe", False),
    ("", False),
])
def test_only_python_interpreters_are_spawned(monkeypatch, executable, expected):
    monkeypatch.setattr(sys, "executable", executable)
    assert pac_evaluator._can_spawn() is expected


def test_pac_process_does_not_import_modules_from_the_working_directory(tmp_path, monkeypatch):
    pytest.importorskip("pypac")
    # Le répertoire courant (tmp_path/work, voir conftest) contient un faux pypac
    (tmp_path / "work" / "pypac").mkdir()
    (tmp_path / "work" / "pypac" / "__init__.py").write_text("raise SystemExit('planted module imported')\n")
    monkeypatch.setattr(sys, "path", [""] + [entry for entry in sys.path if entry])
    pac = write_pac(tmp_path, LOOPING_FOR_ONE_HOST)
    assert ProxyDetector().evaluate_pac("http://ok.test/", pac) == ("http://p1:8080", True)


# ---------------------------------------------------------------------- #
# Negotiate d'abord, puis NTLM
# ---------------------------------------------------------------------- #
def ntlm_izi(proxy):
    return IziProxy(proxy_url=proxy.url, username=proxy.username, password=proxy.password,
                    domain=proxy.domain)


def auth_schemes(proxy):
    """Schémas des en-têtes Proxy-Authorization reçus par le proxy, dans l'ordre."""
    return [entry["headers"]["proxy-authorization"].split(" ", 1)[0]
            for entry in proxy.log if "proxy-authorization" in entry["headers"]]


def test_negotiate_is_preferred_when_the_proxy_offers_both(make_proxy, tls_origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="both")
    with ntlm_izi(proxy).create_session() as session:
        assert session.get(tls_origin.url(), verify=False, timeout=10).status_code == 200
    assert auth_schemes(proxy) and set(auth_schemes(proxy)) == {"Negotiate"}


def test_ntlm_is_used_when_negotiate_is_refused(make_proxy, tls_origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="both", reject_negotiate=True)
    with ntlm_izi(proxy).create_session() as session:
        assert session.get(tls_origin.url(), verify=False, timeout=10).status_code == 200
        # Autre site, donc nouveau tunnel : NTLM directement, sans retenter Negotiate
        assert session.get(tls_origin.url(host="other.test"), verify=False, timeout=10).status_code == 200
    schemes = auth_schemes(proxy)
    assert schemes.count("Negotiate") == 1
    assert schemes[-1] == "NTLM" and schemes.count("NTLM") == 4


# ---------------------------------------------------------------------- #
# Réutilisation des connexions NTLM
# ---------------------------------------------------------------------- #
def test_https_tunnel_is_reused_for_the_same_site(make_proxy, tls_origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    with ntlm_izi(proxy).create_session() as session:
        for _ in range(3):
            assert session.get(tls_origin.url(), verify=False, timeout=10).status_code == 200
    # Un seul tunnel : sonde, jeton de type 1, jeton de type 3 (contre 7 CONNECT avant)
    assert [entry["method"] for entry in proxy.log] == ["CONNECT"] * 3
    assert len(tls_origin.requests) == 3


def test_http_requests_reuse_the_authenticated_connection(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm", keep_alive=True)
    with ntlm_izi(proxy).create_session() as session:
        for _ in range(3):
            assert session.get(origin.url(), timeout=10).status_code == 200
    # Négociation à la première requête seulement (type 1 et type 3). Refus :
    # sonde d'IziProxy (HEAD example.com), requête sans identifiants, type 1
    assert auth_schemes(proxy) == ["NTLM", "NTLM"]
    assert proxy.denied == 3
    assert len(proxy.log) == 5


def test_connect_reuses_an_authenticated_connection(make_proxy, origin, tls_origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm", keep_alive=True)
    with ntlm_izi(proxy).create_session() as session:
        assert session.get(origin.url(), timeout=10).status_code == 200
        denied = proxy.denied
        assert session.get(tls_origin.url(), verify=False, timeout=10).status_code == 200
    # Le CONNECT passe sur la connexion déjà authentifiée : pas de nouvelle négociation
    assert proxy.denied == denied
    assert proxy.log[-1]["method"] == "CONNECT"
    assert "proxy-authorization" not in proxy.log[-1]["headers"]


def test_connection_closed_by_the_proxy_is_replaced(make_proxy, origin, monkeypatch):
    pytest.importorskip("spnego")
    from iziproxy.ntlm_auth import _Connection

    # Le proxy de test ferme la connexion après chaque réponse http://
    proxy = make_proxy(auth="ntlm")
    with ntlm_izi(proxy).create_session() as session:
        assert session.get(origin.url(), timeout=10).status_code == 200
        time.sleep(0.2)
        # Fermeture pas encore visible au moment de la réutilisation
        monkeypatch.setattr(_Connection, "dropped", lambda self: False)
        assert session.get(origin.url(), timeout=10).status_code == 200
    # 3 refus pour la première requête (sonde comprise), 1 pour la nouvelle négociation
    assert proxy.denied == 4


def test_partially_read_responses_are_not_reused(make_proxy, tls_origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm")
    with ntlm_izi(proxy).create_session() as session:
        with session.get(tls_origin.url("/chunked"), verify=False, stream=True, timeout=10) as response:
            assert response.raw.read(5) == b"hello"
        adapter = session.get_adapter("https://")._ntlm()
        assert not any(adapter._connections._idle.values())
        assert session.get(tls_origin.url(), verify=False, timeout=10).status_code == 200
    # Le tunnel abandonné en cours de lecture n'a pas resservi
    assert [entry["method"] for entry in proxy.log].count("CONNECT") == 5


def test_local_proxy_reuses_authenticated_upstream_connections(make_proxy, origin):
    pytest.importorskip("spnego")
    proxy = make_proxy(auth="ntlm", keep_alive=True)
    with ntlm_izi(proxy).start_local_proxy(port=0) as local:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": local.url}))
        for _ in range(3):
            with opener.open(origin.url(), timeout=10) as response:
                assert response.status == 200
                response.read()
    # Une seule négociation (la sonde d'IziProxy compte pour un refus)
    assert auth_schemes(proxy) == ["NTLM", "NTLM"]
    assert proxy.denied == 3
