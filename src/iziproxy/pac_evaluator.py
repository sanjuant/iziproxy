"""
Évaluation des fichiers PAC avec un délai maximal.

pypac exécute le JavaScript du PAC avec dukpy (QuickJS ou Duktape), qui
garde le GIL pendant toute l'évaluation et n'offre aucun moyen de
l'interrompre : un PAC qui boucle (malveillant, servi en http:// et modifié
sur le réseau, ou simplement bogué) gèlerait tout le processus Python, pas
seulement les requêtes.

Le PAC est donc chargé et évalué dans un processus Python fils, arrêté s'il
ne répond pas dans les PAC_EVAL_TIMEOUT secondes. Le processus fils est
lancé une fois par fichier PAC (environ 0,2 s) puis réutilisé pour chaque
URL ; il s'arrête avec l'évaluateur (clear_cache(), fin du programme).

Si le processus fils ne peut pas être lancé (application figée par
PyInstaller, Python embarqué dans un autre logiciel), l'évaluation a lieu
dans le processus courant, sans délai maximal.
"""

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import weakref

logger = logging.getLogger("iziproxy")

# Délai maximal du chargement d'un PAC et de chaque évaluation (secondes) ;
# les fonctions du PAC (dnsResolve, isInNet...) peuvent interroger le DNS
PAC_EVAL_TIMEOUT = 10.0

# Code du processus fils : lit des requêtes JSON (une par ligne) sur stdin,
# répond sur stdout. Il n'importe que pypac, jamais IziProxy.
_WORKER_SOURCE = r"""
import json
import sys


def reply(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


setup = json.loads(sys.stdin.readline())
sys.path[:] = setup["path"]
try:
    from pypac.parser import PACFile

    pac = PACFile(setup["pac"])
except Exception as exc:
    reply({"error": describe(exc)})
    sys.exit(0)
reply({"ok": True})
for line in sys.stdin:
    request = json.loads(line)
    try:
        reply({"result": pac.find_proxy_for_url(request["url"], request["host"])})
    except Exception as exc:
        reply({"error": describe(exc)})
"""


class PacEvaluationError(Exception):
    """Le PAC n'a pas pu être chargé ou évalué (erreur JavaScript...)."""


class PacTimeoutError(PacEvaluationError):
    """Le PAC n'a pas répondu à temps (boucle infinie ?) ; l'évaluateur est arrêté."""


def _can_spawn():
    """
    Indique si sys.executable est un interpréteur Python que l'on peut
    relancer : pas une application figée ni un logiciel qui embarque Python
    (son exécutable recevrait des options qu'il ne comprend pas).
    """
    if getattr(sys, "frozen", False) or not sys.executable:
        return False
    name = os.path.basename(sys.executable).lower()
    return name.startswith(("python", "pypy")) and os.path.isfile(sys.executable)


def _read_replies(stream, replies):
    """
    Thread de lecture des réponses du processus fils.

    Il ne référence pas l'évaluateur : celui-ci peut ainsi être libéré (et
    son processus arrêté) pendant que le thread attend.
    """
    try:
        for line in stream:
            replies.put(line)
    except (OSError, ValueError):
        pass
    finally:
        replies.put(None)


def _stop(process):
    """Arrête le processus fils et ferme ses tubes (appelable plusieurs fois)."""
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    for stream in (process.stdin, process.stdout):
        try:
            stream.close()
        except (OSError, ValueError):
            pass


class _WorkerEvaluator:
    """Évaluateur dont le PAC tourne dans un processus Python fils."""

    def __init__(self, pac_text, timeout):
        self._timeout = timeout
        self._lock = threading.Lock()
        self._process = subprocess.Popen(
            # -I : ni répertoire courant ni variables PYTHON* ; le chemin des
            # modules est celui du processus courant (voir setup)
            [sys.executable, "-I", "-c", _WORKER_SOURCE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            # Pas de fenêtre de console depuis une application graphique
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._replies = queue.Queue()
        threading.Thread(target=_read_replies, args=(self._process.stdout, self._replies),
                         name="iziproxy-pac-reader", daemon=True).start()
        self._finalizer = weakref.finalize(self, _stop, self._process)
        # Chemins absolus et sans le répertoire courant ("") : un pypac.py
        # posé dans le répertoire de travail ne doit pas être importé
        path = [os.path.abspath(entry) for entry in sys.path if entry]
        try:
            self._call({"path": path, "pac": pac_text})
        except BaseException:
            self.close()
            raise

    @property
    def alive(self):
        """False une fois le processus fils arrêté (délai dépassé, plantage)."""
        return self._finalizer.alive and self._process.poll() is None

    def _call(self, message):
        with self._lock:
            if not self.alive:
                raise PacEvaluationError("The PAC evaluation process is not running")
            try:
                self._process.stdin.write((json.dumps(message) + "\n").encode("ascii"))
                self._process.stdin.flush()
                line = self._replies.get(timeout=self._timeout)
            except queue.Empty:
                self.close()
                raise PacTimeoutError(f"no answer within {self._timeout:g} s") from None
            except OSError as exc:
                self.close()
                raise PacEvaluationError(f"the PAC evaluation process stopped: {exc}") from exc
            if line is None:
                self.close()
                raise PacEvaluationError("the PAC evaluation process stopped")
            try:
                reply = json.loads(line)
            except ValueError as exc:
                # Sortie inattendue : l'échange n'est plus synchronisé
                self.close()
                raise PacEvaluationError(f"unexpected output from the PAC evaluation process: {exc}") from exc
            if "error" in reply:
                raise PacEvaluationError(reply["error"])
            return reply

    def find_proxy_for_url(self, url, host):
        """Résultat brut de FindProxyForURL (ex. « PROXY p:8080; DIRECT »)."""
        return self._call({"url": url, "host": host})["result"]

    def close(self):
        """Arrête le processus fils."""
        self._finalizer()


class _InProcessEvaluator:
    """Repli sans délai maximal : le PAC tourne dans le processus courant."""

    alive = True

    def __init__(self, pac_text):
        from pypac.parser import PACFile

        try:
            self._pac = PACFile(pac_text)
        except Exception as exc:
            raise PacEvaluationError(f"{type(exc).__name__}: {exc}") from exc

    def find_proxy_for_url(self, url, host):
        try:
            return self._pac.find_proxy_for_url(url, host)
        except Exception as exc:
            raise PacEvaluationError(f"{type(exc).__name__}: {exc}") from exc

    def close(self):
        pass


def create_evaluator(pac_text, timeout=None):
    """
    Charge un PAC et retourne un objet doté de find_proxy_for_url(url, host)
    et close().

    Args:
        pac_text (str): JavaScript du PAC
        timeout (float): Délai maximal (défaut : PAC_EVAL_TIMEOUT)

    Raises:
        PacEvaluationError: PAC invalide
        PacTimeoutError: Chargement trop long (code de premier niveau qui boucle)
    """
    timeout = PAC_EVAL_TIMEOUT if timeout is None else timeout
    if _can_spawn():
        try:
            return _WorkerEvaluator(pac_text, timeout)
        except OSError as exc:
            logger.warning("Cannot start the PAC evaluation process (%s): evaluating the PAC "
                           "in this process, without a time limit", exc)
    else:
        logger.debug("PAC evaluated in this process (no separate Python process available)")
    return _InProcessEvaluator(pac_text)
