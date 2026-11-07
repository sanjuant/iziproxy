"""
iziproxy.install() : une ligne pour que tout le processus passe le proxy.

Le besoin d'abord : que « ça marche », sans rien connaître du proxy. Un seul
appel configure, pour tout le processus et ses sous-processus :

- requests (y compris requests.get() et les bibliothèques tierces) ;
- urllib.request.urlopen() ;
- les variables HTTP(S)_PROXY / NO_PROXY, lues par httpx, pip, git, curl,
  conda, gRPC... Elles pointent vers un proxy local sur 127.0.0.1 qui gère
  NTLM, le PAC et les exclusions, si bien qu'aucun mot de passe n'apparaît
  dans l'environnement.

Sans proxy (poste en production, réseau domestique), install() ne modifie
rien : le même code fonctionne partout.

Tout est réversible : uninstall(), bloc ``with`` ou fin du programme.
"""

import atexit
import logging
import threading
import urllib.request

logger = logging.getLogger("iziproxy")

_LOCK = threading.RLock()
_CURRENT = {"installation": None}


class Installation:
    """
    Résultat de iziproxy.install() : ce qui a été configuré et comment
    l'annuler.

    Attributs :

    - ``proxy`` (IziProxy) : instance utilisée ; elle donne accès aux
      réglages fins (httpx_client(), aiohttp_session(), get_proxy_url()...)
    - ``active`` (bool) : False si aucun proxy n'a été trouvé (rien n'a été modifié)
    - ``local_proxy_url`` (str|None) : URL du proxy local, si démarré
    - ``environment`` (dict) : variables d'environnement définies
    - ``requests_patched`` (bool) : requests est configuré
    - ``urllib_patched`` (bool) : urllib.request.urlopen() est configuré

    S'utilise aussi comme gestionnaire de contexte :
        >>> with iziproxy.install():
        ...     requests.get("https://example.com")
    """

    def __init__(self, proxy):
        self.proxy = proxy
        self.active = False
        self.local_proxy_url = None
        self.environment = {}
        self.requests_patched = False
        self.urllib_patched = False
        self._previous_opener = None
        self._installed = False

    def __repr__(self):
        return f"<iziproxy.Installation {self.describe()}>"

    def __str__(self):
        return self.describe()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.uninstall()
        return False

    def describe(self):
        """
        Résumé lisible de la configuration (utile pour le diagnostic).

        Returns:
            str: Par exemple « proxy http://proxy:8080 (ntlm) ; local
                 http://127.0.0.1:53211 ; requests, urllib, environment »
        """
        if not self._installed:
            return "uninstalled"
        if not self.active:
            return "no proxy found: direct connections, nothing changed"
        izi = self.proxy
        parts = [f"proxy {izi.get_proxy_url()}"]
        if izi.requires_auth:
            parts[0] += f" ({izi.auth_type})"
        if self.local_proxy_url:
            parts.append(f"local {self.local_proxy_url}")
        patched = [name for name, done in (("requests", self.requests_patched),
                                           ("urllib", self.urllib_patched),
                                           ("environment", bool(self.environment))) if done]
        parts.append(", ".join(patched) or "nothing patched")
        return " ; ".join(parts)

    def uninstall(self):
        """Annule tout ce que install() a configuré (sans effet si déjà fait)."""
        with _LOCK:
            if not self._installed:
                return
            self._installed = False
            if _CURRENT["installation"] is self:
                _CURRENT["installation"] = None

            if self.urllib_patched:
                urllib.request.install_opener(self._previous_opener)
                self.urllib_patched = False
            if self.requests_patched:
                self.proxy.unpatch_requests()
                self.requests_patched = False
            if self.environment:
                self.proxy.clear_environment_variables()
                self.environment = {}
            self.proxy.stop_local_proxies()
            self.local_proxy_url = None
        logger.info("iziproxy uninstalled")


def install(proxy=None, *, requests=True, urllib=True, env_vars=True, local_proxy=True,
            **options):
    """
    Configure le proxy pour tout le processus, en une ligne.

        >>> import iziproxy
        >>> iziproxy.install()

    Par défaut tout est détecté (environnement, proxy système, PAC, type
    d'authentification, session Windows pour NTLM) et tout est configuré :
    requests, urllib.request et les variables d'environnement (donc httpx,
    pip, git, curl...). Sans proxy détecté, rien n'est modifié.

    Un nouvel appel remplace la configuration précédente.

    Args:
        proxy (IziProxy): Instance déjà configurée à utiliser (sinon une
            instance est créée avec ``options``)
        requests (bool): Configurer requests (patch_requests())
        urllib (bool): Configurer urllib.request.urlopen()
        env_vars (bool): Définir HTTP(S)_PROXY / NO_PROXY
        local_proxy (bool): Faire pointer les variables vers le proxy local
            (recommandé : gère NTLM et le PAC, aucun mot de passe dans
            l'environnement). False : variables vers le proxy d'entreprise,
            identifiants Basic inclus ; impossible avec NTLM.
        **options: Paramètres d'IziProxy (proxy_url, pac_url, username,
            password, domain, auth_type, no_proxy, config_path, environment,
            interactive, debug)

    Returns:
        Installation: Ce qui a été configuré (proxy, describe(), uninstall())

    Raises:
        ValueError: local_proxy=False alors que le proxy exige NTLM
    """
    from .proxy_manager import IziProxy

    if proxy is not None and options:
        raise TypeError("Pass either an IziProxy instance or IziProxy options, not both")
    if proxy is None:
        proxy = IziProxy(**options)

    with _LOCK:
        previous = _CURRENT["installation"]
        if previous is not None:
            previous.uninstall()

        installation = Installation(proxy)
        installation._installed = True
        _CURRENT["installation"] = installation

        if proxy._proxy_settings()["source"] == "direct":
            logger.info("iziproxy: no proxy found, direct connections (nothing changed)")
            return installation
        installation.active = True

        try:
            if env_vars:
                if not local_proxy and proxy._uses_ntlm():
                    raise ValueError("Environment variables cannot carry NTLM authentication: "
                                     "use install(local_proxy=True)")
                installation.environment = proxy.set_environment_variables(local_proxy=local_proxy)
                if local_proxy:
                    installation.local_proxy_url = installation.environment.get("HTTPS_PROXY")
            if requests:
                proxy.patch_requests()
                installation.requests_patched = True
            if urllib:
                installation._previous_opener = getattr(urllib_request, "_opener", None)
                urllib_request.install_opener(proxy.urllib_opener())
                installation.urllib_patched = True
        except Exception:
            installation.uninstall()
            raise

    logger.info("iziproxy installed: %s", installation.describe())
    return installation


def uninstall():
    """Annule le dernier iziproxy.install() (sans effet s'il n'y en a pas)."""
    installation = current()
    if installation is not None:
        installation.uninstall()


def current():
    """
    Installation active, ou None.

    Pratique pour retrouver l'instance IziProxy configurée ailleurs dans le
    programme : ``iziproxy.current().proxy.httpx_client()``.
    """
    return _CURRENT["installation"]


# Le paramètre « urllib » masque le module dans install() : alias interne
urllib_request = urllib.request

atexit.register(uninstall)
