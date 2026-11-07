"""
PoolManager urllib3 qui choisit le proxy à chaque requête.

urllib3 ne lit pas les variables d'environnement : un PoolManager ne passe
jamais par un proxy. IziPoolManager garde l'API de PoolManager et délègue
chaque requête soit à lui-même (connexion directe), soit à un ProxyManager
propre à la route (réutilisé, avec son pool de connexions).
"""

import threading

import urllib3

from ..proxy_utils import basic_proxy_authorization, is_https_proxy, strip_credentials


class IziPoolManager(urllib3.PoolManager):
    """
    PoolManager piloté par IziProxy.

    Limite : une redirection suit la route de la requête d'origine (urllib3
    gère les redirections à l'intérieur du gestionnaire choisi).
    """

    def __init__(self, izi, **kwargs):
        """
        Args:
            izi (IziProxy): Instance qui fournit les routes
            **kwargs: Options de urllib3.PoolManager (num_pools, retries,
                cert_reqs, ca_certs...)
        """
        super().__init__(**kwargs)
        self.izi = izi
        self._options = kwargs
        self._proxy_managers = {}
        self._routes_lock = threading.Lock()

    def _manager_for(self, url):
        """ProxyManager à utiliser pour cette URL, ou None (direct)."""
        proxy = self.izi.proxy_for(url)
        if not proxy:
            return None
        with self._routes_lock:
            manager = self._proxy_managers.get(proxy)
            if manager is None:
                headers = {}
                auth = basic_proxy_authorization(proxy)
                if auth:
                    headers["Proxy-Authorization"] = auth
                if is_https_proxy(proxy):
                    # Certificat du proxy vérifié selon verify d'IziProxy
                    self._options.setdefault("proxy_ssl_context", self.izi._proxy_ssl_context())
                manager = urllib3.ProxyManager(strip_credentials(proxy), proxy_headers=headers,
                                               **self._options)
                self._proxy_managers[proxy] = manager
            return manager

    def urlopen(self, method, url, redirect=True, **kw):
        """Envoie la requête par la route choisie pour son URL."""
        manager = self._manager_for(url)
        if manager is None:
            return super().urlopen(method, url, redirect=redirect, **kw)
        return manager.urlopen(method, url, redirect=redirect, **kw)

    def clear(self):
        """Ferme toutes les connexions (directes et via proxy)."""
        super().clear()
        with self._routes_lock:
            managers, self._proxy_managers = list(self._proxy_managers.values()), {}
        for manager in managers:
            manager.clear()
