"""
Handler urllib.request qui choisit le proxy à chaque requête.

Le ProxyHandler standard applique un dictionnaire figé (variables
d'environnement ou registre). IziProxyHandler prend sa place dans la chaîne
des handlers : pour chaque requête, il fixe le proxy de la route choisie par
IziProxy, ou laisse la requête partir en direct.
"""

import urllib.request
from urllib.parse import urlsplit

from ..proxy_utils import basic_proxy_authorization, strip_credentials


class IziProxyHandler(urllib.request.BaseHandler):
    """Handler urllib piloté par IziProxy."""

    # Même rang que ProxyHandler : avant les handlers HTTP / HTTPS
    handler_order = 100

    def __init__(self, izi):
        """
        Args:
            izi (IziProxy): Instance qui fournit les routes
        """
        self.izi = izi

    def _route(self, request):
        proxy = self.izi.proxy_for(request.full_url)
        if proxy and proxy.lower().startswith("https://"):
            # urllib ne parle pas TLS au proxy lui-même : passer par le proxy local
            proxy = self.izi.local_proxy_url()
        if proxy:
            parts = urlsplit(strip_credentials(proxy))
            auth = basic_proxy_authorization(proxy)
            if auth:
                # urllib transmet cet en-tête au proxy seul (tunnel CONNECT en HTTPS)
                request.add_unredirected_header("Proxy-Authorization", auth)
            request.set_proxy(parts.netloc, parts.scheme)
        # None : les handlers suivants envoient la requête
        return None

    def http_open(self, request):
        return self._route(request)

    def https_open(self, request):
        return self._route(request)


def build_opener(izi, *handlers):
    """
    Crée un OpenerDirector utilisant IziProxyHandler.

    Args:
        izi (IziProxy): Instance
        *handlers: Handlers supplémentaires

    Returns:
        urllib.request.OpenerDirector: Opener configuré
    """
    # ProxyHandler({}) remplace le ProxyHandler par défaut (variables d'environnement)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), IziProxyHandler(izi), *handlers)
