"""
Transports httpx qui choisissent le proxy à chaque requête.

httpx permet de remplacer son transport : c'est le point d'extension public
le plus propre. Pour chaque requête, IziProxy fournit la route
(IziProxy.proxy_for) et la requête est confiée à un httpx.HTTPTransport
configuré pour cette route (un transport par proxy, réutilisé, avec son
propre pool de connexions).

- connexion directe : transport sans proxy
- proxy sans authentification ou Basic : httpx envoie Proxy-Authorization
  au proxy uniquement (CONNECT pour HTTPS)
- proxy NTLM / Negotiate : passage par le proxy local partagé
"""

import threading

import anyio
import httpx

# Options transmises au transport plutôt qu'au client
TRANSPORT_OPTIONS = ("verify", "cert", "http1", "http2", "limits", "retries",
                     "local_address", "socket_options")


class _RoutingMixin:
    """Logique commune : un transport httpx par route, créé à la demande."""

    transport_class = None

    def __init__(self, izi, **transport_options):
        """
        Args:
            izi (IziProxy): Instance qui fournit les routes
            **transport_options: Options de httpx.HTTPTransport (verify, http2...)
        """
        self.izi = izi
        self._options = transport_options
        self._transports = {}
        self._lock = threading.Lock()

    def _transport_for(self, proxy):
        with self._lock:
            transport = self._transports.get(proxy)
            if transport is None:
                # trust_env ne concerne ici que SSL_CERT_FILE / SSL_CERT_DIR
                transport = self.transport_class(proxy=proxy, trust_env=True, **self._options)
                self._transports[proxy] = transport
            return transport

    def _take_transports(self):
        with self._lock:
            transports, self._transports = list(self._transports.values()), {}
        return transports


class IziHTTPXTransport(_RoutingMixin, httpx.BaseTransport):
    """Transport httpx synchrone piloté par IziProxy."""

    transport_class = httpx.HTTPTransport

    def handle_request(self, request):
        """Envoie la requête par le transport de la route choisie pour son URL."""
        proxy = self.izi.proxy_for(str(request.url))
        return self._transport_for(proxy).handle_request(request)

    def close(self):
        """Ferme les transports de toutes les routes."""
        for transport in self._take_transports():
            transport.close()


class AsyncIziHTTPXTransport(_RoutingMixin, httpx.AsyncBaseTransport):
    """Transport httpx asynchrone piloté par IziProxy."""

    transport_class = httpx.AsyncHTTPTransport

    async def handle_async_request(self, request):
        """Envoie la requête par le transport de la route choisie pour son URL."""
        # La première résolution peut être bloquante (sonde, PAC, trousseau)
        proxy = await anyio.to_thread.run_sync(self.izi.proxy_for, str(request.url))
        return await self._transport_for(proxy).handle_async_request(request)

    async def aclose(self):
        """Ferme les transports de toutes les routes."""
        for transport in self._take_transports():
            await transport.aclose()


def build_client(izi, asynchronous=False, **kwargs):
    """
    Crée un client httpx utilisant un transport IziProxy.

    Args:
        izi (IziProxy): Instance
        asynchronous (bool): AsyncClient au lieu de Client
        **kwargs: Options du client et du transport

    Returns:
        httpx.Client|httpx.AsyncClient: Client configuré
    """
    if "transport" in kwargs or "proxy" in kwargs or "mounts" in kwargs:
        raise TypeError("transport, proxy and mounts are managed by IziProxy")
    transport_options = {key: kwargs.pop(key) for key in TRANSPORT_OPTIONS if key in kwargs}
    # Sans cela, httpx monterait les proxys des variables d'environnement
    # devant notre transport
    kwargs["trust_env"] = False
    if asynchronous:
        return httpx.AsyncClient(transport=AsyncIziHTTPXTransport(izi, **transport_options), **kwargs)
    return httpx.Client(transport=IziHTTPXTransport(izi, **transport_options), **kwargs)
