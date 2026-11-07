"""
Connexions http.client configurées par IziProxy.

http.client ne connaît pas les proxys, mais sait ouvrir un tunnel CONNECT
(set_tunnel). La connexion renvoyée se connecte au proxy de la route puis
tunnelise vers la cible : les requêtes s'écrivent comme en direct.
"""

import http.client
from urllib.parse import urlsplit

from ..proxy_utils import basic_proxy_authorization, proxy_host_port


def connection_for(izi, url, timeout=None, context=None):
    """
    Crée une connexion http.client vers l'hôte d'une URL.

    Args:
        izi (IziProxy): Instance
        url (str): URL ou origine cible ("https://hôte:port")
        timeout (float): Délai en secondes
        context (ssl.SSLContext): Contexte TLS pour une cible HTTPS

    Returns:
        http.client.HTTPConnection|http.client.HTTPSConnection: Connexion non ouverte
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    secure = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if secure else 80)

    options = {"timeout": timeout}
    if secure:
        options["context"] = context
    cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection

    proxy = izi.proxy_for(f"{parts.scheme}://{host}:{port}/")
    if not proxy:
        return cls(host, port, **options)

    # http.client ne sait pas parler TLS au proxy lui-même : passer par le proxy local
    if proxy.lower().startswith("https://"):
        proxy = izi.local_proxy_url()

    proxy_host, proxy_port = proxy_host_port(proxy)
    connection = cls(proxy_host, proxy_port, **options)
    headers = {}
    auth = basic_proxy_authorization(proxy)
    if auth:
        headers["Proxy-Authorization"] = auth
    connection.set_tunnel(host, port, headers=headers)
    return connection
