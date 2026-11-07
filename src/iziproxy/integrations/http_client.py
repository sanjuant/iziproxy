"""
Connexions http.client configurées par IziProxy.

http.client ne connaît pas les proxys, mais sait ouvrir un tunnel CONNECT
(set_tunnel). Pour une cible https://, la connexion renvoyée se connecte au
proxy de la route puis tunnelise vers la cible ; pour une cible http://, elle
envoie au proxy des requêtes en forme absolue. Dans les deux cas, les
requêtes s'écrivent comme en direct (chemin relatif).
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
    auth = basic_proxy_authorization(proxy)
    if not secure:
        # Cible http:// : requête en forme absolue, comme un navigateur. Un
        # tunnel CONNECT vers le port 80 est refusé par la plupart des proxys
        # (Squid n'autorise CONNECT que vers les ports TLS)
        return _ProxiedHTTPConnection(proxy_host, proxy_port, origin_host=host, origin_port=port,
                                      proxy_authorization=auth, **options)
    connection = cls(proxy_host, proxy_port, **options)
    connection.set_tunnel(host, port, headers={"Proxy-Authorization": auth} if auth else {})
    return connection


class _ProxiedHTTPConnection(http.client.HTTPConnection):
    """
    Connexion vers un proxy HTTP qui s'utilise comme une connexion directe :
    les chemins relatifs (« /api ») deviennent des URLs absolues et l'en-tête
    Host désigne la cible.
    """

    def __init__(self, host, port, origin_host, origin_port, proxy_authorization=None, **kwargs):
        super().__init__(host, port, **kwargs)
        authority = f"[{origin_host}]" if ":" in origin_host else origin_host
        self._origin_authority = authority if origin_port == 80 else f"{authority}:{origin_port}"
        self._proxy_authorization = proxy_authorization

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if not url.startswith("http://"):
            url = f"http://{self._origin_authority}{url if url.startswith('/') else '/' + url}"
        super().putrequest(method, url, skip_host=True, skip_accept_encoding=skip_accept_encoding)
        if not skip_host:
            self.putheader("Host", self._origin_authority)
        if self._proxy_authorization:
            self.putheader("Proxy-Authorization", self._proxy_authorization)
