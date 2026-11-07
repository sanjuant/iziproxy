"""
Configuration des outils qui ne prennent qu'une adresse de proxy : gRPC,
Selenium, Playwright.

Les navigateurs pilotés n'acceptent ni identifiants dans l'URL du proxy ni
règle par URL fournie par l'application : ils passent par le proxy local
partagé, qui applique le PAC, les exclusions et l'authentification.
"""

from urllib.parse import urlsplit

from ..local_proxy import TOKEN_USERNAME


def _uses_proxy(izi):
    """True si une URL quelconque peut avoir besoin d'un proxy."""
    return izi._proxy_settings()["source"] != "direct"


def grpc_options(izi, target, secure=True):
    """
    Options de canal gRPC (« grpc.http_proxy ») pour une cible.

    Args:
        izi (IziProxy): Instance
        target (str): « hôte:port », « dns:///hôte:port » ou « [ipv6]:port »
        secure (bool): Canal TLS

    Returns:
        list: Liste de tuples (option, valeur)
    """
    name = target
    for prefix in ("dns:///", "dns:", "ipv4:", "ipv6:"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    parts = urlsplit(f"//{name}")
    port = parts.port or 443
    host = parts.hostname or name
    scheme = "https" if secure else "http"
    authority = f"[{host}]" if ":" in host else host

    proxy = izi.proxy_for(f"{scheme}://{authority}:{port}/")
    if not proxy:
        return [("grpc.enable_http_proxy", 0)]
    # gRPC ne parle pas TLS au proxy : passer par le proxy local dans ce cas
    if proxy.lower().startswith("https://"):
        proxy = izi.local_proxy_url()
    return [("grpc.http_proxy", proxy)]


def selenium_proxy(izi):
    """
    Proxy pour Selenium.

    Chrome et Firefox pilotés ne savent pas envoyer d'identifiants à un
    proxy configuré par WebDriver : ils utilisent un proxy local partagé
    **sans jeton**, que tout processus de la machine peut emprunter tant
    qu'il tourne (voir la section Sécurité de la documentation).

    Returns:
        selenium.webdriver.common.proxy.Proxy: Proxy manuel vers le proxy
        local partagé, ou connexion directe
    """
    from selenium.webdriver.common.proxy import Proxy

    if not _uses_proxy(izi):
        return Proxy({"proxyType": "DIRECT"})
    address = izi.local_proxy_url(token=False).split("://", 1)[1]
    return Proxy({"proxyType": "MANUAL", "httpProxy": address, "sslProxy": address})


def playwright_proxy(izi):
    """
    Proxy pour Playwright, qui transmet lui-même le jeton du proxy local.

    Returns:
        dict|None: {"server", "username", "password"} pour Playwright, None sans proxy
    """
    if not _uses_proxy(izi):
        return None
    local = izi._shared_local_proxy()
    return {"server": local.address, "username": TOKEN_USERNAME, "password": local.token}
