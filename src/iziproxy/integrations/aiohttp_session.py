"""
Session aiohttp configurée par IziProxy.

aiohttp ne propose pas de point d'extension public pour choisir le proxy de
chaque requête (le modifier dans un middleware passe par des API internes).
La session utilise donc le proxy local partagé d'IziProxy, qui applique
pour chaque URL le PAC, les exclusions et l'authentification (Basic, NTLM,
Negotiate). Le TLS reste de bout en bout : aiohttp vérifie le certificat du
site cible à travers le tunnel CONNECT.
"""

import inspect

import aiohttp


def build_session(izi, **kwargs):
    """
    Crée une aiohttp.ClientSession (à appeler dans une coroutine).

    Args:
        izi (IziProxy): Instance
        **kwargs: Options de aiohttp.ClientSession

    Returns:
        aiohttp.ClientSession: Session configurée
    """
    if "proxy" in kwargs:
        raise TypeError("proxy is managed by IziProxy")
    if "proxy" not in inspect.signature(aiohttp.ClientSession.__init__).parameters:
        raise RuntimeError("aiohttp >= 3.11 is required (ClientSession(proxy=...))")

    # Les variables d'environnement ne doivent pas court-circuiter IziProxy
    kwargs["trust_env"] = False
    if izi._proxy_settings()["source"] != "direct":
        kwargs["proxy"] = izi.local_proxy_url()
    return aiohttp.ClientSession(**kwargs)
