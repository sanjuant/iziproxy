"""
Démarrage rapide : détection automatique du proxy et requêtes via requests.
"""

import requests

from iziproxy import IziProxy

# Détection automatique : environnement, proxy système / PAC, authentification
proxy = IziProxy(debug=True)

print("Environment :", proxy.environment)
print("Proxy       :", proxy.get_proxy_url() or "direct connection")
print("Auth        :", proxy.auth_type if proxy.requires_auth else "none")

# 1. Session préconfigurée (recommandé : gère no_proxy, PAC et NTLM)
session = proxy.create_session()
print(session.get("https://httpbin.org/ip", timeout=10).json())

# 2. Dictionnaire de proxys (Basic uniquement, pas de NTLM)
print(requests.get("https://httpbin.org/ip", proxies=proxy.get_proxy_dict(), timeout=10).json())

# 3. Affichage sans fuite de mot de passe
print(proxy.get_proxy_config())
