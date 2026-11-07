"""
Adaptateurs IziProxy pour les clients HTTP autres que requests.

Chaque module importe sa bibliothèque à l'utilisation : aucune n'est
requise tant que l'adaptateur correspondant n'est pas employé.

- httpx_transport : transports httpx (synchrone et asynchrone)
- aiohttp_session : session aiohttp via le proxy local
- urllib3_pool    : PoolManager urllib3
- urllib_handler  : handler urllib.request
- http_client     : connexions http.client
- tools           : gRPC, Selenium, Playwright
"""
