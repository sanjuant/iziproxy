"""
Une ligne pour tout le processus : iziproxy.install().

Après cet appel, requests, urllib, httpx et les commandes lancées par
subprocess (pip, git, curl...) passent le proxy d'entreprise, quel qu'il
soit. Sans proxy, rien n'est modifié.
"""

import subprocess
import sys
import urllib.request

import requests

import iziproxy

installation = iziproxy.install()
print("iziproxy :", installation)

# requests (et toutes les bibliothèques qui l'utilisent)
print("requests :", requests.get("https://httpbin.org/ip", timeout=10).json())

# urllib.request
with urllib.request.urlopen("https://httpbin.org/ip", timeout=10) as response:
    print("urllib   :", response.read().decode().strip())

# Un sous-processus : il hérite des variables HTTP(S)_PROXY
subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-d", ".", "six"], check=False)

# Réglage fin si besoin : l'instance IziProxy utilisée
proxy = installation.proxy
print("proxy pour l'intranet :", proxy.get_proxy_url("https://intranet.corp/"))

# Facultatif : tout est aussi annulé à la fin du programme
iziproxy.uninstall()
