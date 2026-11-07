"""
Faire passer par le proxy du code qu'on ne contrôle pas.
"""

import subprocess
import sys

import requests

from iziproxy import IziProxy

proxy = IziProxy()

# 1. Bibliothèques basées sur requests : toutes les sessions créées pendant le
#    bloc (y compris celles de requests.get) sont configurées automatiquement.
with proxy:
    proxy.patch_requests()
    print(requests.get("https://httpbin.org/ip", timeout=10).json())
# En sortie de bloc, requests retrouve son comportement d'origine.

# 2. Outils externes (pip, git, curl...) : variables HTTP(S)_PROXY / NO_PROXY.
#    Attention : ces variables ne peuvent pas porter une authentification NTLM.
proxy.set_environment_variables()
try:
    subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-d", ".", "six"], check=False)
finally:
    proxy.clear_environment_variables()  # restaure les valeurs précédentes
