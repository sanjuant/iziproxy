"""
Faire passer par le proxy du code qu'on ne contrôle pas.

Pour tout configurer d'un coup, iziproxy.install() suffit (voir one_line.py).
Cet exemple montre les deux mécanismes séparément.
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

# 2. Outils externes (pip, git, curl...) : HTTP(S)_PROXY / NO_PROXY pointent
#    vers un proxy local qui gère NTLM, le PAC et les exclusions. Aucun mot de
#    passe dans l'environnement, seulement le jeton du proxy local.
proxy.set_environment_variables(local_proxy=True)
try:
    subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-d", ".", "six"], check=False)
finally:
    proxy.clear_environment_variables()  # restaure les variables et arrête le proxy local
