"""
Remplacer cntlm : un proxy local sur 127.0.0.1:3128.

Le proxy local s'authentifie auprès du proxy d'entreprise (NTLM / Negotiate
avec la session Windows, Basic) et applique le PAC et les exclusions : pip,
git, curl, un navigateur... n'ont besoin que de son adresse.

    python local_proxy.py            # port 3128
    python local_proxy.py 8888       # autre port (0 : port libre au hasard)
"""

import sys

from iziproxy import IziProxy

port = int(sys.argv[1]) if len(sys.argv) > 1 else 3128

# Jeton fixe : l'URL reste la même d'un démarrage à l'autre, les outils se
# configurent une fois pour toutes. Sans « token= », il est aléatoire.
local = IziProxy().start_local_proxy(port=port, token="remplacez-par-un-jeton-long-et-secret")

print("Proxy local prêt :", local.url)
print("  git config --global http.proxy", local.url)
print("  HTTPS_PROXY=" + local.url)
print("Ctrl+C pour arrêter.")
local.serve_forever()
