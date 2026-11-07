"""
Proxy d'entreprise avec authentification NTLM / Negotiate.

Prérequis : pip install iziproxy[ntlm]

Sous Windows, aucun mot de passe n'est nécessaire : la session Windows
courante est utilisée (SSPI). Ailleurs, les identifiants sont cherchés dans
IZIPROXY_USERNAME / IZIPROXY_PASSWORD / IZIPROXY_DOMAIN, le fichier .env, le trousseau
système, puis demandés une seule fois et enregistrés dans le trousseau.
"""

from iziproxy import IziProxy, NtlmAuthenticationError

proxy = IziProxy(
    proxy_url="http://proxy.corp.example:8080",  # facultatif si le système le déclare
    auth_type="ntlm",                            # facultatif : détecté via Proxy-Authenticate
    no_proxy="*.corp.example,<local>",           # hôtes internes joints directement
)

session = proxy.create_session()
try:
    response = session.get("https://www.python.org", timeout=15)
    print(response.status_code, response.headers.get("content-type"))
except NtlmAuthenticationError as error:
    print("The proxy rejected the credentials:", error)
    # Oublier le mot de passe enregistré pour qu'il soit redemandé
    proxy.reset_credentials()
