# IziProxy

Une bibliothèque Python pour utiliser les proxys d'entreprise sans y penser.

[![PyPI version](https://img.shields.io/pypi/v/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![License](https://img.shields.io/github/license/sanjuant/iziproxy.svg)](https://github.com/sanjuant/iziproxy/blob/master/LICENSE)

Le même code fonctionne sur le poste du développeur (proxy NTLM), en
recette (proxy Basic) et en production (pas de proxy) : IziProxy détecte
l'environnement, trouve le proxy, découvre l'authentification attendue et
configure vos clients HTTP, en une ligne : `iziproxy.install()`.

## 🚀 Fonctionnalités

- 🔍 **Détection de l'environnement** : `local`, `dev`, `prod` via variable d'environnement, nom d'hôte ou adresse IP
- 🌐 **Proxy système** : variables `HTTP(S)_PROXY`, registre Windows, macOS (`scutil`), GNOME, KDE
- 📜 **Fichiers PAC** évalués **pour chaque URL** (un hôte interne peut être `DIRECT`, le reste via le proxy)
- 🚫 **Exclusions** respectées requête par requête : `NO_PROXY`, `ProxyOverride` Windows (`<local>`, `*.corp.com`, `10.*`), CIDR
- 🔐 **Authentification détectée automatiquement** (réponse 407 et `Proxy-Authenticate`) : Basic ou NTLM / Negotiate
- 🪟 **NTLM sans mot de passe sous Windows** : la session courante est utilisée (SSPI)
- 🔑 **Identifiants** : paramètres, variables d'environnement, `.env`, trousseau système, saisie graphique ou console (une seule fois, puis mémorisée)
- 🛡️ **Sécurité** : les identifiants ne sont envoyés qu'au proxy (jamais au site cible), masqués dans les journaux et chiffrés en mémoire
- 🔌 **Intégration** : session `requests`, dictionnaire `proxies=`, variables d'environnement pour les outils externes, patch global de `requests`
- 🔁 **Proxy local (façon cntlm / px)** : pip, git, curl, conda... traversent un proxy NTLM sans identifiants
- ⚡ **Une ligne pour tout le processus** : `iziproxy.install()` configure requests, urllib, httpx, aiohttp et les sous-processus

## 📦 Installation

```bash
pip install iziproxy            # proxys sans authentification ou Basic
pip install iziproxy[ntlm]      # + NTLM / Negotiate (pyspnego)
pip install iziproxy[pac]       # + fichiers PAC (pypac)
pip install iziproxy[httpx]     # + adaptateur httpx
pip install iziproxy[aiohttp]   # + adaptateur aiohttp
pip install iziproxy[truststore] # + vérification TLS par le système (Python 3.10+)
pip install iziproxy[all]       # NTLM + PAC + truststore
```

Python 3.8 ou plus récent.

## ⚡ Démarrage en 30 secondes

```python
import iziproxy

iziproxy.install()
```

C'est tout. À partir de cette ligne, **tout le processus** passe le proxy
d'entreprise, quel qu'il soit (sans authentification, Basic, NTLM, fichier PAC) :

| Ce qui marche sans rien faire d'autre | Comment |
|---|---|
| `requests` (et `requests.get()` des bibliothèques tierces) | patché |
| `urllib.request.urlopen()` | opener global installé |
| `httpx`, gRPC, et tout client qui lit `HTTP(S)_PROXY` | variables d'environnement |
| `aiohttp` | `ClientSession(trust_env=True)` |
| pip, git, curl, conda lancés par `subprocess` | variables d'environnement héritées |

- **Sans proxy** (production, réseau domestique), `install()` ne touche à
  rien : gardez la ligne, le même code marche partout.
- **Aucun mot de passe** dans les variables d'environnement : elles pointent
  vers un petit proxy local (`127.0.0.1`) qui s'authentifie à la place des
  clients.
- **Sous Windows avec NTLM**, aucun identifiant à fournir : la session
  Windows est utilisée.
- **Réversible** : `iziproxy.uninstall()`, un bloc `with iziproxy.install():`,
  ou simplement la fin du programme.

Pour savoir ce qui a été configuré :

```python
print(iziproxy.install())
# proxy http://proxy.corp:8080 (ntlm) ; local http://127.0.0.1:53211 ; requests, urllib, environment
```

### Et si ça ne marche pas tel quel ?

Ajoutez seulement ce qui manque, du plus simple au plus précis :

| Situation | Solution |
|---|---|
| Le proxy n'est pas détecté | `iziproxy.install(proxy_url="proxy.corp:8080")` ou `iziproxy.install(pac_url="http://wpad/proxy.pac")` |
| Les identifiants ne sont pas trouvés | `iziproxy.install(username="jdupont", password="...", domain="CORP")`, variables `IZIPROXY_USERNAME` / `IZIPROXY_PASSWORD`, ou la saisie interactive (mémorisée dans le trousseau) |
| Pas de saisie interactive (service, CI) | `iziproxy.install(interactive=False)` |
| Certains hôtes doivent rester en direct | `iziproxy.install(no_proxy=["*.corp.local", "10.0.0.0/8"])` |
| Réglages différents selon local / dev / prod | fichier `iziproxy.yml` (voir Configuration ci-dessous), puis `install()` sans paramètre |
| Ne configurer que certains clients | `iziproxy.install(urllib=False, env_vars=False)` |
| Certificat du proxy https:// ou du PAC refusé | `pip install iziproxy[truststore]` (autorités du système), sinon `iziproxy.install(verify="/chemin/ca-entreprise.pem")` |
| Comprendre ce qui se passe | `iziproxy.install(debug=True)` |
| Réglage fin d'un client précis | `iziproxy.current().proxy` est l'instance `IziProxy` (voir ci-dessous) |

`install()` accepte tous les paramètres de `IziProxy(...)`. Toutes les
options sont décrites dans la page « Démarrage rapide » de la documentation.

## 🎛️ Contrôle fin : la classe IziProxy

Pour choisir précisément quel client est configuré et comment, utilisez
directement `IziProxy` (c'est ce que fait `install()` en interne) :

```python
from iziproxy import IziProxy

proxy = IziProxy()

# 1. Session requests préconfigurée (recommandé : gère exclusions, PAC et NTLM)
session = proxy.create_session()
session.get("https://example.com")

# 2. Dictionnaire de proxys pour requests (Basic uniquement)
import requests
requests.get("https://example.com", proxies=proxy.get_proxy_dict())

# 3. Variables d'environnement pour pip, git, curl...
proxy.set_environment_variables()                  # proxy sans auth ou Basic
proxy.set_environment_variables(local_proxy=True)  # NTLM, PAC : via un proxy local
...
proxy.clear_environment_variables()   # restaure les valeurs précédentes

# 4. Tout le code basé sur requests (bibliothèques tierces comprises)
with proxy:
    proxy.patch_requests()
    requests.get("https://example.com")
# requests est restauré en sortie de bloc
```

Informations disponibles :

```python
proxy.environment          # 'local', 'dev' ou 'prod'
proxy.get_proxy_url()      # 'http://proxy.corp:8080' ou None (connexion directe)
proxy.get_proxy_url("https://intranet.corp/")   # selon le PAC et les exclusions
proxy.requires_auth        # True / False (détecté si non configuré)
proxy.auth_type            # 'basic' ou 'ntlm'
proxy.get_proxy_config()   # dictionnaire affichable, mots de passe masqués
```

## 🧩 Autres clients HTTP

Chaque client a son adaptateur, avec les mêmes règles (PAC par URL,
exclusions, Basic, NTLM via le proxy local) :

| Client | Adaptateur |
|---|---|
| requests | `create_session()`, `patch_requests()` |
| httpx | `httpx_client()`, `httpx_async_client()` |
| aiohttp | `aiohttp_session()` |
| urllib3 | `urllib3_pool_manager()` |
| urllib.request | `urllib_opener()`, `install_urllib_opener()` |
| http.client | `http_connection(url)` |
| websockets | `connect(uri, proxy=proxy.websocket_proxy(uri))` |
| gRPC | `grpc_channel_options(target)` |
| Selenium / Playwright | `selenium_proxy()`, `playwright_proxy()` |
| pip, git, curl… | `set_environment_variables(local_proxy=True)` |
| tout autre client | `proxy_for(url)`, `local_proxy_url()` |

```python
with proxy.httpx_client() as client:
    client.get("https://example.com")

async with proxy.aiohttp_session() as session:
    await session.get("https://example.com")
```

Détails dans la documentation (page « Autres clients HTTP »).

## ⚙️ Configuration

Sans configuration, tout est détecté. Pour forcer un comportement :

### Par code

```python
proxy = IziProxy(
    proxy_url="http://proxy.example.com:8080",  # proxy explicite (prioritaire)
    pac_url="http://pac.example.com/proxy.pac", # ou un fichier PAC (URL ou chemin)
    username="user", password="pass",           # identifiants explicites
    domain="CORP",                              # domaine NTLM
    auth_type="ntlm",                           # 'basic' ou 'ntlm' (sinon détecté)
    no_proxy="*.corp.example,<local>",          # exclusions supplémentaires
    environment="prod",                         # forcer l'environnement
    interactive=False,                          # ne jamais demander d'identifiants
    verify="/chemin/ca.pem",                    # certificats du proxy https:// et du PAC
    debug=True,                                 # journaux détaillés sur stderr
)
```

### Par fichier YAML

`./iziproxy.yml`, `~/.config/iziproxy.yml` ou `~/.iziproxy.yml` :

```yaml
environments:
  local:
    requires_auth: true
    auth_type: ntlm             # poste Windows : session courante
  dev:
    proxy_url: "http://dev-proxy.example.com:8080"
    auth_type: basic
    no_proxy: "*.dev.example.com"
  prod:
    pac_url: "http://pac.example.com/proxy.pac"

no_proxy: "<local>,*.internal.example.com"

environment_detection:
  method: auto                  # auto, env_var, hostname, ip, ask
  hostname_patterns:
    dev: ["-dev", "staging"]
  ip_ranges:
    prod: ["172.16.0.0/16"]

system_proxy:
  use_system_proxy: true
  detect_env_vars: true
  detect_pac: true

credentials:
  prompt: true                  # false sur les serveurs et en CI
```

Un exemple complet est fourni dans [examples/config_example.yml](examples/config_example.yml).

### Ordre de priorité

| Élément | Ordre |
|---|---|
| Proxy | `proxy_url=` → `pac_url=` → configuration de l'environnement → variables d'environnement → paramètres système → PAC système → connexion directe |
| Authentification | paramètres → `requires_auth` / `auth_type` de la configuration → sondage du proxy |
| Identifiants | `username=` / `password=` → URL du proxy → `IZIPROXY_*` → `.env` → trousseau → session courante (NTLM Windows) → saisie |
| Environnement | `environment=` → `IZIPROXY_ENV` → nom d'hôte → IP → `local` |

### Variables d'environnement

IziProxy ne lit que ces variables :

| Variable | Rôle |
|---|---|
| `IZIPROXY_USERNAME`, `IZIPROXY_PASSWORD`, `IZIPROXY_DOMAIN` | identifiants du proxy (aussi lus dans un fichier `.env`) |
| `IZIPROXY_ENV` | force l'environnement (`local`, `dev`, `prod` ou un alias : `production`, `staging`...) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (ou en minuscules) | proxy déclaré par le système, comme pour curl ou pip |

`install()` et `set_environment_variables()` écrivent `HTTP_PROXY`,
`HTTPS_PROXY` et `NO_PROXY` (majuscules et minuscules, car curl ne lit que
les minuscules) et les restaurent à la fin.

### Identifiants

Ne stockez pas les mots de passe dans le fichier de configuration.

```bash
IZIPROXY_USERNAME=mon_utilisateur
IZIPROXY_PASSWORD=mon_mot_de_passe
IZIPROXY_DOMAIN=mon_domaine          # NTLM
```

Ces variables peuvent aussi être placées dans un fichier `.env` (répertoire
courant, `~/.config/.env` ou `~/.env`). Les identifiants saisis
interactivement sont enregistrés dans le trousseau du système ;
`proxy.reset_credentials()` les supprime (par exemple après un changement de
mot de passe).

## 🔐 Authentification NTLM

```bash
pip install iziproxy[ntlm]
```

- Le schéma (NTLM ou Negotiate) est choisi d'après la réponse du proxy.
- Sous Windows, sans mot de passe fourni, la session Windows courante est utilisée.
- HTTP et HTTPS (tunnel CONNECT) sont pris en charge, avec vérification des
  certificats, timeouts, redirections, cookies, compression et streaming.
- Des identifiants refusés lèvent `iziproxy.NtlmAuthenticationError`.
- `get_proxy_dict()` et `set_environment_variables()` ne peuvent pas porter
  une authentification NTLM : utilisez `create_session()` ou `patch_requests()`
  en Python, et le proxy local ci-dessous pour les outils externes.

## 🔁 Proxy local pour pip, git, curl, conda...

Ces outils ne lisent que `HTTP(S)_PROXY` et ne savent pas s'authentifier en
NTLM. IziProxy peut démarrer un petit proxy sur `127.0.0.1` (comme cntlm ou
px) qui s'authentifie à leur place :

```python
import os
import subprocess
from iziproxy import IziProxy

proxy = IziProxy()

# Variables d'environnement pointant vers le proxy local (démarré au besoin)
proxy.set_environment_variables(local_proxy=True)
subprocess.run(["pip", "install", "paquet"], check=True)
subprocess.run(["git", "clone", "https://github.com/org/depot.git"], check=True)
proxy.clear_environment_variables()   # restaure les variables et arrête le proxy local

# Ou en gérant le proxy local soi-même
with proxy.start_local_proxy(port=3128) as local:
    print(local.url)                  # http://127.0.0.1:3128
    env = dict(os.environ, HTTP_PROXY=local.url, HTTPS_PROXY=local.url)
    subprocess.run(["curl", "https://example.com"], env=env, check=True)
```

- Requêtes HTTP en forme absolue et tunnels `CONNECT` (HTTPS : le trafic
  chiffré n'est pas déchiffré, les certificats restent vérifiés par l'outil).
- Chaque URL suit la même route que `create_session()` : exclusions, PAC,
  connexion directe.
- Authentification amont NTLM / Negotiate (session Windows courante ou
  identifiants) ou Basic ; les identifiants ne sont jamais envoyés au site cible.
- Les identifiants sont recherchés au démarrage (une éventuelle saisie a lieu à
  ce moment-là, pas pendant une requête).
- Erreurs renvoyées au client : `502` (proxy injoignable, identifiants
  refusés), `504` (délai dépassé), `407` relayé si le proxy amont refuse.
- Le proxy local n'écoute que sur la boucle locale et n'exige aucune
  authentification : sur une machine partagée, les autres utilisateurs
  locaux pourraient s'en servir.

## 🧪 Développement

```bash
pip install -e .[dev]
pytest
```

Les tests d'intégration démarrent un vrai proxy local (sans authentification,
Basic, NTLM et Negotiate) et des serveurs HTTP/HTTPS : aucun accès réseau
externe n'est nécessaire.

## 📄 Licence

MIT. Voir [LICENSE](LICENSE).
