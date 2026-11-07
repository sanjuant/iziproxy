# IziProxy

Les proxys d'entreprise en une ligne de Python.

[![PyPI version](https://img.shields.io/pypi/v/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![License](https://img.shields.io/github/license/sanjuant/iziproxy.svg)](https://github.com/sanjuant/iziproxy/blob/master/LICENSE)

```python
import iziproxy

iziproxy.install()
```

Après cette ligne, `requests`, `urllib`, `httpx`, `aiohttp` et les
commandes lancées par `subprocess` (pip, git, curl…) passent le proxy de
l'entreprise, **quel qu'il soit** : sans authentification, Basic, NTLM /
Negotiate, ou décrit par un fichier PAC. Sans proxy (production, réseau
domestique), la ligne ne change rien : le même code marche partout.

## Sommaire

- [Installation](#installation)
- [Démarrage](#démarrage)
- [Si ça ne marche pas tel quel](#si-ça-ne-marche-pas-tel-quel)
- [Contrôle fin : la classe IziProxy](#contrôle-fin--la-classe-iziproxy)
- [Remplacer cntlm : un proxy local en trois lignes](#remplacer-cntlm--un-proxy-local-en-trois-lignes)
- [Configuration](#configuration)
- [Sécurité](#sécurité)
- [Développement](#développement)

## Installation

```bash
pip install iziproxy              # proxy sans authentification ou Basic
pip install "iziproxy[ntlm]"      # + NTLM / Negotiate (pyspnego)
pip install "iziproxy[pac]"       # + fichiers PAC (pypac)
pip install "iziproxy[truststore]" # + certificats vérifiés par le système (Python 3.10+)
pip install "iziproxy[all]"       # les trois
```

Python 3.8 ou plus récent. `[httpx]` et `[aiohttp]` installent ces clients
pour leurs adaptateurs dédiés.

## Démarrage

```python
import iziproxy

installation = iziproxy.install()
print(installation)
# proxy http://proxy.corp:8080 (ntlm) ; local http://127.0.0.1:53211 ; requests, urllib, environment
```

`install()` fait trois choses :

1. **Trouve le proxy** : paramètres, fichier `iziproxy.yml`, variables
   `HTTP(S)_PROXY`, réglages du système (registre Windows, macOS, GNOME,
   KDE) ou fichier PAC, évalué **pour chaque URL**.
2. **Découvre l'authentification** en interrogeant le proxy (réponse `407`)
   et trouve les identifiants. Sous Windows avec NTLM, la session ouverte
   suffit : aucun mot de passe à fournir.
3. **Configure le processus** :

   | Client | Mécanisme |
   |---|---|
   | `requests` (y compris dans les bibliothèques tierces) | patché |
   | `urllib.request.urlopen()` | opener global |
   | `httpx`, `aiohttp` (`trust_env=True`), gRPC… | variables `HTTP(S)_PROXY` |
   | pip, git, curl, conda… lancés par `subprocess` | variables héritées |

   Les variables pointent vers un **proxy local** (`127.0.0.1`) qui
   s'authentifie à la place des outils : aucun mot de passe dans
   l'environnement, et NTLM ou un PAC fonctionnent même pour curl.

Tout est réversible : `iziproxy.uninstall()`, un bloc
`with iziproxy.install():`, ou simplement la fin du programme.

## Si ça ne marche pas tel quel

Ajoutez seulement ce qui manque :

| Situation | Solution |
|---|---|
| Le proxy n'est pas détecté | `install(proxy_url="proxy.corp:8080")` ou `install(pac_url="http://wpad/proxy.pac")` |
| Les identifiants ne sont pas trouvés | `install(username="jdupont", password="…", domain="CORP")`, variables `IZIPROXY_USERNAME` / `IZIPROXY_PASSWORD`, ou la saisie interactive (mémorisée dans le trousseau) |
| Aucune saisie possible (service, CI) | `install(interactive=False)` |
| Des hôtes doivent rester en direct | `install(no_proxy=["*.corp.local", "10.0.0.0/8"])` |
| Le type d'authentification est mal détecté | `install(auth_type="ntlm")` ou `"basic"` |
| Réglages différents en local / dev / prod | fichier `iziproxy.yml` ([Configuration](#configuration)) |
| Certificat du proxy `https://` ou du PAC refusé | `pip install "iziproxy[truststore]"`, sinon `install(verify="/chemin/ca-entreprise.pem")` |
| Ne configurer que certains clients | `install(urllib=False, env_vars=False)` |
| Comprendre ce qui se passe | `install(debug=True)` (journaux sur stderr, mots de passe masqués) |

`install()` accepte tous les paramètres de `IziProxy(...)`.

## Contrôle fin : la classe IziProxy

`install()` utilise une instance `IziProxy` (`iziproxy.current().proxy`).
Créez la vôtre pour configurer un client précis sans toucher au reste du
processus :

```python
from iziproxy import IziProxy

proxy = IziProxy()                    # rien n'est contacté avant la première requête

session = proxy.create_session()      # requests : PAC, exclusions et NTLM gérés
session.get("https://example.com")

with proxy.httpx_client() as client:  # httpx
    client.get("https://example.com")

proxy.get_proxy_url("https://intranet.corp/")   # 'http://proxy.corp:8080' ou None (direct)
proxy.requires_auth, proxy.auth_type            # True, 'ntlm'
```

| Client | Méthode |
|---|---|
| requests | `create_session()`, `configure_session(s)`, `patch_requests()` |
| httpx | `httpx_client()`, `httpx_async_client()` |
| aiohttp | `aiohttp_session()` |
| urllib3 | `urllib3_pool_manager()` |
| urllib.request | `urllib_opener()`, `install_urllib_opener()` |
| http.client | `http_connection(url)` |
| websockets | `connect(uri, proxy=proxy.websocket_proxy(uri))` |
| gRPC | `grpc_channel_options(target)` |
| Selenium / Playwright | `selenium_proxy()`, `playwright_proxy()` |
| pip, git, curl… | `set_environment_variables(local_proxy=True)` |
| tout autre client | `proxy_for(url)` |

Détails et limites de chaque client : page « Autres clients HTTP » de la
documentation.

Pour pip, git, curl… lancés **hors** de Python, voir la section suivante.

## Remplacer cntlm : un proxy local en trois lignes

IziProxy peut faire tourner sur votre poste un proxy local, comme cntlm ou
px : il écoute sur `127.0.0.1:3128`, s'authentifie auprès du proxy
d'entreprise (NTLM / Negotiate avec la session Windows, Basic) et applique le
PAC et les exclusions. Les outils n'ont besoin d'aucun identifiant, seulement
de l'adresse du proxy local.

```python
from iziproxy import IziProxy

local = IziProxy().start_local_proxy()   # http://127.0.0.1:3128
print("Proxy local :", local.url)
local.serve_forever()                    # Ctrl+C pour arrêter
```

- **Port** : `3128` par défaut (celui de cntlm). Un autre port :
  `start_local_proxy(port=8888)` ; n'importe quel port libre : `port=0`
  (lisez-le ensuite dans `local.port`). Si le port est déjà pris (cntlm
  encore lancé, seconde instance), `start_local_proxy()` lève `OSError`.
- **Jeton** : le proxy local exige un jeton (voir [Sécurité](#sécurité)),
  inclus dans `local.url` : `http://iziproxy:<jeton>@127.0.0.1:3128`. Il est
  aléatoire à chaque démarrage ; pour configurer vos outils une fois pour
  toutes, fixez-le : `start_local_proxy(token="un-jeton-long-et-secret")`.

Configurez ensuite les outils avec `local.url`, par exemple :

```bash
git config --global http.proxy http://iziproxy:un-jeton-long-et-secret@127.0.0.1:3128
export HTTPS_PROXY=http://iziproxy:un-jeton-long-et-secret@127.0.0.1:3128
```

(PowerShell : `$env:HTTPS_PROXY = "http://iziproxy:…@127.0.0.1:3128"`.)
Script complet : [`examples/local_proxy.py`](examples/local_proxy.py).

Depuis un programme Python, le proxy peut aussi ne vivre que le temps d'un
bloc :

```python
import os, subprocess

with IziProxy().start_local_proxy() as local:
    env = dict(os.environ, HTTP_PROXY=local.url, HTTPS_PROXY=local.url)
    subprocess.run(["git", "clone", "https://github.com/org/depot.git"], env=env, check=True)
```

Le trafic HTTPS traverse le proxy local sans être déchiffré : chaque outil
vérifie toujours le certificat du site. `iziproxy.install()` démarre lui
aussi un proxy local, mais sur un port libre au hasard : il ne gêne pas un
proxy local lancé sur 3128.

## Configuration

Rien n'est obligatoire. Pour forcer un comportement, par code :

```python
proxy = IziProxy(
    proxy_url="http://proxy.corp:8080",  # ou pac_url="http://wpad/proxy.pac"
    username="jdupont", password="…", domain="CORP",
    auth_type="ntlm",                    # sinon détecté
    no_proxy="*.corp.local,<local>",
    environment="dev",                   # sinon détecté
    interactive=False,
    verify="/chemin/ca.pem",             # certificats du proxy https:// et du PAC
)
```

ou par fichier YAML, avec des réglages par environnement (`local`, `dev`,
`prod`) — `~/.config/iziproxy.yml`, `~/.iziproxy.yml` ou `./iziproxy.yml` :

```yaml
environments:
  local:
    auth_type: ntlm                 # poste Windows : session courante
  dev:
    proxy_url: "http://dev-proxy.corp:8080"
  prod:
    pac_url: "http://pac.corp/proxy.pac"

no_proxy: "<local>,*.internal.corp"

credentials:
  prompt: false                     # serveurs, CI : jamais de saisie
```

Exemple complet : [examples/config_example.yml](examples/config_example.yml).

### Qui l'emporte ?

| Élément | Ordre de priorité |
|---|---|
| Proxy | `proxy_url=` / `pac_url=` → `iziproxy.yml` → `HTTP(S)_PROXY` → réglages système → PAC système → direct |
| Authentification | `auth_type=` → `iziproxy.yml` → sondage du proxy |
| Identifiants | `username=` / `password=` → URL du proxy → `IZIPROXY_*` → `.env` → trousseau → session Windows (NTLM) → saisie |
| Environnement | `environment=` → `IZIPROXY_ENV` → nom d'hôte → adresse IP → `local` |

### Variables d'environnement lues

| Variable | Rôle |
|---|---|
| `IZIPROXY_USERNAME`, `IZIPROXY_PASSWORD`, `IZIPROXY_DOMAIN` | identifiants (aussi lus dans un fichier `.env`) |
| `IZIPROXY_ENV` | environnement : `local`, `dev`, `prod` ou un alias (`production`, `staging`…) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (ou en minuscules) | proxy déclaré, comme pour curl |

Ne mettez pas de mot de passe dans `iziproxy.yml`. Les identifiants saisis
sont enregistrés dans le trousseau du système ; `proxy.reset_credentials()`
les efface (après un changement de mot de passe, par exemple).

## Sécurité

- **Les identifiants ne vont qu'au proxy**, jamais au site visité (y compris
  après une redirection), et sont encodés en UTF-8.
- **Rien en clair dans les traces** : mots de passe masqués dans les
  journaux, `repr()` et messages d'erreur. En mémoire, `SecurePassword`
  évite les fuites accidentelles (journal, débogueur) mais ne protège pas
  contre un programme capable de lire la mémoire du processus.
- **Proxy local protégé par un jeton** : il n'écoute que sur `127.0.0.1` et
  refuse (`407`) toute connexion sans le jeton aléatoire de son URL. Sur une
  machine partagée, un autre utilisateur ne peut donc pas sortir avec votre
  identité. Exception : `selenium_proxy()` utilise un proxy local sans jeton,
  car Chrome piloté ne sait pas en envoyer.
- **Certificats vérifiés partout** : proxy `https://` et fichier PAC
  `https://` sont vérifiés (autorités du système), sans repli silencieux.
- **Méfiez-vous d'un `iziproxy.yml` inconnu** : le fichier du répertoire
  courant est lu, et il décide où part le trafic (et donc votre
  authentification). IziProxy avertit quand ce fichier définit `proxy_url`,
  `pac_url` ou `verify` ; pour une configuration personnelle, préférez
  `~/.config/iziproxy.yml`.

## Développement

```bash
pip install -e ".[dev]"
pytest
```

Les tests démarrent de vrais proxys locaux (sans authentification, Basic,
NTLM, Negotiate, en HTTP et HTTPS) et des serveurs d'origine : aucun accès
réseau externe n'est nécessaire. Voir [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. Voir [LICENSE](LICENSE).
