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
- [Remplacer cntlm](#remplacer-cntlm)
- [Configuration](#configuration)
- [Sécurité](#sécurité)
- [Développement](#développement)

## Installation

```bash
pip install iziproxy              # proxy sans authentification ou Basic
pip install "iziproxy[ntlm]"      # + NTLM / Negotiate (pyspnego)
pip install "iziproxy[pac]"       # + fichiers PAC (pypac)
pip install "iziproxy[all]"       # les deux
```

Python 3.11 ou plus récent. `truststore` est toujours installé :
`install()` fait vérifier les certificats par le magasin du système, où se
trouve l'autorité d'un proxy d'entreprise qui inspecte TLS (absente de
certifi). L'option `[truststore]` reste acceptée mais n'ajoute plus rien. `[httpx]` et `[aiohttp]` installent ces clients
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

   Les sous-processus reçoivent aussi les **autorités de certification du
   système** et, sous Windows, git vérifie la révocation « au mieux » :
   ils passent un proxy qui inspecte le TLS (voir
   [Proxy local](#remplacer-cntlm--un-proxy-local-en-trois-lignes)).

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
| « Credentials withheld » : PAC en `http://` et proxy authentifié | `install(auth_proxies=["*.proxy.corp.com"])` (voir [Sécurité](docs/source/security.rst)) |
| Réglages différents en local / dev / prod | fichier `iziproxy.yml` ([Configuration](#configuration)) |
| `CERTIFICATE_VERIFY_FAILED` (proxy qui inspecte TLS, proxy `https://`, PAC) | Rien à faire : `install()` injecte truststore (magasin du système). Autorité absente du magasin : `install(verify="/chemin/ca-entreprise.pem")` ; désactiver l'injection : `install(truststore=False)` |
| curl / git sous Windows : `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` | Le proxy d'entreprise inspecte le TLS et Windows ne joint pas la liste de révocation de son autorité. git : réglé par `install()` ; curl : `--ssl-revoke-best-effort` ; `iziproxy setup` règle les deux pour git et curl (voir [Proxy local](#remplacer-cntlm--un-proxy-local-en-trois-lignes)) |
| Ne configurer que certains clients | `install(urllib=False, env_vars=False)` |
| Garder vos propres variables TLS des sous-processus | `install(tls_env=False)` (celles déjà définies ne sont de toute façon jamais remplacées) |
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

## Remplacer cntlm

IziProxy peut faire tourner sur votre poste un proxy local, comme cntlm ou
px : il écoute sur `127.0.0.1:3128`, s'authentifie auprès du proxy
d'entreprise (NTLM / Negotiate avec la session Windows, Basic) et applique le
PAC et les exclusions. Les outils n'ont besoin d'aucun identifiant, seulement
de l'adresse du proxy local.

Deux commandes suffisent :

```bash
iziproxy setup     # une seule fois : configure git, curl et pip
iziproxy serve     # à chaque session : le proxy local (Ctrl+C pour arrêter)
```

`iziproxy setup` affiche ce qu'il va écrire, demande confirmation (`--yes`
pour s'en passer), puis règle la configuration **utilisateur** de chaque
outil sur l'URL du proxy local `http://iziproxy:<jeton>@127.0.0.1:3128` :

| Outil | Fichier | Réglages |
|---|---|---|
| git | configuration globale (`~/.gitconfig`) | `http.proxy`, `https.proxy`, `http.proxyAuthMethod basic` ; sous Windows `http.schannelCheckRevoke best-effort` |
| curl | le fichier que curl lit (`$CURL_HOME`, `$XDG_CONFIG_HOME`, `$HOME`, puis sous Windows `%USERPROFILE%`, `%APPDATA%`) ; à défaut `%APPDATA%\_curlrc` (Windows), `~/.curlrc` | `proxy` ; sous Windows `ssl-revoke-best-effort` ; retire `proxy-user` / `-U`, `proxy-ntlm`, `proxy-negotiate`, `proxy-anyauth`, `proxy-digest`, `proxy-basic` |
| pip | `%APPDATA%\pip\pip.ini` (Windows), `~/.config/pip/pip.conf` | `proxy`, `cert` (export PEM du magasin de certificats du système) |

- **Aucun mot de passe écrit** : seul le jeton du proxy local figure dans ces
  fichiers. Il est généré une fois et gardé dans le répertoire de
  configuration d'IziProxy (`%APPDATA%\iziproxy\local-proxy-token`,
  `~/.config/iziproxy/` sous Linux, `~/Library/Application Support/iziproxy/`
  sous macOS), lisible par vous seul : `iziproxy serve` reprend toujours le
  même, la configuration des outils reste valable d'un démarrage à l'autre.
- **Retour arrière** : chaque valeur et chaque fichier modifiés sont
  sauvegardés avant l'écriture ; `iziproxy setup --undo` les restaure (un
  fichier retouché à la main depuis est d'abord copié en
  `<fichier>.iziproxy-undo.bak`). Relancer `setup` ne perd pas la sauvegarde
  d'origine.
- **Options** : `--only git,curl` limite les outils ; `--port 8888` pour un
  proxy lancé avec `iziproxy serve --port 8888` (port 3128 par défaut,
  celui de cntlm : arrêtez cntlm avant). `iziproxy serve --config
  iziproxy.yml` lit un fichier de configuration, `--debug` détaille les
  journaux.
- **Certificats** : l'export PEM pour pip est figé au moment du `setup` ;
  relancez `iziproxy setup --only pip` si une nouvelle autorité interne est
  installée.

Un autre outil (npm, conda, Docker…) se règle à la main avec la même URL :
le jeton est dans le fichier `local-proxy-token`.

### Depuis Python

Le proxy local se démarre aussi par code :

```python
from iziproxy import IziProxy

local = IziProxy().start_local_proxy()   # http://127.0.0.1:3128
print("Proxy local :", local.address)
local.serve_forever()                    # Ctrl+C pour arrêter
```

- **Port** : `3128` par défaut (celui de cntlm). Un autre port :
  `start_local_proxy(port=8888)` ; n'importe quel port libre : `port=0`
  (lisez-le ensuite dans `local.port`). Si le port est déjà pris (cntlm
  encore lancé, seconde instance), `start_local_proxy()` lève `OSError`.
- **Jeton** : le proxy local exige un jeton (voir [Sécurité](#sécurité)),
  inclus dans `local.url` : `http://iziproxy:<jeton>@127.0.0.1:3128`. Il est
  aléatoire à chaque démarrage, sauf si vous le fixez :
  `start_local_proxy(token="un-jeton-long-et-secret")`.

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

**Lire la sortie de `curl -v`.** `CONNECT: no ALPN negotiated` n'est pas
une erreur : la connexion vers le proxy local est en HTTP clair, il n'y a
pas d'ALPN à négocier. Si `HTTP/1.1 200 Connection established` suit, le
proxy local et le proxy d'entreprise ont fait leur travail ; une erreur
après cette ligne vient de la connexion TLS entre l'outil et le site.

**Proxy d'entreprise qui inspecte le TLS.** Le proxy présente alors des
certificats signés par l'autorité interne, installée dans le magasin du
système. Après `iziproxy.install()` (ou `set_environment_variables()`), les
outils lancés par `subprocess` en tiennent compte **sans rien faire** :

- `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE` et
  `NODE_EXTRA_CA_CERTS` désignent un export PEM des autorités du système
  (Windows : magasins `ROOT` et `CA` ; macOS : trousseaux système ; plus les
  autorités de certifi), rafraîchi chaque jour dans le cache de
  l'utilisateur (`%LOCALAPPDATA%\iziproxy\ca-bundle.pem`,
  `~/Library/Caches/iziproxy`). Sous Linux, c'est le fichier de la
  distribution. Avec `verify="/chemin/ca.pem"`, ce fichier est utilisé à la
  place ; avec `verify=False`, aucune de ces variables n'est définie ;
- sous Windows, git (moteur schannel) vérifie la révocation et échouerait
  avec `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` si la liste de révocation
  de l'autorité interne est injoignable : il reçoit
  `http.schannelCheckRevoke=best-effort` par `GIT_CONFIG_COUNT` /
  `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`, sans toucher à votre
  `.gitconfig`. La vérification reste active quand la liste répond.

Ces variables visent les sous-processus : dans votre programme, les
sessions `requests` configurées par IziProxy continuent de vérifier les
certificats avec le magasin du système en direct (truststore), sans l'export
PEM du magasin. Seul cet export est ignoré : un fichier ou répertoire passé
par `verify="/chemin"`, ou une valeur de `REQUESTS_CA_BUNDLE` ou
`CURL_CA_BUNDLE` que vous aviez définie, reste appliqué.

Une variable que vous avez déjà définie n'est jamais remplacée ;
`uninstall()` restaure exactement les valeurs d'avant ; `install(tls_env=False)`
désactive le tout. Si l'export échoue, un avertissement est journalisé et
le reste de l'installation se fait normalement.

`iziproxy setup` écrit ces réglages dans la configuration de git et de curl.

curl (schannel) n'a pas de variable d'environnement pour la révocation :
ajoutez `--ssl-revoke-best-effort` (ou la ligne `ssl-revoke-best-effort`
dans votre `_curlrc`). Hors `install()`, par exemple avec un proxy local
lancé à part, réglez git vous-même :

```bash
curl --ssl-revoke-best-effort -x "$HTTPS_PROXY" https://pypi.org/simple/
git config --global http.schannelCheckRevoke best-effort
```

Python ne vérifie pas la révocation, mais doit faire confiance à l'autorité
interne : `install()` s'en charge (truststore, magasin du système).

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
