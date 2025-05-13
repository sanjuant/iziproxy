# IziProxy

Une bibliothèque Python pour la gestion simplifiée des proxys d'entreprise.

[![PyPI version](https://img.shields.io/pypi/v/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![License](https://img.shields.io/github/license/votrenom/iziproxy.svg)](https://github.com/votrenom/iziproxy/blob/main/LICENSE)

## Fonctionnalités

- 🔍 Détection automatique de l'environnement (local, dev, prod)
- 🌐 Détection automatique des configurations de proxy système
- 🔐 Gestion sécurisée des identifiants proxy
- 🔄 Support pour l'authentification basique et NTLM
- 📋 Compatibilité avec les fichiers PAC
- 🛠️ API simple et intuitive

## Installation

```bash
pip install iziproxy
```

Pour le support de l'authentification NTLM (recommandé pour les environnements Windows d'entreprise) :

```bash
pip install iziproxy[ntlm]
```

## Utilisation rapide

```python
from iziproxy import IziProxy

# Création avec détection automatique
proxy = IziProxy()

# Méthode 1: Obtenir une session requests préconfigurée
session = proxy.create_session()
response = session.get('https://example.com')

# Méthode 2: Utiliser comme dictionnaire de proxy standard
proxies = proxy.get_proxy_dict()
response = requests.get('https://example.com', proxies=proxies)

# Méthode 3: Patcher le module requests (monkey patching)
proxy.patch_requests()
# Désormais, toutes les requêtes requests utiliseront le proxy
import requests
response = requests.get('https://example.com')
```

## Configuration

IziProxy fonctionne sans configuration, mais vous pouvez personnaliser son comportement :

### Configuration par code

```python
from iziproxy import IziProxy

proxy = IziProxy(
    proxy_url="http://proxy.example.com:8080",
    username="user",
    password="pass",
    environment="prod"
)
```

### Configuration par fichier YAML

Créez un fichier `iziproxy.yml` dans votre répertoire courant ou dans `~/.config/` :

```yaml
environments:
  local:
    proxy_url: null
    requires_auth: false
  dev:
    proxy_url: "http://dev-proxy.example.com:8080"
    requires_auth: true
    auth_type: "basic"
  prod:
    proxy_url: "http://prod-proxy.example.com:8080"
    requires_auth: true
    auth_type: "ntlm"

credentials:
  # Section simplifiée - gestion automatique des identifiants

environment_detection:
  method: "auto"  # Options: auto, env_var, hostname, ip, ask
```

### Configuration des identifiants

Pour la sécurité, les identifiants (nom d'utilisateur, mot de passe, domaine) ne doivent pas être stockés dans le fichier de configuration. Utilisez plutôt :

#### Variables d'environnement

IziProxy recherche les variables d'environnement suivantes :

```bash
# Format recommandé
IZI_USERNAME=mon_utilisateur
IZI_PASSWORD=mon_mot_de_passe
IZI_DOMAIN=mon_domaine

# Format alternatif (rétrocompatibilité)
PROXY_USERNAME=mon_utilisateur
PROXY_PASSWORD=mon_mot_de_passe
PROXY_DOMAIN=mon_domaine
```

#### Fichier .env

Vous pouvez également définir ces variables dans un fichier `.env` :

```bash
# Identifiants pour l'authentification proxy
IZI_USERNAME=mon_utilisateur
IZI_PASSWORD=mon_mot_de_passe
IZI_DOMAIN=mon_domaine
```

Le fichier `.env` peut être placé :
- Dans le répertoire courant (`./.env`)
- Dans le répertoire de configuration utilisateur (`~/.config/.env`)
- Dans le répertoire personnel de l'utilisateur (`~/.env`)

#### Stockage sécurisé avec keyring

Si un nom d'utilisateur est défini mais que le mot de passe est manquant, IziProxy tentera de récupérer le mot de passe depuis le trousseau de clés du système (via `keyring`). 

Lorsque vous fournissez un mot de passe la première fois, il sera automatiquement enregistré dans le trousseau de clés pour les utilisations futures.

### Fonctionnalités avancées

- Intégration avec des bibliothèques tierces via monkey patching
- Support pour les wrappers d'API utilisant `requests`
- Gestion avancée des identifiants via variables d'environnement et `.env`

Consultez [la documentation complète](https://iziproxy.readthedocs.io/) pour plus de détails sur les fonctionnalités avancées.

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.
