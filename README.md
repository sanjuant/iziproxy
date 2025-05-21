# IziProxy

Une bibliothèque Python pour la gestion simplifiée des proxys d'entreprise.

[![PyPI version](https://img.shields.io/pypi/v/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/iziproxy.svg)](https://pypi.org/project/iziproxy/)
[![License](https://img.shields.io/github/license/sanjuant/iziproxy.svg)](https://github.com/sanjuant/iziproxy/blob/main/LICENSE)

## 🚀 Fonctionnalités

- 🔍 **Détection intelligente** - Reconnaissance automatique de l'environnement (local, dev, prod)
- 🌐 **Proxy système** - Détection automatique des configurations de proxy système et support des fichiers PAC
- 🔐 **Gestion sécurisée** - Stockage des identifiants via keyring, variables d'environnement et fichiers .env
- 🔄 **Support complet** - Compatible avec l'authentification basique et NTLM pour les proxys d'entreprise
- 🛠️ **API flexible** - Multiples façons d'intégrer le proxy dans vos applications Python
- 🔌 **Intégration transparente** - Patching dynamique du module requests pour les applications existantes

## 📦 Installation

Installation standard :
```bash
pip install iziproxy
```

Avec support NTLM (recommandé pour les environnements Windows d'entreprise) :
```bash
pip install iziproxy[ntlm]
```

Avec outils de développement :
```bash
pip install iziproxy[dev]
```

## 🚦 Utilisation rapide

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

# Méthode 3: Configurer les variables d'environnement
proxy.set_environment_variables()
# Les bibliothèques qui respectent les variables d'environnement utiliseront le proxy
# N'oubliez pas de nettoyer après utilisation avec proxy.clear_environment_variables()

# Méthode 4: Patcher le module requests (monkey patching)
proxy.patch_requests()
# Désormais, toutes les requêtes requests utiliseront le proxy
import requests
response = requests.get('https://example.com')
# Pour restaurer le comportement d'origine: proxy.unpatch_requests()
```

## ⚙️ Configuration

IziProxy fonctionne sans configuration, mais vous pouvez personnaliser son comportement :

### Configuration par code

```python
from iziproxy import IziProxy

proxy = IziProxy(
    proxy_url="http://proxy.example.com:8080",  # URL spécifique du proxy
    pac_url="http://pac.example.com/proxy.pac", # URL d'un fichier PAC
    username="user",                            # Nom d'utilisateur
    password="pass",                            # Mot de passe
    domain="DOMAIN",                            # Domaine (pour NTLM)
    environment="prod",                         # Forcer l'environnement
    debug=True                                  # Activer les logs détaillés
)
```

### Configuration par fichier YAML

Créez un fichier `iziproxy.yml` dans votre répertoire courant ou dans `~/.config/` :

```yaml
environments:
  local:
    proxy_url: "http://proxy.example.com:8080"
    requires_auth: true
    auth_type: "ntlm"                     # Authentification NTLM en local (poste Windows)
  dev:
    proxy_url: "http://dev-proxy.example.com:8080"
    requires_auth: true
    auth_type: "basic"                    # Authentification basique
  prod:
    proxy_url: "http://prod-proxy.example.com:8080"
    requires_auth: false                  # Souvent pas d'authentification en prod (réseau sécurisé)

environment_detection:
  method: "auto"                          # Méthodes: auto, env_var, hostname, ip, ask
  hostname_patterns:                      # Patterns pour la détection par hostname
    dev: ["dev-", "-dev", "development"]
    prod: ["prod-", "-prod", "production"]
  hostname_regex:                         # Expressions régulières pour la détection par nom d'hôte
    local: ["^laptop-\\w+$", "^pc-\\w+$", "^desktop-\\w+$"]
    dev: ["^dev\\d*-", "^staging\\d*-", "^test\\d*-"]
    prod: ["^prod\\d*-", "^production\\d*-"]
  ip_ranges:                              # Plages IP pour la détection
    dev: ["10.0.0.0/8"]
    prod: ["192.168.0.0/16"]
  env_var_name: "APP_ENV"                 # Variable d'environnement pour la détection

system_proxy:
  detect_pac: true                        # Détecter les fichiers PAC
  detect_env_vars: true                   # Détecter les variables d'environnement
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

## 🧠 Fonctionnalités avancées

### Authentification NTLM

L'authentification NTLM est souvent utilisée dans les environnements Windows d'entreprise et nécessite une configuration spécifique :

```python
# Installation avec le support NTLM
# pip install iziproxy[ntlm]

from iziproxy import IziProxy

# Configuration explicite pour NTLM
proxy = IziProxy(
    proxy_url="http://proxy.example.com:8080",
    username="utilisateur",
    password="mot_de_passe",
    domain="DOMAIN"  # Domaine Windows requis pour NTLM
)

# Le type d'authentification est détecté automatiquement depuis la configuration
session = proxy.create_session()
```

### Détection d'environnement

IziProxy peut automatiquement détecter l'environnement d'exécution :

```python
from iziproxy import IziProxy

proxy = IziProxy()
env = proxy.get_current_environment()  # 'local', 'dev', 'prod'
print(f"Environnement détecté : {env}")

# Forcer un rafraîchissement de toutes les détections
proxy.refresh()
```

### Récupération des informations de proxy

```python
from iziproxy import IziProxy

proxy = IziProxy()

# Obtenir l'hôte et le port du proxy
host = proxy.get_proxy_host()
port = proxy.get_proxy_port()
print(f"Proxy : {host}:{port}")

# Obtenir le dictionnaire complet
proxy_dict = proxy.get_proxy_dict()
print(f"Configuration complète : {proxy_dict}")
```

### Intégration avec des bibliothèques tierces

L'une des fonctionnalités les plus puissantes d'IziProxy est sa capacité à s'intégrer avec des bibliothèques tierces via le monkey patching :

```python
from iziproxy import IziProxy

# Patch global du module requests
IziProxy().patch_requests()

# À partir de maintenant, toutes les bibliothèques utilisant requests bénéficieront
# automatiquement de la configuration proxy, sans modification du code source
import requests
import pandas as pd
import boto3
import any_library_using_requests

# Pour restaurer le comportement d'origine
IziProxy().unpatch_requests()
```

### Gestion du cache

IziProxy met en cache les détections pour optimiser les performances. Vous pouvez contrôler ce comportement :

```python
from iziproxy import IziProxy

proxy = IziProxy()

# Obtenir une configuration spécifique pour une URL donnée (peut utiliser le cache)
config = proxy.get_proxy_config(url="https://api.example.com")

# Forcer un rafraîchissement du cache
fresh_config = proxy.get_proxy_config(url="https://api.example.com", force_refresh=True)
```

### Mode débogage

Pour diagnostiquer les problèmes, activez le mode débogage :

```python
from iziproxy import IziProxy

# À l'initialisation
proxy = IziProxy(debug=True)

# Ou plus tard
proxy.set_debug(enabled=True)  # Désactiver avec False
```

## 🛠️ Compatibilité

IziProxy fonctionne avec Python 3.7 et versions ultérieures, et est compatible avec :

- Windows, Linux et macOS
- Proxys standards HTTP/HTTPS
- Authentification Basic et NTLM
- Fichiers de configuration automatique de proxy (PAC)
- Proxys avec ou sans authentification

## 📚 Exemples

### Utilisation avec une API wrapper

```python
from some_api_library import ApiClient
from iziproxy import IziProxy

# Créer une session configurée
session = IziProxy().create_session()

# Utiliser cette session avec l'API
client = ApiClient(session=session)
```

### Utilisation avec un fichier PAC

```python
from iziproxy import IziProxy

# Configurer avec un fichier PAC explicite
proxy = IziProxy(pac_url="http://intranet.example.com/proxy.pac")

# Ou laisser IziProxy détecter automatiquement le fichier PAC système
proxy = IziProxy()  # Détection automatique si disponible
```

## 🔄 Migration depuis CNTLM

Si vous utilisez actuellement CNTLM, IziProxy offre une alternative 100% Python :

1. Installez IziProxy avec support NTLM: `pip install iziproxy[ntlm]`
2. Sur Windows, IziProxy détecte automatiquement votre domaine et nom d'utilisateur Windows
3. Pour les autres systèmes, configurez vos identifiants via les variables d'environnement
4. Utilisez IziProxy directement dans votre code Python sans avoir à configurer un proxy local

La détection automatique sur Windows simplifie considérablement la transition depuis CNTLM, puisque vous n'avez généralement pas besoin de configuration supplémentaire pour l'authentification.

## 🤝 Contribuer

Les contributions sont les bienvenues ! Consultez notre [guide de contribution](CONTRIBUTING.md) pour plus d'informations.

## 📚 Documentation

Une documentation complète est disponible sur Read the Docs :

[![Documentation Status](https://readthedocs.org/projects/iziproxy/badge/?version=latest)](https://iziproxy.readthedocs.io/fr/latest/?badge=latest)

Visitez [iziproxy.readthedocs.io](https://iziproxy.readthedocs.io/) pour accéder à :
- Guide de démarrage rapide
- Exemples détaillés
- Documentation complète de l'API
- Guides de migration
- Tutoriels et cas d'usage

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

Développé avec ❤️ pour simplifier la vie des développeurs dans les environnements d'entreprise.