Configuration
=============

IziProxy offre plusieurs façons de le configurer pour répondre à vos besoins spécifiques.

Configuration par code
---------------------

Le moyen le plus direct de configurer IziProxy est via les paramètres du constructeur :

.. code-block:: python

   from iziproxy import IziProxy
   
   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",  # URL du proxy (prioritaire)
       pac_url="http://internal.example.com/proxy.pac",  # URL du fichier PAC
       environment="prod",  # Forcer un environnement spécifique
       username="user",  # Nom d'utilisateur pour l'authentification
       password="pass",  # Mot de passe pour l'authentification
       domain="DOMAIN",  # Domaine pour l'authentification NTLM
       debug=True  # Activer les logs détaillés
   )

Tous les paramètres sont optionnels. Si vous ne spécifiez pas de proxy_url, IziProxy tentera de détecter automatiquement la configuration de proxy appropriée.

Configuration par fichier YAML
----------------------------

Pour une configuration plus flexible et réutilisable, vous pouvez utiliser un fichier YAML :

.. code-block:: python

   proxy = IziProxy(config_path="/chemin/vers/config.yml")

Le fichier de configuration YAML doit être structuré comme suit :

.. code-block:: yaml

   # Configuration des environnements
   environments:
     local:
       proxy_url: null  # Pas de proxy pour l'environnement local
       requires_auth: false
     
     dev:
       proxy_url: "http://dev-proxy.example.com:8080"
       requires_auth: true
       auth_type: "basic"  # Authentification basique
     
     prod:
       proxy_url: "http://prod-proxy.example.com:8080"
       requires_auth: true
       auth_type: "ntlm"  # Authentification NTLM
   
   # Configuration de la détection d'environnement
   environment_detection:
     method: "auto"  # auto, env_var, hostname, ip, ask
     
     # Patterns pour la détection par nom d'hôte
     hostname_patterns:
       local: ["local", "laptop", "desktop", "dev-pc"]
       dev: ["dev", "staging", "test", "preprod"]
       prod: ["prod", "production"]
     
     # Expressions régulières pour la détection par nom d'hôte
     hostname_regex:
       local: ["^laptop-\\w+$", "^pc-\\w+$", "^desktop-\\w+$"]
       dev: ["^dev\\d*-", "^staging\\d*-", "^test\\d*-"]
       prod: ["^prod\\d*-", "^production\\d*-"]
     
     # Plages IP pour la détection par adresse IP
     ip_ranges:
       local: ["192.168.0.0/24", "127.0.0.1-127.0.0.255"]
       dev: ["10.0.0.0/16"]
       prod: ["172.16.0.0/16"]
   
   # Configuration de la détection de proxy système
   system_proxy:
     use_system_proxy: true  # Utiliser le proxy système si pas de proxy explicite
     detect_pac: true  # Détecter et utiliser les fichiers PAC

Emplacement du fichier de configuration
--------------------------------------

Si vous ne spécifiez pas de chemin de configuration, IziProxy recherchera automatiquement un fichier ``iziproxy.yml`` ou ``iziproxy.yaml`` dans les emplacements suivants (dans cet ordre) :

1. Le répertoire courant : ``./iziproxy.yml``
2. Le répertoire de configuration utilisateur : ``~/.config/iziproxy.yml``
3. Le répertoire personnel de l'utilisateur : ``~/.iziproxy.yml``

Configuration via variables d'environnement et fichier .env
-----------------------------------------

Pour des raisons de sécurité, les identifiants (nom d'utilisateur, mot de passe, domaine) doivent être configurés via des variables d'environnement ou un fichier .env plutôt que dans le fichier de configuration YAML.

1. Variables d'environnement
^^^^^^^^^^^^^^^^^^^^^^^^^^

IziProxy recherche les variables d'environnement suivantes (en majuscules et minuscules) :

* Format recommandé :
  * ``IZI_USERNAME`` - Nom d'utilisateur pour l'authentification proxy
  * ``IZI_PASSWORD`` - Mot de passe pour l'authentification proxy
  * ``IZI_DOMAIN`` - Domaine pour l'authentification NTLM

* Format alternatif (rétrocompatibilité) :
  * ``PROXY_USERNAME`` - Nom d'utilisateur pour l'authentification proxy
  * ``PROXY_PASSWORD`` - Mot de passe pour l'authentification proxy
  * ``PROXY_DOMAIN`` - Domaine pour l'authentification NTLM

Autres variables d'environnement supportées :

* ``IZIPROXY_ENV`` ou ``ENV`` - Pour forcer un environnement spécifique (``local``, ``dev``, ``prod``)
* Les variables standard de proxy : ``HTTP_PROXY``, ``HTTPS_PROXY``, ``NO_PROXY``

2. Fichier .env
^^^^^^^^^^^^^

Vous pouvez également définir ces variables dans un fichier ``.env`` :

.. code-block:: bash

    # Identifiants pour l'authentification proxy
    IZI_USERNAME=mon_utilisateur
    IZI_PASSWORD=mon_mot_de_passe
    IZI_DOMAIN=mon_domaine

Le fichier ``.env`` est recherché dans les emplacements suivants (dans cet ordre) :

* Dans le répertoire courant (``./.env``)
* Dans le répertoire de configuration utilisateur (``~/.config/.env``)
* Dans le répertoire personnel de l'utilisateur (``~/.env``)

Options de configuration détaillées
---------------------------------

Environnements
^^^^^^^^^^^^^

IziProxy supporte différents environnements d'exécution, chacun pouvant avoir sa propre configuration de proxy :

* ``local`` - Environnement de développement local (souvent sans proxy)
* ``dev`` - Environnement de développement/test
* ``prod`` - Environnement de production

Détection d'environnement
^^^^^^^^^^^^^^^^^^^^^^^^

IziProxy peut détecter automatiquement l'environnement actuel en utilisant différentes méthodes :

* ``auto`` - Utilise toutes les méthodes dans l'ordre (par défaut)
* ``env_var`` - Utilise les variables d'environnement
* ``hostname`` - Détecte en fonction du nom d'hôte de la machine
* ``ip`` - Détecte en fonction de l'adresse IP
* ``ask`` - Demande interactivement à l'utilisateur

Authentification
^^^^^^^^^^^^^^

IziProxy supporte deux types d'authentification proxy :

* ``basic`` - Authentification HTTP basique
* ``ntlm`` - Authentification NTLM (Windows)

Stockage des identifiants
^^^^^^^^^^^^^^^^^^^^^^^^

Les identifiants sont gérés selon l'ordre de priorité suivant :

1. Variables d'environnement - Définies dans le système ou via processus parent
2. Fichier .env - Stockés dans un fichier séparé non inclus dans le contrôle de version
3. Trousseau système (keyring) - Stockage sécurisé intégré au système d'exploitation
4. Demande interactive - Si aucune des méthodes ci-dessus n'a fourni les identifiants

Lorsque vous fournissez un mot de passe via une demande interactive ou des variables d'environnement, il est automatiquement enregistré dans le trousseau de clés du système pour les utilisations futures, évitant ainsi d'avoir à le spécifier à chaque fois.
