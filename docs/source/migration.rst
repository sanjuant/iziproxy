Migration depuis CNTLM
===================

Cette section explique comment migrer d'un proxy CNTLM vers IziProxy.

Qu'est-ce que CNTLM ?
-------------------

CNTLM (Cntlm Authentication Proxy) est un proxy d'authentification populaire qui agit comme un intermédiaire entre vos applications et un proxy d'entreprise, en particulier ceux qui nécessitent une authentification NTLM. 

Bien que CNTLM soit efficace, il présente plusieurs inconvénients :

* Nécessite une installation et une configuration séparées
* Exécute un processus distinct sur votre machine
* Configuration complexe dans certains environnements
* Gestion des mots de passe moins sécurisée
* Nécessite des droits administrateur pour l'installation

Avantages d'IziProxy par rapport à CNTLM
--------------------------------------

IziProxy offre plusieurs avantages par rapport à CNTLM :

1. **Intégration native en Python** - Aucun processus ou service externe à exécuter
2. **Configuration automatique** - Détection automatique de l'environnement et du proxy
3. **Gestion sécurisée des identifiants** - Utilisation de keyring pour stocker les mots de passe
4. **Portable** - Fonctionne sur toutes les plateformes sans installation système
5. **Facile à utiliser** - API simple et intuitive
6. **Compatible avec requests** - Intégration transparente avec la bibliothèque requests

Guide de migration étape par étape
--------------------------------

Voici comment migrer de CNTLM vers IziProxy :

Étape 1 : Installer IziProxy
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Commencez par installer IziProxy avec le support NTLM :

.. code-block:: bash

   pip install iziproxy[ntlm]

Étape 2 : Récupérer les informations de CNTLM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Récupérez les informations de votre configuration CNTLM actuelle, généralement dans ``/etc/cntlm.conf`` (Linux/macOS) ou ``C:\\Program Files\\Cntlm\\cntlm.ini`` (Windows) :

* Nom d'utilisateur et domaine
* URL du proxy d'entreprise
* Port local utilisé par CNTLM

Étape 3 : Configurer IziProxy
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Créez un fichier ``iziproxy.yml`` dans votre projet ou dans ``~/.config/`` :

.. code-block:: yaml

   environments:
     # Reprenez la configuration de votre CNTLM
     dev:
       proxy_url: "http://proxy.entreprise.com:8080"  # URL du proxy d'entreprise
       requires_auth: true
       auth_type: "ntlm"
   
   credentials:
     store_method: "keyring"
     username: "DOMAIN\\utilisateur"  # Comme dans cntlm.conf
     domain: "DOMAIN"  # Si utilisé dans CNTLM
     prompt_on_missing: true

Étape 4 : Adapter votre code
^^^^^^^^^^^^^^^^^^^^^^^^^^

Remplacez les références au proxy CNTLM local par IziProxy :

Avant (avec CNTLM) :

.. code-block:: python

   import requests
   
   # Configuration pour utiliser CNTLM en local
   proxies = {
       'http': 'http://localhost:3128',
       'https': 'http://localhost:3128'
   }
   
   # Utilisation avec requests
   response = requests.get('https://example.com', proxies=proxies)

Après (avec IziProxy) :

.. code-block:: python

   from iziproxy import IziProxy
   
   # Détection et configuration automatiques
   proxy = IziProxy()
   
   # Méthode 1 : Utiliser une session
   session = proxy.create_session()
   response = session.get('https://example.com')
   
   # Méthode 2 : Utiliser un dictionnaire de proxy
   proxies = proxy.get_proxy_dict()
   response = requests.get('https://example.com', proxies=proxies)

Étape 5 : Arrêter CNTLM (optionnel)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Une fois que vous avez vérifié qu'IziProxy fonctionne correctement, vous pouvez arrêter et désinstaller CNTLM :

Sur Linux :

.. code-block:: bash

   sudo service cntlm stop
   sudo systemctl disable cntlm

Sur Windows :

1. Ouvrez les Services (services.msc)
2. Trouvez le service CNTLM
3. Arrêtez-le et définissez son démarrage sur "Manuel" ou "Désactivé"

Différences d'utilisation
-----------------------

Voici quelques différences clés à prendre en compte lors de la migration :

1. **Proxy local vs proxy distant** - CNTLM crée un proxy local, tandis qu'IziProxy communique directement avec le proxy d'entreprise
2. **Configuration globale vs par application** - CNTLM affecte toutes les applications, tandis qu'IziProxy est spécifique à votre application Python
3. **Variables d'environnement** - Si vous avez d'autres applications qui utilisent les variables d'environnement, utilisez `proxy.set_environment_variables()`

Compatibilité avec les applications existantes
-------------------------------------------

Pour les applications qui ne peuvent pas être modifiées pour utiliser IziProxy directement, vous pouvez :

1. Utiliser ``proxy.set_environment_variables()`` pour configurer les variables d'environnement HTTP_PROXY, etc.
2. Développer un petit script qui démarre votre application avec les variables d'environnement correctement configurées
