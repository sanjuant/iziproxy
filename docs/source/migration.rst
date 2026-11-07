Migration
=========

Depuis IziProxy 0.6
-------------------

La version 0.7 réécrit le cœur de la bibliothèque. Changements visibles :

* NTLM repose sur ``pyspnego`` au lieu de ``ntlm-auth`` / ``pycryptodomex``
  (``pip install iziproxy[ntlm]``) ; sous Windows la session courante est
  utilisée sans mot de passe.
* Les fichiers PAC nécessitent l'option ``pac`` (``pip install iziproxy[pac]``).
* Python 3.8 minimum.
* ``patch_requests()`` configure toutes les sessions créées ensuite (et plus
  seulement ``requests.get`` & co.) ; ``with proxy:`` annule le patch.
* ``clear_environment_variables()`` restaure les valeurs d'avant
  ``set_environment_variables()`` au lieu de tout supprimer.
* ``get_proxy_config()`` / ``get_proxy_dict()`` acceptent une URL cible et ne
  gardent plus de cache figé : PAC et exclusions sont appliqués par URL.
* Les identifiants Basic ne sont plus envoyés via ``session.auth`` (ils
  atteignaient le site cible en HTTPS) mais dans l'URL du proxy.
* Les journaux ne sont plus écrits sur stdout par défaut ; ``debug=True``
  écrit sur stderr.
* Nouveaux paramètres : ``auth_type``, ``no_proxy``, ``interactive`` ;
  nouvelles méthodes et propriétés : ``get_proxy_url()``, ``environment``,
  ``requires_auth``, ``auth_type``, ``reset_credentials()``.
* Variables d'environnement réduites au strict nécessaire :
  ``IZIPROXY_USERNAME`` / ``IZIPROXY_PASSWORD`` / ``IZIPROXY_DOMAIN``
  remplacent ``IZI_*`` et ``PROXY_*`` ; seule ``IZIPROXY_ENV`` désigne
  l'environnement (``ENV``, ``APP_ENV``, ``ENVIRONMENT``, ``STAGE``... et
  l'option ``environment_detection.env_var_name`` ont disparu) ;
  ``ALL_PROXY`` n'est plus lu.
* Un PAC en ``https://`` dont le certificat est refusé n'est plus
  retéléchargé sans vérification : il est ignoré. Option ``verify`` (et clé
  YAML ``verify``) pour fournir une autorité ; ``iziproxy[truststore]`` pour
  s'appuyer sur le magasin du système.
* Les proxys ``https://`` sont joints en TLS partout (NTLM, proxy local,
  urllib, websockets) et leur certificat suit ``verify`` d'IziProxy.
* ``environment=`` accepte les alias (``"production"``) et lève
  ``ValueError`` pour une valeur inconnue.
* Supprimés : ``NtlmProxyManager`` (utilisez ``IziProxy(auth_type="ntlm")``),
  le paramètre ``workstation`` de ``NtlmProxyAdapter``,
  ``get_current_environment()`` (propriété ``environment``) et la lecture
  de l'ancienne entrée ``username`` du trousseau.

Depuis CNTLM
------------

Cette section explique comment migrer d'un proxy CNTLM vers IziProxy.

Qu'est-ce que CNTLM ?
^^^^^^^^^^^^^^^^^^^^^

CNTLM (Cntlm Authentication Proxy) est un proxy d'authentification populaire qui agit comme un intermédiaire entre vos applications et un proxy d'entreprise, en particulier ceux qui nécessitent une authentification NTLM. 

Bien que CNTLM soit efficace, il présente plusieurs inconvénients :

* Nécessite une installation et une configuration séparées
* Exécute un processus distinct sur votre machine
* Configuration complexe dans certains environnements
* Gestion des mots de passe moins sécurisée
* Nécessite des droits administrateur pour l'installation

Avantages d'IziProxy par rapport à CNTLM
----------------------------------------

IziProxy offre plusieurs avantages par rapport à CNTLM :

1. **Intégration native en Python** - Aucun processus ou service externe à exécuter
2. **Configuration automatique** - Détection automatique de l'environnement et du proxy
3. **Gestion sécurisée des identifiants** - Utilisation de keyring pour stocker les mots de passe
4. **Portable** - Fonctionne sur toutes les plateformes sans installation système
5. **Facile à utiliser** - API simple et intuitive
6. **Compatible avec requests** - Intégration transparente avec la bibliothèque requests

Guide de migration étape par étape
----------------------------------

Voici comment migrer de CNTLM vers IziProxy :

Étape 1 : Installer IziProxy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Commencez par installer IziProxy avec le support NTLM :

.. code-block:: bash

   pip install iziproxy[ntlm]

Étape 2 : Récupérer les informations de CNTLM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Récupérez les informations de votre configuration CNTLM actuelle, généralement dans ``/etc/cntlm.conf`` (Linux/macOS) ou ``C:\\Program Files\\Cntlm\\cntlm.ini`` (Windows) :

* Nom d'utilisateur et domaine
* URL du proxy d'entreprise
* Port local utilisé par CNTLM

Étape 3 : Configurer IziProxy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Créez un fichier ``iziproxy.yml`` dans votre projet ou dans ``~/.config/`` :

.. code-block:: yaml

   environments:
     # Reprenez la configuration de votre CNTLM
     dev:
       proxy_url: "http://proxy.entreprise.com:8080"  # URL du proxy d'entreprise
       requires_auth: true
       auth_type: "ntlm"
   
Le mot de passe n'a pas à figurer dans la configuration : sous Windows la
session courante est utilisée ; ailleurs il est lu depuis ``IZIPROXY_PASSWORD``,
le fichier ``.env`` ou le trousseau, ou demandé une seule fois.

Étape 4 : Adapter votre code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
-------------------------

Voici quelques différences clés à prendre en compte lors de la migration :

1. **Proxy local vs proxy distant** - CNTLM crée un proxy local, tandis qu'IziProxy communique directement avec le proxy d'entreprise
2. **Configuration globale vs par application** - CNTLM affecte toutes les applications, tandis qu'IziProxy est spécifique à votre application Python
3. **Variables d'environnement** - ``proxy.set_environment_variables()`` seul ne peut pas transmettre une authentification NTLM aux outils externes ; ``proxy.set_environment_variables(local_proxy=True)`` démarre un proxy local qui joue le rôle de CNTLM pour eux

Compatibilité avec les applications existantes
----------------------------------------------

Pour les applications qui ne peuvent pas être modifiées pour utiliser IziProxy directement, vous pouvez :

1. Utiliser ``proxy.set_environment_variables(local_proxy=True)`` pour configurer les variables d'environnement HTTP_PROXY, etc. vers un proxy local qui gère NTLM et le PAC
2. Développer un petit script qui démarre votre application avec les variables d'environnement correctement configurées
