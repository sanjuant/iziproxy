Utilisation
===========

Création
--------

.. code-block:: python

   from iziproxy import IziProxy

   proxy = IziProxy()                       # tout est détecté
   proxy = IziProxy(environment="prod")     # environnement forcé
   proxy = IziProxy(proxy_url="http://proxy.corp:8080", username="u", password="p")

La création est instantanée : le proxy et l'authentification ne sont
déterminés qu'à la première utilisation.

Intégration avec requests
-------------------------

Session préconfigurée (recommandé)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   session = proxy.create_session()
   session.get("https://example.com")

   # ou une session existante (les réglages de nouvelles tentatives sont conservés)
   proxy.configure_session(my_session)

Le proxy est choisi **pour chaque requête** : un hôte exclu ou déclaré
``DIRECT`` par le PAC est contacté directement. C'est aussi la seule méthode
qui prend en charge NTLM.

Dictionnaire de proxys
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   requests.get(url, proxies=proxy.get_proxy_dict(url))

Les identifiants Basic sont inclus (encodés) dans les URLs. Passer l'URL
cible permet de tenir compte des exclusions et du PAC.

Variables d'environnement
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   proxy.set_environment_variables()   # HTTP(S)_PROXY, NO_PROXY
   subprocess.run(["pip", "install", "paquet"])
   proxy.clear_environment_variables() # restaure les valeurs précédentes

Patch global de requests
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   proxy.patch_requests()
   requests.get(url)            # passe par le proxy
   third_party_library.call()   # ses sessions requests aussi
   proxy.unpatch_requests()

   # ou, avec restauration automatique :
   with proxy:
       proxy.patch_requests()
       ...

Toutes les sessions ``requests`` créées pendant le patch sont configurées,
y compris celles de ``requests.get()`` et des bibliothèques tierces.

Informations
------------

.. code-block:: python

   proxy.environment                   # 'local', 'dev', 'prod'
   proxy.get_proxy_url()               # URL du proxy sans identifiants, ou None
   proxy.get_proxy_url("https://intranet.corp/")
   proxy.get_proxy_host(), proxy.get_proxy_port()
   proxy.requires_auth, proxy.auth_type
   proxy.get_credentials()             # (utilisateur, SecurePassword, domaine)
   print(proxy.get_proxy_config())     # mots de passe masqués

Maintenance
-----------

.. code-block:: python

   proxy.refresh()            # relancer toutes les détections
   proxy.clear_auth_cache()   # redétecter l'authentification
   proxy.reset_credentials()  # supprimer le mot de passe du trousseau
   proxy.set_debug(True)      # journaux détaillés sur stderr
