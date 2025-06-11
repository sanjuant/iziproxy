Fonctionnalités avancées
====================

Cette section décrit les fonctionnalités avancées d'IziProxy et comment les utiliser dans des scénarios complexes.

Authentification NTLM avancée
----------------------------

Configuration manuelle de l'authentification NTLM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Dans certains cas, vous pourriez avoir besoin de configurer manuellement les paramètres NTLM :

.. code-block:: python

   from iziproxy import IziProxy
   
   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",
       username="DOMAIN\\user",  # Ou simplement "user" si vous spécifiez le domaine
       password="password",
       domain="DOMAIN",  # Optionnel si le domaine est dans le nom d'utilisateur
       environment="prod"
   )
   
   session = proxy.create_session()

Utilisation directe des classes NTLM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pour des besoins spécifiques, vous pouvez utiliser directement les classes d'authentification NTLM :

.. code-block:: python

   from iziproxy.ntlm_auth import NtlmProxyManager, is_ntlm_auth_available
   
   # Vérifier si l'authentification NTLM est disponible
   if is_ntlm_auth_available():
       # Créer un gestionnaire NTLM
       ntlm_manager = NtlmProxyManager()
       
       # Créer une session NTLM
       session = ntlm_manager.create_ntlm_proxy_session(
           proxy_host="proxy.example.com",
           proxy_port=8080,
           username="user",
           password="password",
           domain="DOMAIN",
           workstation="MYPC"  # Nom de poste optionnel
       )
       
       # Utiliser la session
       response = session.get("https://example.com")

Gestion de proxy avec PAC
------------------------

Support des fichiers PAC
^^^^^^^^^^^^^^^^^^^^^^

IziProxy peut utiliser des fichiers PAC (Proxy Auto-Configuration) pour déterminer le proxy à utiliser :

.. code-block:: python

   # Utilisation d'un fichier PAC spécifique
   proxy = IziProxy(pac_url="http://internal.example.com/proxy.pac")
   
   # La détection PAC est également activée par défaut
   # IziProxy cherchera automatiquement les fichiers PAC configurés sur le système

Tester le proxy PAC pour une URL spécifique
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Les fichiers PAC peuvent retourner différents proxys selon l'URL de destination :

.. code-block:: python

   # Pour une URL spécifique
   proxies = proxy.get_proxy_dict(url="https://example.com")
   
   # Pour une autre URL
   proxies_intranet = proxy.get_proxy_dict(url="https://intranet.example.com")

Proxy système avancé
------------------

Détection de proxy dans des environnements complexes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

IziProxy utilise plusieurs méthodes pour détecter le proxy système :

.. code-block:: python

   from iziproxy.proxy_detector import ProxyDetector
   
   # Configuration détaillée
   detector = ProxyDetector({
       "use_system_proxy": True,
       "detect_pac": True
   })
   
   # Détecter le proxy pour une URL spécifique
   proxies = detector.detect_system_proxy("https://example.com")
   
   # Forcer le rafraîchissement de la détection
   proxies = detector.detect_system_proxy(force_refresh=True)

Contourner le proxy pour certaines URLs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Vous pouvez configurer des exceptions pour certaines URLs :

.. code-block:: yaml

   # Dans iziproxy.yml
   environments:
     prod:
       proxy_url: "http://proxy.example.com:8080"
       no_proxy: "localhost,127.0.0.1,.example.com"

Ou par code :

.. code-block:: python

   from iziproxy import IziProxy
   import os
   
   # Définir NO_PROXY avant de créer l'instance
   os.environ["NO_PROXY"] = "localhost,127.0.0.1,.example.com"
   
   proxy = IziProxy()
   session = proxy.create_session()
   
   # Les requêtes vers ces domaines contourneront le proxy
   response = session.get("http://localhost:8000")

Débugger les problèmes de proxy
-----------------------------

Activer le mode de débogage
^^^^^^^^^^^^^^^^^^^^^^^^^

Pour diagnostiquer les problèmes de proxy, activez le mode débogage :

.. code-block:: python

   proxy = IziProxy(debug=True)
   
   # Ou activez-le plus tard
   proxy.set_debug(True)

Les logs détaillés seront affichés dans la console.

Effectuer un diagnostic complet
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from iziproxy import IziProxy
   
   # Créer une instance avec débogage
   proxy = IziProxy(debug=True)
   
   # Afficher les informations de diagnostic
   print(f"Environnement détecté: {proxy.get_current_environment()}")
   print(f"Configuration proxy: {proxy.get_proxy_config()}")

   # Essayer une requête de test
   try:
       session = proxy.create_session()
       response = session.get("https://httpbin.org/ip", timeout=5)
       print(f"Statut: {response.status_code}")
       print(f"Réponse: {response.text}")
   except Exception as e:
       print(f"Erreur: {e}")

   # Forcer le rafraîchissement et réessayer
   proxy.refresh()
   print(f"Configuration après refresh: {proxy.get_proxy_config()}")

Gestion sécurisée des identifiants
--------------------------------

IziProxy utilise SecurePassword pour protéger les mots de passe en mémoire :

.. code-block:: python

   from iziproxy.secure_config import SecurePassword
   
   # Créer un mot de passe sécurisé
   password = SecurePassword("mon_mot_de_passe")
   
   # Le mot de passe est masqué dans les représentations
   print(password)  # Affiche: ***********
   
   # Mais il peut être récupéré si nécessaire
   real_password = password.get_password()

Personnalisation de la détection d'environnement
---------------------------------------------

Vous pouvez personnaliser la façon dont IziProxy détecte l'environnement actuel :

.. code-block:: python

   from iziproxy.env_detector import EnvironmentDetector
   
   # Configuration personnalisée
   config = {
       "environment_detection": {
           "method": "hostname",  # Utiliser uniquement la détection par nom d'hôte
           "hostname_patterns": {
               "prod": ["prod", "prd", "production", "p-"],
               "dev": ["dev", "development", "d-"],
               "test": ["test", "tst", "t-"]
           }
       }
   }
   
   # Créer un détecteur personnalisé
   detector = EnvironmentDetector(config)
   env = detector.detect_environment()
   
   # Utiliser ce détecteur avec IziProxy
   from iziproxy import IziProxy
   proxy = IziProxy(config_path="custom_config.yml")
