Exemples d'utilisation
==================

Cette section présente des exemples d'utilisation d'IziProxy dans différents scénarios.

Exemple basique
-------------

.. code-block:: python

   from iziproxy import IziProxy
   import requests
   
   # Création d'une instance avec détection automatique
   proxy = IziProxy()
   
   # Obtenir une session configurée
   session = proxy.create_session()
   
   # Faire une requête
   response = session.get('https://httpbin.org/ip')
   print(response.json())

Utilisation avec un dictionnaire de proxy
---------------------------------------

.. code-block:: python

   from iziproxy import IziProxy
   import requests
   
   # Création d'une instance
   proxy = IziProxy()
   
   # Obtenir un dictionnaire de proxy
   proxies = proxy.get_proxy_dict()
   
   # Utiliser avec des requêtes individuelles
   response = requests.get('https://httpbin.org/get', proxies=proxies)
   print(response.json())
   
   # Ou avec une session
   session = requests.Session()
   session.proxies = proxies
   response = session.get('https://httpbin.org/headers')
   print(response.json())

Configuration explicite
---------------------

.. code-block:: python

   from iziproxy import IziProxy
   
   # Création avec configuration explicite
   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",
       username="user",
       password="pass",
       environment="dev"
   )
   
   # Toutes les requêtes utiliseront cette configuration
   session = proxy.create_session()
   response = session.get('https://example.com')

Utilisation de fichier de configuration
-------------------------------------

.. code-block:: python

   from iziproxy import IziProxy
   
   # Charger la configuration depuis un fichier
   proxy = IziProxy(config_path="/chemin/vers/config.yml")
   
   # Utiliser la configuration chargée
   session = proxy.create_session()
   response = session.get('https://example.com')

Exemple avec authentification NTLM
--------------------------------

.. code-block:: python

   from iziproxy import IziProxy
   
   # Configuration pour proxy avec NTLM
   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",
       username="DOMAIN\\user",  # Notez la double barre oblique
       password="pass",
       domain="DOMAIN"  # Peut être omis si inclus dans le nom d'utilisateur
   )
   
   # Créer une session avec authentification NTLM
   session = proxy.create_session()
   response = session.get('https://example.com')

Variables d'environnement
-----------------------

.. code-block:: python

   from iziproxy import IziProxy
   import urllib.request
   
   # Création d'une instance
   proxy = IziProxy()
   
   # Définir les variables d'environnement
   proxy.set_environment_variables()
   
   try:
       # Utiliser d'autres bibliothèques qui respectent les variables d'environnement
       response = urllib.request.urlopen('https://httpbin.org/get')
       print(response.read().decode('utf-8'))
   finally:
       # Toujours nettoyer les variables d'environnement
       proxy.clear_environment_variables()

Monkey patching
-------------

Le monkey patching permet de remplacer les méthodes du module requests standard pour que toutes les requêtes utilisent automatiquement IziProxy.

.. code-block:: python

   from iziproxy import IziProxy
   import requests
   
   # Configurer IziProxy et patcher le module requests
   proxy = IziProxy()
   proxy.patch_requests()
   
   # À partir de ce point, toutes les requêtes utiliseront automatiquement le proxy
   response = requests.get('https://httpbin.org/ip')
   print(response.json())
   
   # Restaurer requests à son état original
   proxy.unpatch_requests()

Intégration avec des wrappers d'API
---------------------------------

Un cas d'utilisation avancé est l'intégration avec des wrappers d'API tierces qui utilisent requests en interne.

.. code-block:: python

   class APIClient:
       """
       Client pour interagir avec une API tierce
       """
       def __init__(self):
           # Configuration
           self.api_key = "your-api-key"
           self.api_url = "https://api.example.com"
           
           # Obtention d'une session préconfigurée avec IziProxy
           self.session = IziProxy().create_session()
   
           # Monkey patch requests methods avec notre session
           self._patch_requests()
   
           # Important: l'API est initialisée APRÈS le monkey patching
           self.api = None
           self._initialize_api()
       
       def _initialize_api(self):
           """
           Initialise l'API tierce (qui utilisera requests en interne)
           """
           self.api = SomeThirdPartyAPI(
               self.api_url,
               self.api_key
           )
   
       def _patch_requests(self):
           """
           Remplace les méthodes du module requests par celles de notre session
           """
           import requests
           
           # Remplacer les méthodes par celles de notre session préconfigurée
           requests.get = self.session.get
           requests.post = self.session.post
           requests.put = self.session.put
           requests.delete = self.session.delete
       
       def find_resources(self, query_params):
           """
           Recherche des ressources via l'API
           """
           # L'API tierce utilise requests.get en interne, qui a été patché
           # pour utiliser notre session IziProxy
           response = self.api.find_resources(query_params)
           return response

Détection d'environnement personnalisée
-------------------------------------

.. code-block:: python

   import os
   from iziproxy import IziProxy
   
   # Définir une variable d'environnement
   os.environ['ENV'] = 'prod'
   
   # IziProxy détectera l'environnement 'prod'
   proxy = IziProxy()
   print(f"Environnement détecté: {proxy.get_current_environment()}")
   
   # Forcer un environnement spécifique
   proxy = IziProxy(environment='dev')
   print(f"Environnement forcé: {proxy.get_current_environment()}")

Utilisation en parallèle (multithreading)
---------------------------------------

.. code-block:: python

   import concurrent.futures
   from iziproxy import IziProxy
   
   proxy = IziProxy()
   
   def fetch_url(url):
       # Créer une nouvelle session pour chaque thread
       session = proxy.create_session()
       response = session.get(url)
       return url, response.status_code
   
   urls = [
       'https://httpbin.org/get',
       'https://httpbin.org/headers',
       'https://httpbin.org/ip',
       'https://httpbin.org/user-agent'
   ]
   
   with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
       results = list(executor.map(fetch_url, urls))
   
   for url, status in results:
       print(f"{url}: {status}")

Exemples de code complets
----------------------

Pour des exemples de code complets, consultez le dossier `examples` du projet :

- `simple_usage.py` - Utilisation basique d'IziProxy
- `custom_config.py` - Configuration personnalisée
- `ntlm_auth_example.py` - Utilisation avec authentification NTLM
- `env_credentials.py` - Utilisation des variables d'environnement et fichiers `.env`
- `monkey_patching.py` - Utilisation du monkey patching
- `api_wrapper_integration.py` - Intégration avec des wrappers d'API