Guide d'utilisation
================

Ce guide présente les principales façons d'utiliser IziProxy dans vos projets.

Utilisation basique
------------------

Créer une instance IziProxy
^^^^^^^^^^^^^^^^^^^^^^^^^^

La façon la plus simple d'utiliser IziProxy est de créer une instance sans paramètres :

.. code-block:: python

   from iziproxy import IziProxy
   
   # Création avec détection automatique
   proxy = IziProxy()

IziProxy détectera automatiquement :

* L'environnement d'exécution (local, dev, prod)
* La configuration de proxy appropriée pour cet environnement
* Les identifiants nécessaires (si l'authentification est requise)

Utiliser une session requests préconfigurée
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

La méthode la plus directe pour effectuer des requêtes est d'utiliser une session préconfigurée :

.. code-block:: python

   # Obtenir une session requests préconfigurée
   session = proxy.create_session()
   
   # Utiliser la session comme une session requests normale
   response = session.get('https://example.com')
   
   # Toutes les requêtes de cette session utiliseront automatiquement le proxy
   response = session.post('https://api.example.com/data', json={'key': 'value'})

Cette approche est recommandée car elle gère automatiquement :

* La configuration du proxy
* L'authentification (basique ou NTLM)
* La réutilisation des connexions

Utiliser un dictionnaire de proxy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Si vous préférez configurer vos propres sessions ou requêtes, vous pouvez obtenir un dictionnaire de proxy :

.. code-block:: python

   # Obtenir un dictionnaire de proxy compatible avec requests
   proxies = proxy.get_proxy_dict()
   
   # Utiliser avec une requête individuelle
   response = requests.get('https://example.com', proxies=proxies)
   
   # Ou configurer une session
   session = requests.Session()
   session.proxies = proxies
   response = session.get('https://example.com')

Utiliser les variables d'environnement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pour les bibliothèques qui n'utilisent pas requests mais respectent les variables d'environnement standard :

.. code-block:: python

   # Définir les variables d'environnement HTTP_PROXY, HTTPS_PROXY, etc.
   proxy.set_environment_variables()
   
   # Utiliser d'autres bibliothèques qui respectent ces variables
   import urllib.request
   response = urllib.request.urlopen('https://example.com')
   
   # Nettoyer les variables d'environnement quand vous avez terminé
   proxy.clear_environment_variables()

Cette méthode est utile pour les bibliothèques tierces qui ne prennent pas explicitement en charge les proxys mais qui respectent les variables d'environnement standard.

Utiliser le monkey patching
^^^^^^^^^^^^^^^^^^^^^^^^

Pour simplifier l'utilisation d'IziProxy dans des projets existants ou avec des bibliothèques tierces,
vous pouvez appliquer un "monkey patching" au module requests :

.. code-block:: python

   # Configurer IziProxy et patcher le module requests
   proxy = IziProxy()
   proxy.patch_requests()
   
   # À partir de ce point, toutes les requêtes requests utiliseront automatiquement le proxy
   import requests
   response = requests.get('https://example.com')  # Utilise le proxy
   
   # Parfait pour du code existant ou des bibliothèques tierces qui utilisent requests
   # sans avoir à modifier le code source
   
   # Restaurer requests à son état original si nécessaire
   proxy.unpatch_requests()

Cette technique est particulièrement utile pour :

* Intégrer IziProxy dans des projets existants sans avoir à modifier tout le code
* Utiliser des bibliothèques tierces qui ne supportent pas facilement la configuration de proxy
* Simplifier la configuration d'un projet entier en une seule ligne de code

Utilisation avec des bibliothèques tierces
---------------------------------

Utiliser IziProxy avec des wrappers d'API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Un cas d'utilisation avancé mais très puissant est d'utiliser IziProxy avec des wrappers d'API tierces qui utilisent ``requests``.
Mais que se passe-t-il si le wrapper fait lui-même du monkey patching?

Voici un exemple pratique montrant comment intégrer IziProxy dans un wrapper d'API qui patch également ``requests`` :

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
           requests.patch = self.session.patch
           requests.delete = self.session.delete
       
       def find_resources(self, query_params):
           """
           Recherche des ressources via l'API
           """
           # Cette méthode appelle l'API tierce en interne, qui utilisera requests
           # Mais comme requests a été patché, c'est notre session qui sera utilisée
           response = self.api.find_resources(query_params)
           return response

**Comment cela fonctionne**:

Le point clé ici est l'ordre des opérations:

1. Vous créez une session préconfigurée avec IziProxy
2. Vous remplacez les méthodes du module ``requests`` par celles de votre session
3. **Ensuite** vous initialisez l'API tierce

Quand l'API tierce fera des appels comme ``requests.get(url, ...)``:

1. Ces appels passeront par la session IziProxy configurée
2. La configuration proxy sera automatiquement appliquée
3. L'API ne saura même pas qu'elle passe par un proxy

Cette technique est particulièrement utile lorsque:

* La bibliothèque tierce ne permet pas de passer une session personnalisée
* Vous avez besoin d'intégrer IziProxy dans un environnement complexe
* Vous souhaitez garder une séparation claire entre la configuration du proxy et l'utilisation de l'API

Authentification basique
^^^^^^^^^^^^^^^^^^^^^^

Pour l'authentification basique, IziProxy ajoute automatiquement les identifiants nécessaires :

.. code-block:: python

   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",
       username="user",
       password="pass"
   )
   
   session = proxy.create_session()
   # L'authentification sera automatiquement ajoutée aux requêtes

Authentification NTLM
^^^^^^^^^^^^^^^^^^^

Pour l'authentification NTLM (courante dans les environnements Windows d'entreprise) :

.. code-block:: python

   proxy = IziProxy(
       proxy_url="http://proxy.example.com:8080",
       username="domain\\user",  # Notez la double barre oblique
       password="pass",
       domain="DOMAIN"  # Optionnel, peut être inclus dans le nom d'utilisateur
   )
   
   # S'assurer que les dépendances NTLM sont installées
   session = proxy.create_session()
   # L'authentification NTLM sera gérée automatiquement

Assurez-vous d'avoir installé les dépendances NTLM avec ``pip install iziproxy[ntlm]``.

Stockage sécurisé des identifiants
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

IziProxy utilise keyring pour stocker de manière sécurisée les identifiants, évitant ainsi d'avoir à les inclure en clair dans votre code :

.. code-block:: python

   # Premier usage - vous serez invité à saisir vos identifiants
   proxy = IziProxy()
   session = proxy.create_session()
   
   # Utilisations suivantes - les identifiants seront récupérés depuis keyring
   proxy = IziProxy()
   session = proxy.create_session()
