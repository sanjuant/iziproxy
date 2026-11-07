Autres clients HTTP
===================

IziProxy fournit un adaptateur pour chaque client HTTP courant. Tous
appliquent les mêmes règles que ``create_session()`` : PAC évalué par URL,
exclusions, authentification Basic ou NTLM / Negotiate.

.. list-table::
   :header-rows: 1
   :widths: 20 45 35

   * - Client
     - Adaptateur
     - Mécanisme
   * - requests
     - ``create_session()``, ``patch_requests()``
     - adaptateur requests natif
   * - httpx
     - ``httpx_client()``, ``httpx_async_client()``
     - transport httpx natif
   * - aiohttp
     - ``aiohttp_session()``
     - proxy local partagé
   * - urllib3
     - ``urllib3_pool_manager()``
     - PoolManager natif
   * - urllib.request
     - ``urllib_opener()``, ``install_urllib_opener()``
     - handler urllib natif
   * - http.client
     - ``http_connection(url)``
     - tunnel ``set_tunnel`` natif
   * - websockets
     - ``websocket_proxy(uri)``
     - paramètre ``proxy`` natif
   * - gRPC
     - ``grpc_channel_options(target)``
     - option ``grpc.http_proxy``
   * - Selenium
     - ``selenium_proxy()``
     - proxy local partagé
   * - Playwright
     - ``playwright_proxy()``
     - proxy local partagé
   * - pip, git, curl...
     - ``set_environment_variables(local_proxy=True)``
     - proxy local
   * - Tout autre client
     - ``proxy_for(url)``, ``local_proxy_url()``
     - URL de proxy à fournir

Le proxy NTLM / Negotiate n'est compris nativement que par requests. Pour
les autres clients, l'adaptateur passe automatiquement par le **proxy local
partagé** (démarré à la première demande sur ``127.0.0.1``, arrêté par
``stop_local_proxies()`` ou en sortie de ``with proxy:``), qui s'authentifie
à leur place. Le TLS reste de bout en bout : chaque client vérifie le
certificat du site à travers le tunnel ``CONNECT``.

.. code-block:: bash

   pip install iziproxy[httpx]     # httpx >= 0.28
   pip install iziproxy[aiohttp]   # aiohttp >= 3.14

httpx
-----

.. code-block:: python

   with proxy.httpx_client(http2=False, timeout=10) as client:
       client.get("https://example.com")

   async with proxy.httpx_async_client() as client:
       await client.get("https://example.com")

Le transport choisit la route de chaque requête et garde un pool de
connexions par proxy. Les options ``verify``, ``cert``, ``http1``, ``http2``,
``limits``, ``retries`` vont au transport, les autres au client. Les
variables d'environnement de proxy sont ignorées (``trust_env=False``).

aiohttp
-------

.. code-block:: python

   async with proxy.aiohttp_session() as session:
       async with session.get("https://example.com") as response:
           print(await response.text())

aiohttp n'offre pas de point d'extension public pour choisir le proxy de
chaque requête : la session passe par le proxy local partagé, qui fait ce
choix. Sans proxy configuré, la session est directe.

urllib3
-------

.. code-block:: python

   pool = proxy.urllib3_pool_manager(retries=3)
   pool.request("GET", "https://example.com")

urllib3 ne lit pas les variables d'environnement : sans IziProxy, un
``PoolManager`` ne passe jamais par un proxy. Une redirection suit la route
de la requête d'origine.

urllib.request
--------------

.. code-block:: python

   opener = proxy.urllib_opener()
   opener.open("https://example.com")

   # Pour tout le code qui appelle urllib.request.urlopen()
   proxy.install_urllib_opener()

Chaque requête et chaque redirection sont routées individuellement.

http.client
-----------

.. code-block:: python

   connection = proxy.http_connection("https://api.example.com", timeout=10)
   connection.request("GET", "/status")
   response = connection.getresponse()

Via un proxy, la connexion ouvre un tunnel ``CONNECT`` vers la cible : les
requêtes s'écrivent avec un chemin relatif, comme en direct.

websockets
----------

.. code-block:: python

   from websockets.sync.client import connect

   uri = "wss://stream.example.com/feed"
   with connect(uri, proxy=proxy.websocket_proxy(uri)) as ws:
       ws.send("hello")

Nécessite websockets 15 ou plus récent. websockets ne décode pas les
identifiants placés dans l'URL du proxy : avec un proxy authentifié, la
connexion passe par le proxy local.

gRPC
----

.. code-block:: python

   import grpc

   target = "api.example.com:443"
   channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(),
                                 options=proxy.grpc_channel_options(target))

Pour une cible exclue, l'option ``grpc.enable_http_proxy`` vaut ``0`` : gRPC
ignore alors aussi ses variables d'environnement.

Selenium et Playwright
----------------------

.. code-block:: python

   browser = playwright.chromium.launch(proxy=proxy.playwright_proxy())

   options = webdriver.ChromeOptions()
   options.proxy = proxy.selenium_proxy()
   driver = webdriver.Chrome(options=options)

Les navigateurs pilotés n'acceptent pas de règles par URL : ils passent par
le proxy local partagé.

* ``playwright_proxy()`` renvoie ``{"server", "username", "password"}`` :
  Playwright transmet le jeton du proxy local.
* ``selenium_proxy()`` : WebDriver ne sait pas transmettre d'identifiants au
  proxy. Selenium utilise donc un proxy local **sans jeton**, que tout
  processus de la machine peut emprunter tant qu'il tourne. Sur un poste
  partagé, préférez Playwright (voir :doc:`security`).

Autres clients
--------------

``proxy_for(url)`` donne l'URL de proxy à fournir à n'importe quel client :

* ``None`` : connexion directe ;
* l'URL du proxy, avec ses identifiants Basic encodés s'il en faut ;
* pour NTLM, l'URL du proxy local partagé (jeton inclus).

``local_proxy_url()`` donne directement l'URL du proxy local partagé. Le
client doit envoyer en Basic les identifiants contenus dans cette URL ; s'il
en est incapable, ``local_proxy_url(token=False)`` fournit un proxy local
sans jeton (voir :doc:`security`).

Limites communes
----------------

* Les proxys SOCKS (directive PAC ``SOCKS`` / ``SOCKS5``) ne sont gérés que
  par requests (avec ``requests[socks]``) et httpx (avec ``httpx[socks]``) ;
  le proxy local répond ``502`` pour une telle route.
* http.client, urllib, gRPC et websockets ne savent pas parler TLS à un
  proxy ``https://`` : leurs adaptateurs passent alors par le proxy local.
