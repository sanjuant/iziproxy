Utilisation
===========

.. tip::

   Pour que tout le processus passe le proxy en une ligne, utilisez
   ``iziproxy.install()`` (voir :doc:`quickstart`). Cette page décrit la
   classe ``IziProxy``, pour configurer chaque client précisément.

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

Les variables d'environnement ne peuvent décrire qu'un proxy sans
authentification ou Basic, et un seul proxy pour toutes les URLs. Avec un
proxy NTLM / Negotiate ou un fichier PAC, utilisez le proxy local.

Proxy local pour les outils externes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Comme cntlm ou px, IziProxy peut démarrer un proxy HTTP sur ``127.0.0.1``
qui s'authentifie auprès du proxy d'entreprise à la place de pip, git, curl,
conda, d'un navigateur... Ces outils n'ont besoin que de son adresse.

Remplacer cntlm en trois lignes
"""""""""""""""""""""""""""""""

.. code-block:: python

   from iziproxy import IziProxy

   local = IziProxy().start_local_proxy()   # http://127.0.0.1:3128
   print("Proxy local :", local.url)
   local.serve_forever()                    # Ctrl+C pour arrêter

* **Port** : ``3128`` par défaut, comme cntlm. ``start_local_proxy(port=8888)``
  pour un autre port, ``port=0`` pour un port libre choisi par le système
  (lu ensuite dans ``local.port``). Un port déjà pris (cntlm encore lancé,
  seconde instance) lève ``OSError``.
* **Jeton** : aléatoire à chaque démarrage et inclus dans ``local.url``. Pour
  configurer les outils une fois pour toutes, fixez-le :
  ``start_local_proxy(token="un-jeton-long-et-secret")``, puis par exemple
  ``git config --global http.proxy http://iziproxy:un-jeton-long-et-secret@127.0.0.1:3128``.
* ``serve_forever()`` bloque jusqu'à Ctrl+C (ou ``stop()`` depuis un autre
  thread), puis arrête le proxy. Script complet : :doc:`examples`.

Depuis un programme Python
""""""""""""""""""""""""""

.. code-block:: python

   proxy.set_environment_variables(local_proxy=True)   # port libre au hasard
   subprocess.run(["pip", "install", "paquet"], check=True)
   proxy.clear_environment_variables()   # arrête aussi le proxy local

   # Gestion explicite, le temps d'un bloc
   with proxy.start_local_proxy() as local:
       env = dict(os.environ, HTTP_PROXY=local.url, HTTPS_PROXY=local.url)
       subprocess.run(["git", "fetch"], env=env, check=True)

``start_local_proxy()`` retourne un :class:`iziproxy.LocalProxy` :

* ``url`` : à placer dans ``HTTP(S)_PROXY``. Elle contient un jeton
  (``http://iziproxy:<jeton>@127.0.0.1:3128``) que les outils renvoient
  d'eux-mêmes ; sans lui, le proxy local répond ``407`` (voir :doc:`security`) ;
* ``address`` : la même adresse sans jeton, pour l'affichage ;
* ``host``, ``port``, ``token``, ``running`` ;
* ``serve_forever()``, ``stop()``, gestionnaire de contexte.

``install()``, ``set_environment_variables(local_proxy=True)`` et les
adaptateurs (aiohttp, navigateurs...) démarrent leur propre proxy local sur un
port libre au hasard : ils ne gênent pas un proxy local lancé sur 3128.

Les proxys locaux encore actifs sont arrêtés en sortie d'un bloc
``with proxy:`` ou par ``stop_local_proxies()``.

Erreurs TLS des outils
""""""""""""""""""""""

Le trafic HTTPS traverse le proxy local sans être déchiffré : chaque outil
vérifie lui-même le certificat du site.

* **Lire** ``curl -v`` : ``CONNECT: no ALPN negotiated`` n'est pas une
  erreur (la connexion vers le proxy local est en HTTP clair). Si
  ``HTTP/1.1 200 Connection established`` suit, le tunnel est ouvert ; une
  erreur après cette ligne vient de la connexion TLS entre l'outil et le
  site.
* **Proxy qui inspecte le TLS** : les sites présentent des certificats
  signés par l'autorité interne, installée dans le magasin du système. Après
  ``install()`` ou ``set_environment_variables()``, les sous-processus en
  tiennent compte sans rien faire :

  - ``REQUESTS_CA_BUNDLE``, ``PIP_CERT``, ``SSL_CERT_FILE``,
    ``CURL_CA_BUNDLE`` et ``NODE_EXTRA_CA_CERTS`` désignent un export PEM des
    autorités du système (Windows : magasins ``ROOT`` et ``CA``, certificats
    valables pour un serveur TLS ; macOS : trousseaux système ; plus les
    autorités de certifi), rafraîchi chaque jour dans le cache de
    l'utilisateur. Sous Linux, c'est le fichier de la distribution (sinon
    celui de certifi). Avec ``verify="/chemin/ca.pem"``, ce fichier est
    utilisé à la place (un répertoire va dans ``REQUESTS_CA_BUNDLE``,
    ``PIP_CERT`` et ``SSL_CERT_DIR``) ; avec ``verify=False``, aucune de ces
    variables n'est définie ;
  - sous Windows, git (moteur schannel) vérifie la révocation et échouerait
    avec ``CRYPT_E_NO_REVOCATION_CHECK (0x80092012)`` si la liste de
    révocation de l'autorité interne est injoignable (cntlm donnerait la
    même erreur). Il reçoit ``http.schannelCheckRevoke=best-effort`` par
    ``GIT_CONFIG_COUNT`` / ``GIT_CONFIG_KEY_n`` / ``GIT_CONFIG_VALUE_n``,
    ajoutées à la suite de celles déjà définies, sans toucher au
    ``.gitconfig`` ; la vérification reste active quand la liste répond.

  Une variable déjà définie n'est jamais remplacée,
  ``clear_environment_variables()`` et ``uninstall()`` restaurent exactement
  les valeurs d'avant, ``install(tls_env=False)`` (ou
  ``set_environment_variables(tls_env=False)``) désactive le tout. Un export
  impossible est signalé dans les journaux sans faire échouer ``install()``.

* **curl sous Windows** n'a pas de variable d'environnement pour la
  révocation : ajoutez ``--ssl-revoke-best-effort`` (ou la ligne
  ``ssl-revoke-best-effort`` dans ``_curlrc``). Avec un proxy local lancé à
  part, sans ``install()``, réglez aussi git vous-même :

  .. code-block:: bash

     curl --ssl-revoke-best-effort -x "$HTTPS_PROXY" https://pypi.org/simple/
     git config --global http.schannelCheckRevoke best-effort

* **Python** ne vérifie pas la révocation, mais doit faire confiance à
  l'autorité interne : ``install()`` s'en charge (truststore, magasin du
  système), sinon ``verify="/chemin/ca-entreprise.pem"``.

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
