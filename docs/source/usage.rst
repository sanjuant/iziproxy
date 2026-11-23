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

Remplacer cntlm : ``iziproxy serve`` et ``iziproxy setup``
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Le paquet installe la commande ``iziproxy`` :

.. code-block:: bash

   iziproxy setup     # une seule fois : configure git, curl et pip
   iziproxy serve     # le proxy local sur 127.0.0.1:3128 (Ctrl+C pour arrêter)

IziProxy ne peut pas modifier l'environnement d'un terminal déjà ouvert :
``iziproxy setup`` écrit donc l'URL du proxy local
(``http://iziproxy:<jeton>@127.0.0.1:3128``) dans la configuration
**utilisateur** de chaque outil, après avoir affiché ce qu'il va écrire et
demandé confirmation :

* **git** : configuration globale, ``http.proxy`` et ``https.proxy``,
  ``http.proxyAuthMethod basic`` (une méthode NTLM ou Negotiate réglée pour
  l'ancien proxy serait refusée par le proxy local) ; sous Windows,
  ``http.schannelCheckRevoke best-effort`` (voir plus bas) ;
* **curl** : ``proxy`` dans le fichier que curl lit réellement, cherché dans
  le même ordre que curl : ``$CURL_HOME``, ``$XDG_CONFIG_HOME/curlrc``,
  ``$HOME``, puis sous Windows ``%USERPROFILE%`` et ``%APPDATA%``
  (``.curlrc`` avant ``_curlrc``), enfin ``~/.config/curlrc`` ; à défaut,
  ``%APPDATA%\_curlrc`` (Windows) ou ``~/.curlrc`` est créé. Sous Windows,
  ``ssl-revoke-best-effort`` est ajouté. Les options d'authentification
  auprès d'un proxy (``proxy-user`` / ``-U``, ``proxy-ntlm``,
  ``proxy-negotiate``, ``proxy-anyauth``, ``proxy-digest``, ``proxy-basic``)
  sont retirées : curl enverrait sinon d'autres identifiants au proxy local
  (``407``). ``--undo`` les rétablit ;
* **pip** : ``proxy`` et ``cert`` dans ``%APPDATA%\pip\pip.ini`` (Windows)
  ou ``~/.config/pip/pip.conf``. ``cert`` désigne un export PEM des autorités
  de certifi et du magasin du système (autorité interne d'un proxy qui
  inspecte le TLS comprise), écrit dans le répertoire de configuration
  d'IziProxy. Relancez ``iziproxy setup --only pip`` après l'installation
  d'une nouvelle autorité.

Options de ``iziproxy setup`` :

* ``--yes`` : pas de confirmation (script d'installation) ;
* ``--only git,curl`` : seulement ces outils ;
* ``--port 8888`` : port d'un proxy lancé avec ``iziproxy serve --port 8888`` ;
* ``--undo`` : restaure les valeurs et fichiers d'avant le premier ``setup``
  (sauvegardés dans ``setup-backup.json``) ; avec ``--only``, seulement ces
  outils. Un fichier modifié à la main depuis le ``setup`` est d'abord copié
  en ``<fichier>.iziproxy-undo.bak``.

**Jeton fixe.** Aucun mot de passe n'est écrit : seul le jeton du proxy
local figure dans ces fichiers. Il est généré au premier ``serve`` ou
``setup`` et gardé dans ``local-proxy-token``, dans le répertoire de
configuration d'IziProxy (``%APPDATA%\iziproxy`` sous Windows,
``~/.config/iziproxy`` sous Linux, ``~/Library/Application Support/iziproxy``
sous macOS), lisible par vous seul. ``iziproxy serve`` le reprend à chaque
démarrage : la configuration des outils reste valable. Supprimez ce fichier
puis relancez ``iziproxy setup`` pour changer de jeton.

``iziproxy serve`` accepte ``--port`` (3128 par défaut, comme cntlm : un
port déjà pris, cntlm encore lancé par exemple, arrête la commande),
``--config fichier.yml`` (voir :doc:`configuration`) et ``--debug``. Il
affiche l'adresse du proxy, jamais le jeton.

Depuis Python, en trois lignes
""""""""""""""""""""""""""""""

.. code-block:: python

   from iziproxy import IziProxy

   local = IziProxy().start_local_proxy()   # http://127.0.0.1:3128
   print("Proxy local :", local.address)
   local.serve_forever()                    # Ctrl+C pour arrêter

* **Port** : ``3128`` par défaut, comme cntlm. ``start_local_proxy(port=8888)``
  pour un autre port, ``port=0`` pour un port libre choisi par le système
  (lu ensuite dans ``local.port``). Un port déjà pris (cntlm encore lancé,
  seconde instance) lève ``OSError``.
* **Jeton** : aléatoire à chaque démarrage et inclus dans ``local.url``, sauf
  si vous le fixez : ``start_local_proxy(token="un-jeton-long-et-secret")``.
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

  Ces variables visent les sous-processus : dans le processus lui-même,
  les sessions ``requests`` configurées par IziProxy (``create_session()``,
  ``patch_requests()``, ``install()``) ignorent les ``REQUESTS_CA_BUNDLE`` /
  ``CURL_CA_BUNDLE`` qui pointent vers l'export du magasin écrit par
  IziProxy et vérifient avec le magasin du système en direct (truststore)
  plutôt qu'avec cet export, qui peut dater d'un jour. Seul l'export est
  ignoré : un fichier ou répertoire passé par ``verify="/chemin"``, ou une
  valeur que vous aviez définie avant, reste appliqué.

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

  ``iziproxy setup`` règle ces deux options pour vous.

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
