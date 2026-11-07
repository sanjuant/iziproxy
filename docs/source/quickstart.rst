Démarrage rapide
================

Le besoin d'abord : que ça marche. Ensuite, si nécessaire, on règle.

Une ligne
---------

.. code-block:: python

   import iziproxy

   iziproxy.install()

Placez cette ligne au démarrage du programme (``main``, ``__init__`` de
l'application, ``conftest.py``...). Elle :

1. détecte l'environnement (local, dev, prod) et le proxy : paramètres,
   fichier ``iziproxy.yml``, variables d'environnement, réglages système
   (registre Windows, macOS, GNOME, KDE), fichier PAC ;
2. découvre l'authentification attendue en interrogeant le proxy (aucune,
   Basic, NTLM / Negotiate) et trouve les identifiants (session Windows pour
   NTLM, trousseau, variables, saisie interactive une seule fois) ;
3. configure tout le processus :

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Client
     - Mécanisme
   * - requests, ``requests.get()``, bibliothèques tierces basées sur requests
     - ``patch_requests()`` : chaque requête choisit sa route (PAC, exclusions)
   * - ``urllib.request.urlopen()``
     - opener global (``install_urllib_opener()``)
   * - httpx, gRPC, tout client lisant ``HTTP(S)_PROXY``
     - variables d'environnement vers le proxy local
   * - aiohttp
     - variables d'environnement, avec ``ClientSession(trust_env=True)``
   * - pip, git, curl, conda, npm... lancés par ``subprocess``
     - variables d'environnement héritées par les sous-processus

Les variables d'environnement pointent vers un **proxy local** sur
``127.0.0.1`` (voir :doc:`usage`), jamais vers le proxy d'entreprise avec un
mot de passe : celui-ci n'apparaît donc ni dans ``os.environ`` ni dans
l'environnement des sous-processus, et NTLM ou un PAC fonctionnent même pour
les outils qui n'en savent rien.

Sans proxy
^^^^^^^^^^

Si aucun proxy n'est trouvé (production, réseau domestique), ``install()``
ne modifie rien. Gardez la ligne : le même code fonctionne partout.

Vérifier ce qui a été fait
^^^^^^^^^^^^^^^^^^^^^^^^^^

``install()`` retourne une :class:`iziproxy.Installation` :

.. code-block:: python

   installation = iziproxy.install()
   print(installation)
   # proxy http://proxy.corp:8080 (ntlm) ; local http://127.0.0.1:53211 ; requests, urllib, environment

   installation.active            # False : aucun proxy, rien n'a été modifié
   installation.local_proxy_url   # 'http://127.0.0.1:53211'
   installation.environment       # variables définies
   installation.proxy             # l'instance IziProxy utilisée

Ailleurs dans le programme, ``iziproxy.current()`` retourne l'installation
active (ou ``None``).

Annuler
^^^^^^^

.. code-block:: python

   iziproxy.uninstall()           # tout est restauré, le proxy local est arrêté

   with iziproxy.install():       # configuration limitée au bloc
       ...

La fin du programme annule aussi tout automatiquement. Un nouvel appel à
``install()`` remplace le précédent.

Quand il faut aider la détection
--------------------------------

Ajoutez seulement le paramètre qui manque. ``install()`` accepte tous les
paramètres de :class:`iziproxy.IziProxy`.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Situation
     - Solution
   * - Le proxy n'est pas détecté
     - ``install(proxy_url="proxy.corp:8080")`` ou ``install(pac_url="http://wpad/proxy.pac")``
   * - Les identifiants ne sont pas trouvés
     - ``install(username="jdupont", password="...", domain="CORP")``, variables
       ``IZIPROXY_USERNAME`` / ``IZIPROXY_PASSWORD`` / ``IZIPROXY_DOMAIN``, ou saisie interactive
       (mémorisée dans le trousseau système)
   * - Pas de saisie interactive (service, CI)
     - ``install(interactive=False)``
   * - Des hôtes doivent rester en direct
     - ``install(no_proxy=["*.corp.local", "10.0.0.0/8"])``
   * - Le type d'authentification est mal détecté
     - ``install(auth_type="ntlm")`` ou ``"basic"``
   * - Réglages différents en local / dev / prod
     - fichier ``iziproxy.yml`` (voir :doc:`configuration`), puis ``install()`` sans paramètre
   * - Forcer l'environnement
     - ``install(environment="dev")`` ou variable ``IZIPROXY_ENV=dev``
   * - Comprendre ce qui se passe
     - ``install(debug=True)`` : journaux détaillés sur stderr (mots de passe masqués)
   * - Une instance déjà configurée
     - ``install(IziProxy(...))``

Choisir ce qui est configuré
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Option
     - Défaut
     - Effet
   * - ``requests``
     - ``True``
     - patcher requests (toutes les sessions, y compris celles des bibliothèques)
   * - ``urllib``
     - ``True``
     - installer l'opener global de ``urllib.request``
   * - ``env_vars``
     - ``True``
     - définir ``HTTP(S)_PROXY`` / ``NO_PROXY`` (minuscules et majuscules)
   * - ``local_proxy``
     - ``True``
     - faire pointer ces variables vers le proxy local. ``False`` : vers le proxy
       d'entreprise, identifiants Basic inclus dans l'URL (refusé avec NTLM)

.. code-block:: python

   # Seulement requests, sans toucher à l'environnement
   iziproxy.install(urllib=False, env_vars=False)

Aller plus loin
---------------

Pour un réglage fin par client (adaptateur httpx natif plutôt que le proxy
local, session aiohttp, gRPC, Selenium, Playwright...), utilisez l'instance
:class:`iziproxy.IziProxy` : ``iziproxy.current().proxy`` ou votre propre
instance. Voir :doc:`usage` et :doc:`clients`.
