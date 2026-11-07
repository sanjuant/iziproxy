Migration
=========

Depuis IziProxy 0.6
-------------------

La version 0.7 réécrit le cœur de la bibliothèque. Changements visibles :

* NTLM repose sur ``pyspnego`` au lieu de ``ntlm-auth`` / ``pycryptodomex``
  (``pip install iziproxy[ntlm]``) ; sous Windows la session courante est
  utilisée sans mot de passe.
* Les fichiers PAC nécessitent l'option ``pac`` (``pip install iziproxy[pac]``).
* Python 3.10 minimum ; requests >= 2.34, urllib3 >= 2.8 (les versions
  antérieures ont des failles connues, dont des fuites de l'en-tête
  ``Proxy-Authorization``).
* ``auth_type`` accepte ``basic``, ``ntlm`` ou ``negotiate`` ; toute autre
  valeur lève ``ValueError`` (elle était traitée en silence comme Basic).
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
* Nouveau : un proxy local (``install()``, ``start_local_proxy()``) qui
  s'authentifie à la place des outils externes ; il exige un jeton inclus
  dans son URL (voir :doc:`security`).
* ``verify="/chemin"`` lève ``ValueError`` si le fichier n'existe pas.
* Les proxys désignés par un PAC en ``http://`` ne reçoivent plus
  d'identifiants, sauf s'ils figurent dans la nouvelle option
  ``auth_proxies`` (voir :doc:`security`).
* ``get_proxy_dict()`` ne renvoie plus de clé ``no_proxy`` (requests
  l'ignore pour des proxys explicites) : passez l'URL cible.
* ``http_connection()`` vers une cible ``http://`` envoie des requêtes en
  forme absolue au lieu d'un tunnel ``CONNECT`` (refusé vers le port 80 par
  la plupart des proxys).
* Détection de l'environnement : les mots par défaut (``dev``, ``test``,
  ``prod``...) ne reconnaissent plus qu'un segment entier du nom d'hôte
  (``dev01-web`` oui, ``devices`` non) ; les motifs de la configuration
  restent des sous-chaînes et passent en premier.
* Les fichiers ``.env`` sont tous lus : chaque variable vient du premier
  fichier qui la définit.

Depuis CNTLM ou px
------------------

CNTLM et px sont des proxys locaux qui s'authentifient en NTLM à la place
des applications. IziProxy fait la même chose, sans service à installer ni
mot de passe à écrire dans un fichier de configuration.

Pour un programme Python
^^^^^^^^^^^^^^^^^^^^^^^^

Remplacez le dictionnaire qui pointait vers CNTLM par une ligne :

.. code-block:: python

   # Avant
   proxies = {"http": "http://localhost:3128", "https": "http://localhost:3128"}
   requests.get("https://example.com", proxies=proxies)

   # Après
   import iziproxy

   iziproxy.install()
   requests.get("https://example.com")

Correspondance avec ``cntlm.conf``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - CNTLM
     - IziProxy
   * - ``Proxy proxy.corp:8080``
     - détecté ; sinon ``proxy_url="proxy.corp:8080"``
   * - ``Username`` / ``Domain``
     - session Windows ; sinon ``username=`` / ``domain=`` ou ``IZIPROXY_USERNAME`` / ``IZIPROXY_DOMAIN``
   * - ``Password`` / ``PassNTLMv2``
     - session Windows ; sinon trousseau du système (saisi une fois) ou ``IZIPROXY_PASSWORD``
   * - ``NoProxy``
     - détecté (``ProxyOverride`` Windows, ``NO_PROXY``) ; sinon ``no_proxy=``
   * - ``Listen 3128``
     - ``start_local_proxy(token="...")`` (port 3128 par défaut)

Pour les outils externes
^^^^^^^^^^^^^^^^^^^^^^^^

Lancés depuis Python, pip, git ou curl héritent des variables posées par
``install()``. Pour des outils lancés hors de Python, faites tourner un proxy
local, comme cntlm, sur ``127.0.0.1:3128`` :

.. code-block:: python

   from iziproxy import IziProxy

   local = IziProxy().start_local_proxy(token="un-jeton-long-et-secret")
   print("HTTPS_PROXY =", local.url)
   local.serve_forever()   # Ctrl+C pour arrêter

et configurez les outils avec cette URL (jeton inclus), par exemple
``git config --global http.proxy http://iziproxy:un-jeton-long-et-secret@127.0.0.1:3128``.
Arrêtez cntlm avant : les deux ne peuvent pas écouter sur le même port
(sinon ``start_local_proxy(port=3129)``).

Différences avec CNTLM
^^^^^^^^^^^^^^^^^^^^^^

* Le proxy local exige un jeton (voir :doc:`security`) : là où CNTLM accepte
  toute connexion locale, une URL sans jeton reçoit ``407``.
* Le PAC est évalué pour chaque URL et les exclusions du système sont
  appliquées : pas besoin de les recopier.
* Le proxy local traite une requête HTTP par connexion (``Connection: close``)
  et ne relaie pas vers un proxy SOCKS.
