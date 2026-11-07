Fonctionnement détaillé
=======================

Choix du proxy pour chaque requête
----------------------------------

``create_session()`` monte un adaptateur ``requests`` qui interroge IziProxy
à chaque requête :

1. l'hôte est-il exclu (``no_proxy``, boucle locale) ? → connexion directe ;
2. la source est un PAC ? → ``FindProxyForURL`` est évalué pour l'hôte (avec cache) ;
3. sinon le proxy explicite ou système est utilisé.

Les directives PAC ``PROXY``, ``HTTPS``, ``SOCKS``, ``SOCKS5`` et ``DIRECT``
sont prises en charge (``SOCKS`` nécessite ``requests[socks]`` et n'est pas
relayé par le proxy local).

Le PAC est chargé et évalué dans un processus Python séparé, lancé une fois
par fichier PAC (environ 0,2 s). Le moteur JavaScript de pypac (dukpy) garde
en effet le verrou global de Python pendant l'évaluation, sans moyen de
l'interrompre : un PAC qui boucle gèlerait tout le programme. Au-delà de
10 secondes (``iziproxy.pac_evaluator.PAC_EVAL_TIMEOUT``), le processus est
arrêté, les connexions sont directes et le PAC est retenté au bout d'une
minute. Dans une application figée (PyInstaller) ou un Python embarqué dans
un autre logiciel, le PAC est évalué dans le processus courant, sans ce
délai maximal.

Détection de l'authentification
-------------------------------

Si ``requires_auth`` ou ``auth_type`` ne sont pas configurés, IziProxy envoie
au proxy une requête ``HEAD http://example.com/`` sans identifiants, une seule
fois et seulement lorsqu'une requête doit passer par le proxy. Une réponse
``407`` indique qu'une authentification est nécessaire ; les en-têtes
``Proxy-Authenticate`` donnent le schéma (NTLM / Negotiate si pyspnego est
installé, sinon Basic).

Avec un PAC, le proxy sondé est celui de la première URL qui en désigne un :
un PAC qui répond ``DIRECT`` pour ``www.example.com`` ne fige donc pas la
décision.

Un proxy qui ne répond pas à la sonde (VPN pas encore établi, délai de 3 s
dépassé) ne fige pas non plus la décision : les requêtes partent sans
identifiants et le proxy est sondé de nouveau après 10 secondes
(``iziproxy.proxy_manager.AUTH_PROBE_RETRY_DELAY``).

Authentification Basic
----------------------

Les identifiants sont placés, encodés, dans l'URL du proxy. urllib3 envoie
alors ``Proxy-Authorization`` au proxy seul : dans la requête ``CONNECT``
pour HTTPS, jamais au site cible. Les identifiants sont encodés en UTF-8.

Authentification NTLM / Negotiate
---------------------------------

NTLM authentifie une connexion, pas une requête. L'adaptateur NTLM :

* ouvre la connexion vers le proxy et réalise la négociation
  (type 1 → challenge → type 3) ;
* pour HTTPS, établit le tunnel ``CONNECT`` puis la session TLS (certificats
  vérifiés avec le magasin système et le bundle de requests) ;
* pour HTTP, envoie la requête en forme absolue sur la connexion authentifiée ;
* confie la lecture de la réponse à http.client / urllib3 : en-têtes,
  cookies, redirections, ``stream=True``, gzip/deflate, ``timeout``.

Quand le proxy propose Negotiate et NTLM, Negotiate est essayé d'abord
(Kerberos quand un ticket est disponible, plus sûr que NTLM), puis NTLM sur
une nouvelle connexion s'il est refusé. Le schéma qui a réussi est mémorisé :
les négociations suivantes commencent par lui, sans sonder le proxy. Des
identifiants refusés lèvent ``NtlmAuthenticationError``.

Les connexions sont réutilisées (keep-alive), si bien que la négociation n'a
lieu qu'à l'ouverture d'une connexion :

* un tunnel TLS vers un site sert aux requêtes ``https://`` suivantes vers
  ce site (mêmes réglages ``verify`` / ``cert``) ;
* une connexion authentifiée au proxy sert aux requêtes ``http://``
  suivantes et aux ``CONNECT`` (le proxy local en profite aussi) ;
* une connexion fermée entre-temps par le proxy ou le site est remplacée,
  et la requête renvoyée une fois ; une réponse ``407`` sur une connexion
  réutilisée relance la négociation ;
* au plus ``pool_maxsize`` connexions inactives (10) par proxy et par site ;
  elles sont fermées avec la session.

Sous Windows, sans mot de passe, pyspnego utilise SSPI avec la session
courante.

Proxy local
-----------

``start_local_proxy()`` lance un serveur ``socketserver`` multi-thread sur
``127.0.0.1``. Pour chaque connexion cliente :

* le jeton est vérifié (``Proxy-Authorization: Basic``, comparaison à temps
  constant) ; sans lui, réponse ``407`` ;
* ``CONNECT hôte:port`` : la route est celle de ``https://hôte:port/``. En
  direct, le proxy local se connecte à la cible ; via un proxy NTLM, il
  réutilise la négociation de l'adaptateur NTLM (``open_tunnel()``) ; via un
  proxy Basic, il envoie ``CONNECT`` avec ``Proxy-Authorization``. Une fois le
  tunnel établi, les octets sont relayés sans être lus. La réponse du proxy
  amont est lue sans déborder sur le tunnel : les protocoles où le serveur
  parle en premier (SSH sur le port 443, SMTP...) gardent leur bannière.
* requête HTTP en forme absolue : le corps (``Content-Length`` ou
  ``chunked``) est lu en entier (un corps tronqué ou une longueur invalide
  donnent ``400``), les en-têtes propres au saut (``Connection``,
  ``Proxy-Authorization``...) sont retirés, puis la requête est envoyée en
  forme d'origine (direct) ou absolue (proxy) avec la même négociation NTLM.
  La réponse est relayée avec ``Connection: close`` : une requête par
  connexion cliente. Vers un proxy NTLM, la connexion amont authentifiée est
  ensuite réutilisée pour les requêtes suivantes.

Le type d'authentification et les identifiants sont déterminés au démarrage,
dans le thread appelant. Une route qui reviendrait vers le proxy local
lui-même (par exemple après ``refresh()`` alors que ``HTTP_PROXY`` pointe vers
lui) est refusée avec ``508 Loop Detected``.

Journalisation
--------------

IziProxy n'ajoute aucun handler par défaut : configurez le logger
``iziproxy`` comme les autres, ou utilisez ``debug=True`` /
``set_debug(True)`` pour afficher les journaux détaillés sur stderr. Les mots
de passe et le jeton du proxy local n'apparaissent jamais dans les journaux.
