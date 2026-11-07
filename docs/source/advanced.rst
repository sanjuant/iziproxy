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
sont prises en charge (``SOCKS`` nécessite ``requests[socks]``).

Détection de l'authentification
-------------------------------

Si ``requires_auth`` ou ``auth_type`` ne sont pas configurés, IziProxy envoie
au proxy une requête ``HEAD http://example.com/`` sans identifiants, une seule
fois et seulement lorsqu'une requête doit passer par le proxy. Une réponse
``407`` indique qu'une authentification est nécessaire ; les en-têtes
``Proxy-Authenticate`` donnent le schéma (NTLM / Negotiate si pyspnego est
installé, sinon Basic).

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

Le schéma retenu est mémorisé : les requêtes suivantes ne sondent plus le
proxy. Des identifiants refusés lèvent ``NtlmAuthenticationError``.

Sous Windows, sans mot de passe, pyspnego utilise SSPI avec la session
courante.

Journalisation
--------------

IziProxy n'ajoute aucun handler par défaut : configurez le logger
``iziproxy`` comme les autres, ou utilisez ``debug=True`` /
``set_debug(True)`` pour afficher les journaux détaillés sur stderr. Les mots
de passe n'apparaissent jamais dans les journaux.
