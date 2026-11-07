Sécurité
========

IziProxy manipule vos identifiants d'entreprise (mot de passe, ou session
Windows pour NTLM). Cette page résume ce qui les protège, et ce qui reste de
votre ressort.

Ce qu'IziProxy garantit
-----------------------

Les identifiants ne vont qu'au proxy
   Avec Basic, ils sont placés dans l'URL du proxy : requests, urllib3,
   httpx et urllib n'envoient alors ``Proxy-Authorization`` qu'au proxy
   (dans la requête ``CONNECT`` pour HTTPS), jamais au site visité, même
   après une redirection. Avec NTLM, la négociation a lieu sur la connexion
   au proxy uniquement.

Pas de mot de passe dans l'environnement
   ``install()`` et ``set_environment_variables(local_proxy=True)`` font
   pointer ``HTTP(S)_PROXY`` vers le proxy local : les sous-processus ne
   voient qu'un jeton à usage local, jamais le mot de passe.

Pas de mot de passe dans les traces
   Journaux (y compris en ``debug=True``), ``repr()``, ``describe()`` et
   messages d'erreur masquent mots de passe et jetons.
   ``get_proxy_config()`` renvoie un dictionnaire affichable sans risque.

Certificats vérifiés, sans repli
   Un proxy ``https://`` et un fichier PAC ``https://`` sont vérifiés avec
   les autorités du système (``verify=True``). Un PAC refusé est ignoré
   (avertissement), un proxy refusé fait échouer la requête : rien n'est
   retenté sans vérification. Le trafic HTTPS vers les sites n'est jamais
   déchiffré, ni par IziProxy ni par son proxy local.

Le proxy local
--------------

Le proxy local (``start_local_proxy()``, ``install()``) s'authentifie auprès
du proxy d'entreprise **avec votre identité**. Pour qu'un autre programme ne
puisse pas en profiter :

* il n'écoute que sur ``127.0.0.1`` ;
* il exige un **jeton aléatoire**, différent à chaque démarrage, envoyé en
  Basic (utilisateur ``iziproxy``). Le jeton fait partie de ``local.url``
  (``http://iziproxy:<jeton>@127.0.0.1:port``) : pip, git, curl, requests,
  httpx, aiohttp, urllib, gRPC et websockets le renvoient d'eux-mêmes. Sans
  jeton, la réponse est ``407`` ;
* le jeton n'est jamais relayé vers le proxy d'entreprise ni vers les sites.

Deux cas désactivent cette protection, à choisir en connaissance de cause :

* ``selenium_proxy()`` : Chrome et Firefox pilotés par WebDriver ne savent
  pas envoyer d'identifiants au proxy. Ils utilisent un proxy local **sans
  jeton**, que tout processus de la machine peut emprunter tant qu'il tourne.
  Sur un poste partagé (Citrix, serveur multi-utilisateurs), préférez
  Playwright, qui transmet le jeton (``playwright_proxy()``).
* ``start_local_proxy(token=False)`` : même chose, explicitement. Pour un
  outil configuré une fois pour toutes avec une adresse fixe, passez plutôt
  un jeton fixe : ``start_local_proxy(token="un-jeton-long-et-secret")`` (port 3128 par défaut).

Les autres limites du proxy local : corps de requête ``http://`` de 100 Mio
au plus (``413`` au-delà ; les tunnels ``CONNECT`` ne sont pas concernés),
256 connexions simultanées (``503`` au-delà), caractères de contrôle refusés
dans la ligne de requête et les en-têtes (``400``).

Proxys qui reçoivent vos identifiants
-------------------------------------

Le mot de passe Basic, ou la réponse NTLM / Negotiate calculée avec votre
session Windows, ne part que vers un proxy de confiance :

* sans ``auth_proxies`` : les proxys donnés explicitement (``proxy_url``,
  configuration) ou par le système (registre, variables d'environnement),
  et ceux d'un PAC obtenu de façon sûre (fichier local, ``file://`` ou
  ``https://`` avec certificat vérifié) ;
* avec ``auth_proxies`` : uniquement les hôtes listés, quelle que soit la
  source (mêmes formats que ``no_proxy`` : ``proxy.corp.com``,
  ``*.corp.com``, ``10.0.0.0/8``, ``proxy:8080``).

Un PAC téléchargé en ``http://`` (ou découvert via WPAD) peut être modifié
par n'importe quel équipement du réseau : il désignerait alors un proxy qui
récupérerait le mot de passe ou une réponse NTLM réutilisable (relais). Ses
proxys ne reçoivent donc des identifiants que s'ils figurent dans
``auth_proxies`` ; sinon la requête part sans authentification (``407``) et
un avertissement donne la marche à suivre :

.. code-block:: python

   IziProxy(pac_url="http://wpad.corp/proxy.pac", auth_proxies=["*.proxy.corp.com"])

Le téléchargement d'un PAC ``https://`` ne suit jamais une redirection vers
``http://``. Un PAC indisponible est retenté au bout d'une minute.

En CGI (``REQUEST_METHOD`` défini), la variable ``HTTP_PROXY`` est ignorée,
comme dans urllib : elle peut provenir de l'en-tête ``Proxy:`` envoyé par
le client (« httpoxy »).

Ce qui reste de votre ressort
-----------------------------

Le fichier ``iziproxy.yml`` du répertoire courant
   IziProxy lit ``./iziproxy.yml`` (pratique pour un projet). Or ce fichier
   décide où part le trafic : un dépôt cloné malveillant pourrait y désigner
   son propre proxy, qui recevrait votre authentification. IziProxy
   **avertit** quand ce fichier définit ``proxy_url``, ``pac_url``,
   ``auth_proxies`` ou ``verify``. Pour une configuration personnelle, utilisez
   ``~/.config/iziproxy.yml`` ; dans une application, passez
   ``config_path=`` explicitement.

``verify=False``
   Désactive la vérification du certificat du proxy et du PAC : n'importe
   quel intermédiaire réseau peut alors se faire passer pour eux.

Le mot de passe en mémoire
   ``SecurePassword`` chiffre le mot de passe pour éviter les fuites
   accidentelles (journal, débogueur, recherche dans un vidage mémoire), mais
   la clé est dans le même processus : ce n'est pas une protection contre un
   programme qui lit la mémoire de votre processus.

Basic sur un proxy ``http://``
   Le protocole Basic envoie le mot de passe à peine encodé. Entre vous et un
   proxy en ``http://``, il circule donc en clair sur le réseau local. NTLM /
   Negotiate ou un proxy ``https://`` évitent ce problème.

Signaler une vulnérabilité
--------------------------

Ouvrez un ticket sur https://github.com/sanjuant/iziproxy/issues en
décrivant le problème sans détails exploitables ; nous conviendrons d'un
canal privé pour la suite.
