Configuration
=============

Aucune configuration n'est nécessaire. Elle permet de forcer un
comportement par environnement.

Paramètres du constructeur
--------------------------

=================  ==============================================================
Paramètre          Rôle
=================  ==============================================================
``config_path``    Fichier YAML à utiliser
``proxy_url``      Proxy explicite (prioritaire sur toute détection)
``pac_url``        Fichier PAC (URL http/https/file ou chemin local)
``environment``    Environnement forcé (``local``, ``dev``, ``prod``)
``username``       Utilisateur du proxy
``password``       Mot de passe du proxy
``domain``         Domaine NTLM
``auth_type``      ``basic``, ``ntlm`` ou ``negotiate`` (détecté sinon)
``no_proxy``       Exclusions supplémentaires (chaîne ou liste)
``interactive``    ``False`` pour ne jamais demander d'identifiants
``verify``         Certificats du proxy https:// et du PAC : ``True``, ``False``
                   ou chemin d'autorités (voir plus bas)
``auth_proxies``   Proxys autorisés à recevoir les identifiants (voir
                   :doc:`security`) ; mêmes formats que ``no_proxy``
``debug``          Journaux détaillés sur stderr
=================  ==============================================================

Fichier YAML
------------

Emplacements recherchés : ``./iziproxy.yml``, ``./iziproxy.yaml``,
``~/.config/iziproxy.yml``, ``~/.config/iziproxy.yaml``, ``~/.iziproxy.yml``,
``~/.iziproxy.yaml``.

.. literalinclude:: ../../examples/config_example.yml
   :language: yaml

Clés par environnement :

* ``proxy_url`` : proxy explicite
* ``pac_url`` : fichier PAC
* ``requires_auth`` : ``true``, ``false`` ou absent (détection par sondage)
* ``auth_type`` : ``basic``, ``ntlm`` ou ``negotiate`` (équivalent de ``ntlm`` :
  le schéma est choisi parmi ceux du proxy) ; absent : choisi d'après
  ``Proxy-Authenticate``. Toute autre valeur lève ``ValueError``
* ``no_proxy`` : exclusions propres à l'environnement
* ``auth_proxies`` : proxys autorisés à recevoir les identifiants (aussi
  accepté à la racine du fichier, pour tous les environnements)

Exclusions
----------

Formats acceptés (séparés par virgules, points-virgules ou espaces) :

* ``example.com`` ou ``.example.com`` : le domaine et ses sous-domaines
* ``*.example.com``, ``10.*``, ``intra*`` : jokers
* ``10.0.0.0/8`` : réseau CIDR
* ``host:8080`` : hôte et port (``http://host/`` utilise le port 80 et n'est
  donc pas couvert)
* ``<local>`` : noms sans point (format Windows)
* ``*`` : tout

``localhost``, ``127.0.0.0/8`` et ``::1`` sont toujours contactés directement.

Détection de l'environnement
----------------------------

Méthode ``auto`` : variable ``IZIPROXY_ENV``, puis nom d'hôte, puis IP, puis
``local``.

``IZIPROXY_ENV`` accepte ``local``, ``dev``, ``prod`` et des alias explicites
(``production``, ``prd`` → ``prod`` ; ``staging``, ``qa``, ``uat``,
``recette`` → ``dev``...) ; une valeur inconnue est signalée dans les
journaux et ignorée. Aucune autre variable (``APP_ENV``, ``ENVIRONMENT``...)
n'est lue : pour réutiliser la vôtre, passez
``environment=os.environ["APP_ENV"]``.

Identifiants
------------

Ordre de recherche :

1. ``username`` / ``password`` du constructeur
2. Identifiants présents dans l'URL du proxy
3. Variables ``IZIPROXY_USERNAME``, ``IZIPROXY_PASSWORD``, ``IZIPROXY_DOMAIN``
4. Fichier ``.env`` (``./.env``, ``~/.config/.env``, ``~/.env``)
5. Trousseau système (service ``iziproxy_<env>-<auth_type>``)
6. NTLM sous Windows : session courante (aucune saisie)
7. Saisie interactive (fenêtre Windows, tkinter ou console), puis
   enregistrement dans le trousseau

``credentials.prompt: false`` ou ``interactive=False`` désactive l'étape 7.

Variables d'environnement
-------------------------

IziProxy ne lit que ces variables :

.. list-table::
   :header-rows: 1

   * - Variable
     - Rôle
   * - ``IZIPROXY_USERNAME``, ``IZIPROXY_PASSWORD``, ``IZIPROXY_DOMAIN``
     - Identifiants du proxy (aussi lus dans un fichier ``.env``)
   * - ``IZIPROXY_ENV``
     - Environnement forcé (``local``, ``dev``, ``prod`` ou un alias)
   * - ``HTTP_PROXY``, ``HTTPS_PROXY``, ``NO_PROXY`` (ou en minuscules)
     - Proxy déclaré par le système (désactivable : ``system_proxy.detect_env_vars: false``)

``ALL_PROXY`` n'est pas lu. ``install()`` et ``set_environment_variables()``
écrivent ``HTTP_PROXY``, ``HTTPS_PROXY`` et ``NO_PROXY`` en majuscules et en
minuscules (curl ne lit que les minuscules) et les restaurent à la fin ;
``refresh()`` relit les valeurs d'origine, pas celles qu'IziProxy a écrites.

Certificats : proxy https:// et fichier PAC
-------------------------------------------

Un proxy déclaré en ``https://`` est joint en TLS, y compris par
l'adaptateur NTLM et le proxy local ; une cible HTTPS est alors chiffrée une
seconde fois dans le tunnel. Un fichier PAC servi en ``https://`` est
téléchargé en vérifiant son certificat.

Le paramètre ``verify`` (ou la clé ``verify`` du YAML) règle ces deux
vérifications :

* ``True`` (défaut) : autorités du système. Avec
  ``pip install iziproxy[truststore]``, la vérification est confiée au
  système lui-même (autorités d'entreprise déployées par stratégie,
  trousseau macOS, certificats intermédiaires manquants) ; sinon, magasin lu
  par OpenSSL complété par certifi.
* ``"/chemin/ca.pem"`` (fichier ou répertoire) : seules ces autorités.
* ``False`` : aucune vérification (déconseillé).

Il n'y a aucun repli silencieux : un PAC dont le certificat est refusé est
ignoré (avertissement dans les journaux), un proxy refusé fait échouer la
requête. Les certificats des sites restent vérifiés par chaque client
(``verify`` de requests, de httpx...).
