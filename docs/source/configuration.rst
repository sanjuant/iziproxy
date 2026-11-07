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
``auth_type``      ``basic`` ou ``ntlm`` (détecté sinon)
``no_proxy``       Exclusions supplémentaires (chaîne ou liste)
``interactive``    ``False`` pour ne jamais demander d'identifiants
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
* ``auth_type`` : ``basic`` ou ``ntlm`` (absent : choisi d'après ``Proxy-Authenticate``)
* ``no_proxy`` : exclusions propres à l'environnement

Exclusions
----------

Formats acceptés (séparés par virgules, points-virgules ou espaces) :

* ``example.com`` ou ``.example.com`` : le domaine et ses sous-domaines
* ``*.example.com``, ``10.*``, ``intra*`` : jokers
* ``10.0.0.0/8`` : réseau CIDR
* ``host:8080`` : hôte et port
* ``<local>`` : noms sans point (format Windows)
* ``*`` : tout

``localhost``, ``127.0.0.0/8`` et ``::1`` sont toujours contactés directement.

Détection de l'environnement
----------------------------

Méthode ``auto`` : variables d'environnement, puis nom d'hôte, puis IP, puis
``local``.

Variables lues : ``IZIPROXY_ENV``, ``PROXY_ENV``, ``APP_ENV``,
``ENVIRONMENT``, ``ENVIRONMENT_TYPE``, ``DEPLOY_ENV``, ``STAGE`` (et
``env_var_name``). Les valeurs reconnues sont des alias explicites
(``production``, ``prd`` → ``prod`` ; ``staging``, ``qa``, ``uat``,
``recette`` → ``dev``...). La variable ``ENV`` n'est pas lue : les shells
l'utilisent pour désigner un fichier.

Identifiants
------------

Ordre de recherche :

1. ``username`` / ``password`` du constructeur
2. Identifiants présents dans l'URL du proxy
3. Variables ``IZI_USERNAME``, ``IZI_PASSWORD``, ``IZI_DOMAIN`` (ou ``PROXY_*``)
4. Fichier ``.env`` (``./.env``, ``~/.config/.env``, ``~/.env``)
5. Trousseau système (service ``iziproxy_<env>-<auth_type>``)
6. NTLM sous Windows : session courante (aucune saisie)
7. Saisie interactive (fenêtre Windows, tkinter ou console), puis
   enregistrement dans le trousseau

``credentials.prompt: false`` ou ``interactive=False`` désactive l'étape 7.
