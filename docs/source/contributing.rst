Contribuer au projet
====================

Cette section explique comment contribuer au projet IziProxy.

Installation de l'environnement de développement
------------------------------------------------

1. Cloner le dépôt :

.. code-block:: bash

   git clone https://github.com/sanjuant/iziproxy.git
   cd iziproxy

2. Créer et activer un environnement virtuel (Python 3.11 ou plus récent) :

.. code-block:: bash

   python -m venv venv
   source venv/bin/activate  # Sur Windows : venv\Scripts\activate

3. Installer les dépendances de développement :

.. code-block:: bash

   pip install -e ".[dev]"

Exécuter les tests
------------------

Exécuter les tests avec pytest :

.. code-block:: bash

   pytest

Les versions minimales déclarées dans ``pyproject.toml`` (plus anciennes
versions sans faille connue) se vérifient dans un environnement installé
« au plus bas », avec Python 3.11 :

.. code-block:: bash

   uv venv --python 3.11 .venv-min
   uv pip install --python .venv-min --resolution lowest-direct -e ".[dev]"
   .venv-min/Scripts/python -m pytest   # Linux, macOS : .venv-min/bin/python

Pour vérifier la couverture de code :

.. code-block:: bash

   pytest --cov=iziproxy

Style de code
-------------

Flake8 vérifie le code (configuration dans ``.flake8`` : lignes de 120
caractères au plus) :

.. code-block:: bash

   flake8 src tests

Soumettre une Pull Request
--------------------------

1. Créez une branche pour votre contribution :

.. code-block:: bash

   git checkout -b feature/ma-nouvelle-fonctionnalite

2. Faites vos modifications et testez-les.

3. Assurez-vous que tous les tests passent :

.. code-block:: bash

   pytest

4. Vérifiez la qualité du code avec Flake8 :

.. code-block:: bash

   flake8 src tests

5. Committez vos modifications :

.. code-block:: bash

   git commit -am "Ajout de ma nouvelle fonctionnalité"

6. Poussez vos modifications vers votre fork :

.. code-block:: bash

   git push origin feature/ma-nouvelle-fonctionnalite

7. Créez une Pull Request sur GitHub.

Intégration continue
--------------------

GitHub Actions (``.github/workflows/ci.yml``) lance à chaque push sur
``master``, à chaque Pull Request et chaque lundi :

* les tests sous Linux et Windows, Python 3.11 à 3.14, avec les dernières
  versions des dépendances, plus Python 3.11 avec les versions minimales ;
* flake8 ;
* la documentation Sphinx en mode strict (``-W``).

Publier une version
-------------------

1. Changez ``version`` dans ``pyproject.toml``. C'est le seul endroit à
   modifier : ``iziproxy.__version__`` et la documentation lisent la version
   du paquet.
2. Décrivez les changements visibles dans :doc:`migration`.
3. Commitez sur ``master``, puis créez et poussez le tag :

.. code-block:: bash

   git tag -a v0.8.0 -m "iziproxy 0.8.0"
   git push origin master v0.8.0

Le tag déclenche ``.github/workflows/release.yml`` :

#. le workflow vérifie que le tag correspond à la version ;
#. il relance tous les tests ;
#. il construit le paquet et le contrôle (``twine check``) ;
#. il le publie sur PyPI ;
#. il crée la release GitHub.

Read the Docs reconstruit la documentation de son côté.

La publication passe par Trusted Publishing, donc sans jeton PyPI. Il faut
l'avoir déclarée une fois sur pypi.org, dans les réglages du projet
(*Publishing* > *GitHub*) :

* dépôt : ``sanjuant/iziproxy`` ;
* workflow : ``release.yml`` ;
* environnement : ``pypi``.

Une version publiée sur PyPI ne peut plus être remplacée : un correctif
demande un nouveau numéro.

Documentation
-------------

La documentation est générée avec Sphinx. Pour construire la documentation localement :

.. code-block:: bash

   cd docs
   make html

La documentation générée se trouvera dans ``docs/build/html``.

Pour les docstrings, nous utilisons le format Google Style :

.. code-block:: python

   def ma_fonction(parametre):
       """
       Description de la fonction
       
       Args:
           parametre: Description du paramètre
           
       Returns:
           Description de la valeur de retour
           
       Raises:
           Exception: Description de l'exception
       """
       return parametre

Structure du projet
-------------------

.. code-block:: text

   iziproxy/
   ├── src/
   │   └── iziproxy/           # Package principal
   │       ├── __init__.py       # Exports publics
   │       ├── bootstrap.py      # iziproxy.install() / uninstall()
   │       ├── proxy_manager.py  # Classe IziProxy
   │       ├── local_proxy.py    # Proxy local façon cntlm (jeton, CONNECT, NTLM)
   │       ├── adapters.py       # Adaptateur requests (choix du proxy par requête)
   │       ├── integrations/     # httpx, aiohttp, urllib3, urllib, http.client, gRPC, navigateurs
   │       ├── ntlm_auth.py      # Adaptateur NTLM / Negotiate (pyspnego), connexions réutilisées
   │       ├── proxy_detector.py # Proxy système et fichiers PAC
   │       ├── pac_evaluator.py  # Évaluation des PAC dans un processus séparé (délai maximal)
   │       ├── proxy_utils.py    # Exclusions, URLs, sonde d'authentification, TLS
   │       ├── config_manager.py # Configuration YAML et identifiants
   │       ├── password_manager.py # Saisie interactive (Windows, tkinter, console)
   │       ├── env_detector.py   # Détection de l'environnement
   │       ├── secure_config.py  # SecurePassword, SecureProxyConfig
   │       └── logger.py         # Journalisation
   ├── tests/
   │   ├── servers.py            # Vrai proxy local (Basic/NTLM) et serveurs HTTP(S)
   │   └── test_*.py
   ├── docs/                   # Documentation
   ├── examples/               # Exemples d'utilisation
   ├── pyproject.toml          # Configuration de build
   ├── setup.py                # Script d'installation
   ├── README.md               # Documentation principale
   └── LICENSE                 # Licence du projet

Conventions
-----------

* Code (noms, messages de journal et d'erreur) en anglais.
* Commentaires et docstrings en français.
* Les tests ne doivent dépendre ni du réseau externe, ni de la configuration
  de la machine (``tests/conftest.py`` isole l'environnement, le registre et
  le trousseau). Préférez les tests d'intégration avec ``tests/servers.py``
  aux mocks.

Ajouter une nouvelle fonctionnalité
-----------------------------------

1. Commencez par créer des tests pour votre fonctionnalité.
2. Implémentez la fonctionnalité.
3. Documentez la fonctionnalité avec des docstrings et dans la documentation Sphinx.
4. Ajoutez un exemple d'utilisation dans le répertoire ``examples/``.
5. Mettez à jour le fichier README.md si nécessaire.

Signaler un bug
---------------

Signalez les bugs sur le tracker de problèmes GitHub. Incluez :

1. La version d'IziProxy que vous utilisez.
2. Votre environnement Python et système d'exploitation.
3. Les étapes pour reproduire le bug.
4. Le comportement attendu et le comportement observé.
5. Tout message d'erreur ou traceback.

Demande de fonctionnalité
-------------------------

Les demandes de fonctionnalités sont les bienvenues ! Pour proposer une nouvelle fonctionnalité :

1. Assurez-vous que la fonctionnalité n'existe pas déjà ou n'est pas déjà demandée.
2. Ouvrez une issue sur GitHub avec le tag "feature request".
3. Décrivez la fonctionnalité et les cas d'utilisation.
4. Si possible, proposez une implémentation.
