Contribuer au projet
==================

Cette section explique comment contribuer au projet IziProxy.

Installation de l'environnement de développement
----------------------------------------------

1. Cloner le dépôt :

.. code-block:: bash

   git clone https://github.com/votrenom/iziproxy.git
   cd iziproxy

2. Créer et activer un environnement virtuel :

.. code-block:: bash

   python -m venv venv
   source venv/bin/activate  # Sur Windows : venv\Scripts\activate

3. Installer les dépendances de développement :

.. code-block:: bash

   pip install -e ".[dev]"

Exécuter les tests
----------------

Exécuter les tests avec pytest :

.. code-block:: bash

   pytest

Pour vérifier la couverture de code :

.. code-block:: bash

   pytest --cov=iziproxy

Style de code
-----------

Nous utilisons Black pour le formatage du code :

.. code-block:: bash

   black src tests

Et Flake8 pour la vérification de la qualité du code :

.. code-block:: bash

   flake8 src tests

Soumettre une Pull Request
------------------------

1. Créez une branche pour votre contribution :

.. code-block:: bash

   git checkout -b feature/ma-nouvelle-fonctionnalite

2. Faites vos modifications et testez-les.

3. Assurez-vous que tous les tests passent :

.. code-block:: bash

   pytest

4. Formatez le code avec Black :

.. code-block:: bash

   black src tests

5. Vérifiez la qualité du code avec Flake8 :

.. code-block:: bash

   flake8 src tests

6. Committez vos modifications :

.. code-block:: bash

   git commit -am "Ajout de ma nouvelle fonctionnalité"

7. Poussez vos modifications vers votre fork :

.. code-block:: bash

   git push origin feature/ma-nouvelle-fonctionnalite

8. Créez une Pull Request sur GitHub.

Documentation
-----------

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
-----------------

.. code-block:: text

   iziproxy/
   ├── src/
   │   └── iziproxy/           # Package principal
   │       ├── __init__.py     # Exports principaux
   │       ├── proxy_manager.py # Classe principale IziProxy
   │       ├── config_manager.py # Gestion de la configuration
   │       ├── env_detector.py  # Détection d'environnement
   │       ├── proxy_detector.py # Détection de proxy
   │       ├── secure_config.py # Classes de sécurité
   │       ├── ntlm_auth.py    # Support NTLM
   │       └── logger.py       # Utilitaires de logging
   ├── tests/                  # Tests unitaires
   ├── docs/                   # Documentation
   ├── examples/               # Exemples d'utilisation
   ├── pyproject.toml          # Configuration de build
   ├── setup.py                # Script d'installation
   ├── README.md               # Documentation principale
   └── LICENSE                 # Licence du projet

Ajouter une nouvelle fonctionnalité
---------------------------------

1. Commencez par créer des tests pour votre fonctionnalité.
2. Implémentez la fonctionnalité.
3. Documentez la fonctionnalité avec des docstrings et dans la documentation Sphinx.
4. Ajoutez un exemple d'utilisation dans le répertoire ``examples/``.
5. Mettez à jour le fichier README.md si nécessaire.

Signaler un bug
-------------

Signalez les bugs sur le tracker de problèmes GitHub. Incluez :

1. La version d'IziProxy que vous utilisez.
2. Votre environnement Python et système d'exploitation.
3. Les étapes pour reproduire le bug.
4. Le comportement attendu et le comportement observé.
5. Tout message d'erreur ou traceback.

Demande de fonctionnalité
-----------------------

Les demandes de fonctionnalités sont les bienvenues ! Pour proposer une nouvelle fonctionnalité :

1. Assurez-vous que la fonctionnalité n'existe pas déjà ou n'est pas déjà demandée.
2. Ouvrez une issue sur GitHub avec le tag "feature request".
3. Décrivez la fonctionnalité et les cas d'utilisation.
4. Si possible, proposez une implémentation.
