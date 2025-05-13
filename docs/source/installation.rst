Installation
============

IziProxy est disponible sur PyPI et peut être installé avec pip.

Installation basique
-------------------

Pour installer IziProxy avec les fonctionnalités de base :

.. code-block:: bash

   pip install iziproxy

Installation complète (avec support NTLM)
----------------------------------------

Pour installer IziProxy avec le support pour l'authentification NTLM (recommandé pour les environnements Windows d'entreprise) :

.. code-block:: bash

   pip install iziproxy[ntlm]

Cette installation inclut les dépendances supplémentaires suivantes :

* ``ntlm-auth`` - Pour l'authentification NTLM
* ``pycryptodomex`` - Pour le support des algorithmes de hachage nécessaires à NTLM

Dépendances
-----------

IziProxy dépend des bibliothèques suivantes :

* ``requests`` - Pour les requêtes HTTP
* ``PyYAML`` - Pour la lecture des fichiers de configuration
* ``keyring`` - Pour le stockage sécurisé des identifiants
* ``cryptography`` - Pour le chiffrement des mots de passe en mémoire

Installation depuis les sources
------------------------------

Pour installer IziProxy depuis les sources :

.. code-block:: bash

   git clone https://github.com/votrenom/iziproxy.git
   cd iziproxy
   pip install -e .

Installation pour le développement
--------------------------------

Pour installer IziProxy avec les dépendances de développement :

.. code-block:: bash

   pip install -e ".[dev]"

Cela installera :

* ``pytest`` et ``pytest-cov`` pour les tests
* ``black`` et ``flake8`` pour le formatage du code
* ``sphinx`` pour la génération de la documentation

Compatibilité Python
-------------------

IziProxy est compatible avec Python 3.7 et versions supérieures.
