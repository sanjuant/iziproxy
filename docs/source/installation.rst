Installation
============

IziProxy nécessite Python 3.8 ou plus récent.

.. code-block:: bash

   pip install iziproxy            # proxys sans authentification ou Basic
   pip install iziproxy[ntlm]      # + NTLM / Negotiate (pyspnego)
   pip install iziproxy[pac]       # + fichiers PAC (pypac)
   pip install iziproxy[all]       # tout

Dépendances
-----------

* ``requests`` et ``urllib3`` : requêtes HTTP
* ``PyYAML`` : fichier de configuration
* ``keyring`` : trousseau système pour les mots de passe
* ``cryptography`` : chiffrement des mots de passe en mémoire
* ``pyspnego`` (option ``ntlm``) : jetons NTLM / Negotiate, SSPI sous Windows,
  MD4 intégré (compatible OpenSSL 3)
* ``pypac`` (option ``pac``) : évaluation des fichiers PAC

Installation de développement
-----------------------------

.. code-block:: bash

   git clone https://github.com/sanjuant/iziproxy.git
   cd iziproxy
   pip install -e .[dev]
   pytest
