Installation
============

IziProxy nécessite Python 3.8 ou plus récent.

.. code-block:: bash

   pip install iziproxy               # proxy sans authentification ou Basic
   pip install "iziproxy[ntlm]"       # + NTLM / Negotiate (pyspnego)
   pip install "iziproxy[pac]"        # + fichiers PAC (pypac)
   pip install "iziproxy[truststore]" # + certificats vérifiés par le système (Python 3.10+)
   pip install "iziproxy[all]"        # les trois

Les options ``httpx`` et ``aiohttp`` installent ces clients pour leurs
adaptateurs dédiés (voir :doc:`clients`).

Dépendances
-----------

* ``requests`` et ``urllib3`` : requêtes HTTP
* ``PyYAML`` : fichier de configuration
* ``keyring`` : trousseau système pour les mots de passe
* ``cryptography`` : mots de passe non stockés en clair en mémoire (voir :doc:`security`)
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
