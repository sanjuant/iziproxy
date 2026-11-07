Documentation d'IziProxy
========================

.. image:: https://img.shields.io/pypi/v/iziproxy.svg
   :target: https://pypi.org/project/iziproxy/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/iziproxy.svg
   :target: https://pypi.org/project/iziproxy/
   :alt: Python versions

.. image:: https://img.shields.io/github/license/sanjuant/iziproxy.svg
   :target: https://github.com/sanjuant/iziproxy/blob/master/LICENSE
   :alt: License

Une bibliothèque Python pour la gestion simplifiée des proxys d'entreprise.

Fonctionnalités principales
---------------------------

* 🔍 Détection automatique de l'environnement (local, dev, prod)
* 🌐 Détection automatique des configurations de proxy système
* 🔐 Gestion sécurisée des identifiants proxy
* 🔄 Support pour l'authentification basique et NTLM
* 📋 Compatibilité avec les fichiers PAC
* 🛠️ API simple et intuitive

Installation
------------

.. code-block:: bash

   pip install iziproxy

Pour le support de l'authentification NTLM (recommandé pour les environnements Windows d'entreprise) :

.. code-block:: bash

   pip install iziproxy[ntlm]

Guide de démarrage rapide
-------------------------

.. code-block:: python

   from iziproxy import IziProxy

   # Création avec détection automatique
   proxy = IziProxy()

   # Obtenir une session requests préconfigurée
   session = proxy.create_session()
   response = session.get('https://example.com')

   # Utiliser comme dictionnaire de proxy standard
   proxies = proxy.get_proxy_dict()

   # Définir les variables d'environnement
   proxy.set_environment_variables()
   
   # ...utiliser d'autres bibliothèques qui respectent les variables d'environnement...
   
   # Nettoyer les variables d'environnement
   proxy.clear_environment_variables()


Contenu
-------

.. toctree::
   :maxdepth: 2
   
   installation
   usage
   clients
   configuration
   api
   examples
   advanced
   migration
   contributing

Indices et tables
-----------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
