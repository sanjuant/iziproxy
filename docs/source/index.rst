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

   import iziproxy

   iziproxy.install()   # requests, urllib, httpx, pip, git... passent le proxy

Sans proxy, rien n'est modifié : le même code fonctionne partout. Voir
:doc:`quickstart` pour les options, et :doc:`usage` pour le contrôle fin avec
la classe ``IziProxy``.


Contenu
-------

.. toctree::
   :maxdepth: 2
   
   installation
   quickstart
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
