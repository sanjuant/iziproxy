IziProxy
========

.. image:: https://img.shields.io/pypi/v/iziproxy.svg
   :target: https://pypi.org/project/iziproxy/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/iziproxy.svg
   :target: https://pypi.org/project/iziproxy/
   :alt: Python versions

.. image:: https://img.shields.io/github/license/sanjuant/iziproxy.svg
   :target: https://github.com/sanjuant/iziproxy/blob/master/LICENSE
   :alt: License

Les proxys d'entreprise en une ligne de Python.

.. code-block:: python

   import iziproxy

   iziproxy.install()

Après cette ligne, ``requests``, ``urllib``, ``httpx``, ``aiohttp`` et les
commandes lancées par ``subprocess`` (pip, git, curl...) passent le proxy de
l'entreprise, quel qu'il soit : sans authentification, Basic, NTLM /
Negotiate, ou décrit par un fichier PAC. Sans proxy, rien n'est modifié : le
même code marche sur le poste du développeur, en recette et en production.

Ce que fait IziProxy
--------------------

* **Trouve le proxy** : paramètres, fichier ``iziproxy.yml``, variables
  ``HTTP(S)_PROXY``, registre Windows, macOS, GNOME, KDE, fichier PAC
  (évalué pour chaque URL).
* **Respecte les exclusions** requête par requête : ``NO_PROXY``,
  ``ProxyOverride`` Windows (``<local>``, ``*.corp.com``, ``10.*``), CIDR.
* **Découvre l'authentification** (réponse ``407``) : Basic ou NTLM /
  Negotiate ; sous Windows, la session ouverte suffit pour NTLM.
* **Trouve les identifiants** : paramètres, variables, ``.env``, trousseau du
  système, ou saisie (une seule fois, puis mémorisée).
* **Configure vos clients** : requests, httpx, aiohttp, urllib3, urllib,
  http.client, websockets, gRPC, Selenium, Playwright.
* **Remplace cntlm** : en trois lignes, un proxy local sur ``127.0.0.1:3128``
  (port au choix) qui s'authentifie à la place de pip, git, curl ou d'un
  navigateur (voir :doc:`usage`).

Par où commencer
----------------

* :doc:`quickstart` — ``install()``, et quoi ajouter si la détection ne suffit pas.
* :doc:`usage` — la classe ``IziProxy`` pour configurer un client précis.
* :doc:`clients` — chaque client HTTP, son adaptateur et ses limites.
* :doc:`configuration` — paramètres, fichier YAML, ordre de priorité.
* :doc:`security` — ce qui protège vos identifiants, et vos responsabilités.

.. toctree::
   :maxdepth: 2
   :caption: Guide

   installation
   quickstart
   usage
   clients
   configuration
   security

.. toctree::
   :maxdepth: 2
   :caption: Référence

   api
   advanced
   examples
   migration
   contributing

Indices et tables
-----------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
