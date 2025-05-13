"""
Configuration pytest pour les tests d'IziProxy
"""

import sys
import os
import logging

# Ajouter le répertoire src au PYTHONPATH pour permettre l'importation des modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Désactiver les logs pendant les tests pour éviter de polluer la sortie
logging.basicConfig(level=logging.ERROR)
