"""
Tests unitaires pour le module logger
"""

import io
import logging
import sys
import unittest
from unittest.mock import patch

from iziproxy.logger import get_logger


class TestLogger(unittest.TestCase):
    """Tests pour les fonctionnalités de logging"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Réinitialiser l'état du système de logging
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
        # Supprimer les loggers créés
        for name in list(logging.Logger.manager.loggerDict.keys()):
            if name.startswith('iziproxy'):
                del logging.Logger.manager.loggerDict[name]

    def test_get_logger_basic(self):
        """Vérifie la création basique d'un logger"""
        logger = get_logger("iziproxy.test")
        
        # Vérifier les propriétés du logger
        self.assertEqual(logger.name, "iziproxy.test")
        self.assertEqual(logger.level, logging.INFO)  # Niveau par défaut
        self.assertEqual(len(logger.handlers), 1)
        
        # Vérifier que le handler est un StreamHandler
        handler = logger.handlers[0]
        self.assertIsInstance(handler, logging.StreamHandler)
        self.assertEqual(handler.stream, sys.stdout)

    def test_get_logger_with_level(self):
        """Vérifie la création d'un logger avec un niveau spécifique"""
        logger = get_logger("iziproxy.test", level=logging.DEBUG)
        
        # Vérifier le niveau du logger
        self.assertEqual(logger.level, logging.DEBUG)
        
        # Vérifier que le handler a le même niveau
        handler = logger.handlers[0]
        self.assertEqual(handler.level, logging.DEBUG)

    def test_logger_output(self):
        """Vérifie que le logger produit la sortie attendue"""
        # Rediriger la sortie pour la capturer
        stream = io.StringIO()
        with patch('sys.stdout', stream):
            logger = get_logger("iziproxy.test")
            
            # Envoyer un message de log
            logger.info("Test message")
            
            # Vérifier que le message a été formaté correctement
            output = stream.getvalue()
            self.assertIn("iziproxy.test", output)
            self.assertIn("INFO", output)
            self.assertIn("Test message", output)

    def test_logger_format(self):
        """Vérifie que le format du logger est correct"""
        logger = get_logger("iziproxy.test")
        
        # Vérifier le format du handler
        handler = logger.handlers[0]
        formatter = handler.formatter
        
        self.assertIsInstance(formatter, logging.Formatter)
        
        # Le format doit contenir les éléments attendus
        format_str = formatter._fmt
        self.assertIn("%(name)s", format_str)
        self.assertIn("%(levelname)s", format_str)
        self.assertIn("%(message)s", format_str)
        self.assertIn("%(asctime)s", format_str)

    def test_get_logger_singleton(self):
        """Vérifie que get_logger retourne le même logger pour le même nom"""
        logger1 = get_logger("iziproxy.test")
        logger2 = get_logger("iziproxy.test")
        
        # Les deux variables devraient référencer le même objet
        self.assertIs(logger1, logger2)
        
        # Vérifier qu'un seul handler a été ajouté
        self.assertEqual(len(logger1.handlers), 1)

    def test_log_levels(self):
        """Vérifie que les différents niveaux de log fonctionnent correctement"""
        # Rediriger la sortie pour la capturer
        stream = io.StringIO()
        with patch('sys.stdout', stream):
            logger = get_logger("iziproxy.test", level=logging.INFO)
            
            # Les messages DEBUG ne devraient pas apparaître avec le niveau INFO
            logger.debug("Debug message")
            self.assertEqual(stream.getvalue(), "")
            
            # Les messages INFO devraient apparaître
            logger.info("Info message")
            self.assertIn("Info message", stream.getvalue())
            
            # Réinitialiser le stream
            stream.seek(0)
            stream.truncate()
            
            # Changer le niveau à DEBUG
            logger.setLevel(logging.DEBUG)
            logger.handlers[0].setLevel(logging.DEBUG)
            
            # Les messages DEBUG devraient maintenant apparaître
            logger.debug("Debug message")
            self.assertIn("Debug message", stream.getvalue())

if __name__ == '__main__':
    unittest.main()
