"""
Tests unitaires pour le module config_manager
"""

import unittest
from unittest.mock import patch, mock_open

import yaml

from iziproxy.config_manager import ConfigManager
from iziproxy.secure_config import SecurePassword


class TestConfigManager(unittest.TestCase):
    """Tests pour la classe ConfigManager"""

    def setUp(self):
        """Initialisation avant chaque test"""
        self.test_config = {
            "environments": {
                "local": {
                    "proxy_url": None,
                    "requires_auth": False
                },
                "dev": {
                    "proxy_url": "http://dev-proxy.example.com:8080",
                    "requires_auth": True,
                    "auth_type": "basic"
                },
                "prod": {
                    "proxy_url": "http://prod-proxy.example.com:8080",
                    "requires_auth": True,
                    "auth_type": "ntlm"
                }
            }
        }

    def test_default_config(self):
        """Vérifie que la configuration par défaut est chargée si aucun fichier n'est trouvé"""
        # Patcher os.path.exists pour que tous les chemins retournent False
        with patch('os.path.exists', return_value=False):
            manager = ConfigManager()
            
            # Vérifier que la configuration contient les sections attendues
            self.assertIn("environments", manager.config)
            self.assertIn("environment_detection", manager.config)
            self.assertIn("system_proxy", manager.config)

    def test_load_yaml_config(self):
        """Vérifie le chargement d'une configuration depuis un fichier YAML"""
        # Créer un mock pour open() qui retourne notre configuration de test
        yaml_content = yaml.dump(self.test_config)
        mock_file = mock_open(read_data=yaml_content)
        
        # Patcher os.path.exists pour indiquer que le fichier existe
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_file):
            
            manager = ConfigManager("test_config.yml")
            
            # Vérifier que la configuration a été chargée
            self.assertEqual(manager.config["environments"]["dev"]["proxy_url"], 
                           "http://dev-proxy.example.com:8080")
            self.assertTrue(manager.config["environments"]["dev"]["requires_auth"])

    def test_get_environment_config(self):
        """Vérifie la méthode get_environment_config"""
        # Patcher _load_yaml_config pour utiliser notre configuration de test
        with patch.object(ConfigManager, '_load_yaml_config'):
            manager = ConfigManager()
            manager.config = self.test_config
            
            # Tester la récupération de la configuration dev
            dev_config = manager.get_environment_config("dev")
            self.assertEqual(dev_config["proxy_url"], "http://dev-proxy.example.com:8080")
            self.assertTrue(dev_config["requires_auth"])
            self.assertEqual(dev_config["auth_type"], "basic")
            
            # Tester un environnement qui n'existe pas
            unknown_config = manager.get_environment_config("unknown")
            self.assertEqual(unknown_config, {})

    def test_get_credentials_from_config(self):
        """Vérifie la récupération des identifiants depuis la configuration"""
        # Patcher _load_yaml_config pour utiliser notre configuration de test
        # Et patcher _get_credentials_from_env_vars pour simuler des identifiants
        with patch.object(ConfigManager, '_load_yaml_config'), \
             patch.object(ConfigManager, '_get_credentials_from_env_vars', 
                         return_value=("testuser", "testpass", "TESTDOMAIN")):
            
            manager = ConfigManager()
            manager.config = self.test_config
            
            # Tester la récupération des identifiants pour dev (requires_auth=True)
            username, password, domain = manager.get_credentials("dev")
            self.assertEqual(username, "testuser")
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), "testpass")
            self.assertEqual(domain, "TESTDOMAIN")
            
            # Tester pour local (requires_auth=False)
            username, password, domain = manager.get_credentials("local")
            self.assertIsNone(username)
            self.assertIsNone(password)
            self.assertIsNone(domain)

    def test_get_credentials_from_env_vars(self):
        """Vérifie la récupération des identifiants depuis les variables d'environnement"""
        # Définir les variables d'environnement
        env_vars = {
            'PROXY_USERNAME': 'envuser',
            'PROXY_PASSWORD': 'envpass',
            'PROXY_DOMAIN': 'ENVDOMAIN'
        }
        
        with patch.object(ConfigManager, '_load_yaml_config'), \
             patch.dict('os.environ', env_vars):
            
            manager = ConfigManager()
            manager.config = self.test_config
            
            # Tester la récupération des identifiants pour dev
            username, password, domain = manager.get_credentials("dev")
            pwd = password.get_password()
            self.assertEqual(username, "envuser")
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), "envpass")
            self.assertEqual(domain, "ENVDOMAIN")

    def test_get_credentials_from_keyring(self):
        """Vérifie la récupération des identifiants depuis keyring"""
        # Patcher les méthodes pour que _get_credentials_from_env_vars ne retourne rien
        # et que _get_credentials_from_keyring retourne des identifiants
        
        # Patcher keyring.get_password pour simuler un mot de passe stocké
        with patch.object(ConfigManager, '_load_yaml_config'), \
             patch.object(ConfigManager, '_get_credentials_from_env_vars', return_value=(None, None, None)), \
             patch.object(ConfigManager, '_get_credentials_from_keyring', 
                         return_value=("keyringuser", "keyringpass", None)):
            
            manager = ConfigManager()
            manager.config = self.test_config
            
            # Tester la récupération des identifiants pour dev
            username, password, domain = manager.get_credentials("dev")
            self.assertEqual(username, "keyringuser")
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), "keyringpass")
