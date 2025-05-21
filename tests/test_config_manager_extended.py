"""
Tests unitaires étendus pour le module config_manager
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, mock_open

import yaml

from iziproxy.config_manager import ConfigManager
from iziproxy.secure_config import SecurePassword


class TestConfigManagerExtended(unittest.TestCase):
    """Tests étendus pour la classe ConfigManager"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Configuration de test
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
            },
            "environment_detection": {
                "method": "auto"
            },
            "system_proxy": {
                "use_system_proxy": True,
                "detect_pac": True
            }
        }
        
        # Nettoyer les variables d'environnement
        self.clean_env_vars()
        
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.clean_env_vars()
        
    def clean_env_vars(self):
        """Nettoie les variables d'environnement pour les tests"""
        for var in ["PROXY_USERNAME", "PROXY_PASSWORD", "PROXY_DOMAIN",
                    "IZI_USERNAME", "IZI_PASSWORD", "IZI_DOMAIN",
                    "USERDOMAIN", "COMPUTERNAME", "USERNAME", "USER"]:
            if var in os.environ:
                del os.environ[var]

    def test_config_file_search_order(self):
        """Vérifie l'ordre de recherche des fichiers de configuration"""
        # Patcher Path.exists au lieu de os.path.exists
        with patch('pathlib.Path.exists') as mock_exists, \
                patch('pathlib.Path.expanduser', return_value=Path("nonexistent_config.yml")), \
                patch('pathlib.Path.resolve', return_value=Path("nonexistent_config.yml")):

            # Simuler un fichier qui n'existe pas
            mock_exists.return_value = False

            # Créer un gestionnaire de configuration avec un chemin spécifié qui n'existe pas
            cm = ConfigManager("nonexistent_config.yml")

            # Vérifier que le path.exists a été appelé
            mock_exists.assert_called()

    def test_config_loading_with_valid_file(self):
        """Vérifie le chargement depuis un fichier valide"""
        # Créer un fichier de configuration temporaire avec mode texte
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yml") as temp_file:
                temp_file_path = temp_file.name
                yaml.dump(self.test_config, temp_file)

            # Créer un gestionnaire avec le fichier temporaire
            cm = ConfigManager(temp_file_path)

            # Vérifier que la configuration a été chargée correctement
            self.assertIn("environments", cm.config)
            self.assertIn("system_proxy", cm.config)
        finally:
            # Nettoyage
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                
    def test_config_loading_with_invalid_file(self):
        """Vérifie le chargement avec un fichier invalide"""
        # Créer un fichier de configuration temporaire avec un contenu YAML invalide
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as temp_file:
            temp_file.write(b"invalid: yaml: content: - [ } ]")
        
        try:
            # Créer un gestionnaire avec le fichier temporaire
            cm = ConfigManager(temp_file.name)
            
            # Vérifier que la configuration par défaut a été utilisée
            self.assertIsNotNone(cm.config)
            self.assertIn("environments", cm.config)
        finally:
            # Nettoyer
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
    
    def test_config_loading_with_empty_file(self):
        """Vérifie le chargement avec un fichier vide"""
        # Créer un fichier de configuration temporaire vide
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as temp_file:
            pass
        
        try:
            # Créer un gestionnaire avec le fichier temporaire
            cm = ConfigManager(temp_file.name)
            
            # Vérifier que la configuration par défaut a été utilisée
            self.assertIsNotNone(cm.config)
            self.assertIn("environments", cm.config)
        finally:
            # Nettoyer
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
    
    def test_deep_merge(self):
        """Vérifie la fusion profonde de configurations"""
        # Créer un gestionnaire de configuration
        cm = ConfigManager()
        
        # Définir une configuration cible
        target = {
            "key1": "value1",
            "key2": {
                "subkey1": "subvalue1",
                "subkey2": "subvalue2"
            }
        }
        
        # Définir une configuration source pour la fusion
        source = {
            "key2": {
                "subkey2": "new_subvalue2",
                "subkey3": "subvalue3"
            },
            "key3": "value3"
        }
        
        # Effectuer la fusion
        cm._deep_merge(target, source)
        
        # Vérifier que la fusion a été effectuée correctement
        self.assertEqual(target["key1"], "value1")  # Inchangé
        self.assertEqual(target["key2"]["subkey1"], "subvalue1")  # Inchangé
        self.assertEqual(target["key2"]["subkey2"], "new_subvalue2")  # Modifié
        self.assertEqual(target["key2"]["subkey3"], "subvalue3")  # Ajouté
        self.assertEqual(target["key3"], "value3")  # Ajouté
    
    def test_get_credentials_with_env_vars(self):
        """Vérifie la récupération des identifiants depuis les variables d'environnement"""
        # Configurer des variables d'environnement
        os.environ["PROXY_USERNAME"] = "envuser"
        os.environ["PROXY_PASSWORD"] = "envpass"
        os.environ["PROXY_DOMAIN"] = "ENVDOMAIN"
        
        # Créer un gestionnaire avec une configuration sans identifiants
        with patch.object(ConfigManager, '_load_yaml_config'):
            cm = ConfigManager()
            cm.config = self.test_config.copy()
            
            # Récupérer les identifiants pour dev (requires_auth=True)
            username, password, domain = cm.get_credentials("dev")
            
            # Vérifier qu'ils viennent des variables d'environnement
            self.assertEqual(username, "envuser")
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), "envpass")
            self.assertEqual(domain, "ENVDOMAIN")
    
    def test_load_dotenv(self):
        """Vérifie le chargement depuis un fichier .env"""
        # Créer un fichier .env temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix=".env") as temp_file:
            temp_file.write(b"IZI_USERNAME=dotenvuser\nIZI_PASSWORD=dotenvpass\n")
        
        try:
            # Patcher os.path.exists et open pour simuler le fichier .env
            with patch('os.path.exists', return_value=True), \
                 patch('builtins.open', mock_open(read_data="IZI_USERNAME=dotenvuser\nIZI_PASSWORD=dotenvpass\n")):
                
                # Créer un gestionnaire
                cm = ConfigManager()
                
                # Charger les variables depuis .env
                env_vars = cm._load_dotenv()
                
                # Vérifier que les variables ont été chargées
                self.assertEqual(env_vars["IZI_USERNAME"], "dotenvuser")
                self.assertEqual(env_vars["IZI_PASSWORD"], "dotenvpass")
        finally:
            # Nettoyer
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
    
    def test_get_credentials_from_dotenv(self):
        """Vérifie la récupération des identifiants depuis .env"""
        # Patcher _load_dotenv pour simuler un fichier .env
        with patch.object(ConfigManager, '_load_dotenv', return_value={
                "IZI_USERNAME": "dotenvuser",
                "IZI_PASSWORD": "dotenvpass",
                "IZI_DOMAIN": "DOTENVDOMAIN"
            }):
            
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Récupérer les identifiants
            username, password, domain = cm._get_credentials_from_env_vars(None, None, None)
            
            # Vérifier qu'ils viennent du fichier .env
            self.assertEqual(username, "dotenvuser")
            self.assertEqual(password, "dotenvpass")
            self.assertEqual(domain, "DOTENVDOMAIN")
    
    def test_get_current_session_info_windows(self):
        """Vérifie la récupération des informations de session sur Windows"""
        # Simuler Windows
        with patch('platform.system', return_value="Windows"), \
             patch.dict('os.environ', {
                 "USERNAME": "winuser",
                 "USERDOMAIN": "WINDOMAIN",
                 "COMPUTERNAME": "WINPC"
             }):
            
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Récupérer les infos de session
            username, domain = cm._get_current_session_info()
            
            # Vérifier les informations
            self.assertEqual(username, "winuser")
            self.assertEqual(domain, "WINDOMAIN")
    
    def test_get_current_session_info_unix(self):
        """Vérifie la récupération des informations de session sur Unix"""
        # Simuler Unix/Linux
        with patch('platform.system', return_value="Linux"), \
                patch.dict('os.environ', {"USER": "linuxuser"}), \
                patch('socket.getfqdn', return_value="hostname.example.com"):

            # Créer un gestionnaire
            cm = ConfigManager()

            # Récupérer les infos de session
            username, domain = cm._get_current_session_info()

            # Vérifier les informations
            self.assertEqual(username, "linuxuser")
            self.assertEqual(domain, "example.com")
    
    def test_windows_workgroup(self):
        """Vérifie la détection de groupe de travail Windows (pas de domaine AD)"""
        # Simuler Windows avec un groupe de travail (USERDOMAIN = COMPUTERNAME)
        with patch('platform.system', return_value="Windows"), \
             patch.dict('os.environ', {
                 "USERNAME": "winuser",
                 "USERDOMAIN": "WINPC",
                 "COMPUTERNAME": "WINPC"
             }):
            
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Récupérer les infos de session
            username, domain = cm._get_current_session_info()
            
            # USERDOMAIN = COMPUTERNAME signifie qu'il n'y a pas de vrai domaine AD
            self.assertEqual(username, "winuser")
            self.assertIsNone(domain)
    
    def test_windows_domain_username(self):
        """Vérifie la détection de domaine à partir du format domain\\username"""
        # Simuler Windows avec un nom d'utilisateur au format domain\\username
        with patch('platform.system', return_value="Windows"), \
             patch('getpass.getuser', return_value="DOMAIN\\winuser"):
            
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Récupérer les infos de session
            username, domain = cm._get_current_session_info()
            
            # Le domaine devrait être extrait du nom d'utilisateur
            self.assertEqual(username, "winuser")
            self.assertEqual(domain, "DOMAIN")
    
    @patch('getpass.getpass')
    @patch('builtins.input')
    def test_interactive_credentials(self, mock_input, mock_getpass):
        """Vérifie la demande interactive d'identifiants"""
        # Configurer les mocks
        mock_input.side_effect = ["interactiveuser", "INTERACTIVEDOMAIN"]
        mock_getpass.return_value = "interactivepass"
        
        # Créer un gestionnaire
        with patch.object(ConfigManager, '_store_credentials_in_keyring'):
            cm = ConfigManager()
            
            # Récupérer les identifiants de manière interactive
            username, password, domain = cm._get_credentials_interactively(
                None, None, None, "keyring_service", "username_key", "service_name", "ntlm"
            )
            
            # Vérifier les identifiants
            self.assertEqual(username, "interactiveuser")
            self.assertEqual(password, "interactivepass")
            self.assertEqual(domain, "INTERACTIVEDOMAIN")
    
    @patch('getpass.getpass')
    @patch('builtins.input')
    def test_interactive_credentials_basic_auth(self, mock_input, mock_getpass):
        """Vérifie la demande interactive d'identifiants pour l'authentification basique"""
        # Configurer les mocks
        mock_input.return_value = "interactiveuser"
        mock_getpass.return_value = "interactivepass"
        
        # Créer un gestionnaire
        with patch.object(ConfigManager, '_store_credentials_in_keyring'):
            cm = ConfigManager()
            
            # Récupérer les identifiants de manière interactive pour l'authentification basique
            username, password, domain = cm._get_credentials_interactively(
                None, None, None, "keyring_service", "username_key", "service_name", "basic"
            )
            
            # Vérifier les identifiants (pas de domaine pour l'authentification basique)
            self.assertEqual(username, "interactiveuser")
            self.assertEqual(password, "interactivepass")
            self.assertEqual(domain, None)
            
            # input() ne devrait pas être appelé pour le domaine en authentification basique
            self.assertEqual(mock_input.call_count, 1)
    
    def test_store_credentials_in_keyring(self):
        """Vérifie le stockage des identifiants dans keyring"""
        # Patcher keyring.set_password
        with patch('keyring.set_password') as mock_set_password:
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Stocker des identifiants
            cm._store_credentials_in_keyring(
                "keyringuser", "keyringpass", "KEYRINGDOMAIN",
                "keyring_service", "username_key", "service_name"
            )
            
            # Vérifier que keyring a été appelé correctement
            mock_set_password.assert_any_call("keyring_service", "keyringuser", "keyringpass")
            mock_set_password.assert_any_call("service_name", "username_key", "keyringuser")
    
    def test_store_credentials_in_keyring_error(self):
        """Vérifie la gestion des erreurs lors du stockage dans keyring"""
        # Patcher keyring.set_password pour lever une exception
        with patch('keyring.set_password', side_effect=Exception("Keyring error")):
            # Créer un gestionnaire
            cm = ConfigManager()
            
            # Stocker des identifiants (ne devrait pas lever d'exception)
            cm._store_credentials_in_keyring(
                "keyringuser", "keyringpass", "KEYRINGDOMAIN",
                "keyring_service", "username_key", "service_name"
            )
            
            # Pas d'assertion, on vérifie juste que ça ne plante pas
    
    def test_get_credentials_priority(self):
        """Vérifie la priorité des sources d'identifiants"""
        # Configurer plusieurs sources d'identifiants
        os.environ["PROXY_USERNAME"] = "envuser"
        os.environ["PROXY_PASSWORD"] = "envpass"
        
        # Créer un gestionnaire avec des identifiants dans la configuration
        config_with_creds = self.test_config.copy()
        
        with patch.object(ConfigManager, '_load_yaml_config'):
            cm = ConfigManager()
            cm.config = config_with_creds
            
            # Patcher les méthodes pour vérifier l'ordre d'appel
            methods = [
                '_get_credentials_from_env_vars',
                '_get_credentials_from_keyring',
                '_get_credentials_from_session',
                '_get_credentials_interactively'
            ]
            
            mocks = {}
            for method in methods:
                mocks[method] = patch.object(cm, method, return_value=(None, None, None))
            
            # Définir un comportement pour que la méthode env_vars retourne des identifiants
            with patch.object(cm, '_get_credentials_from_env_vars', return_value=("envuser", "envpass", None)):
                # Utiliser tous les mocks
                with mocks['_get_credentials_from_keyring'], \
                     mocks['_get_credentials_from_session'], \
                     mocks['_get_credentials_interactively']:
                    
                    # Récupérer les identifiants
                    username, password, domain = cm.get_credentials("dev")
                    
                    # Vérifier qu'ils viennent des variables d'environnement
                    self.assertEqual(username, "envuser")
                    self.assertIsInstance(password, SecurePassword)

    def test_securepassword_conversion(self):
        """Vérifie la conversion en SecurePassword"""
        # Créer un gestionnaire avec une configuration simulée
        with patch.object(ConfigManager, '_load_yaml_config'):
            cm = ConfigManager()

            # Créer une configuration d'environnement qui nécessite une authentification
            mock_env_config = {
                "requires_auth": True,
                "auth_type": "basic"
            }

            # Mock la méthode get_environment_config pour retourner notre configuration simulée
            with patch.object(cm, 'get_environment_config', return_value=mock_env_config):
                # Mock la méthode _get_credentials_from_env_vars pour retourner des identifiants
                with patch.object(cm, '_get_credentials_from_env_vars', return_value=("testuser", "testpass", "TESTDOMAIN")):
                    # Appeler la méthode à tester
                    username, password, domain = cm.get_credentials("dev")

                    # Vérifier les résultats
                    self.assertEqual(username, "testuser")
                    self.assertEqual(domain, "TESTDOMAIN")
                    # Vérifier que le mot de passe a été converti en SecurePassword
                    self.assertIsInstance(password, SecurePassword)


if __name__ == '__main__':
    unittest.main()
