"""
Tests d'intégration pour IziProxy
"""

import unittest
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock, mock_open

from iziproxy import IziProxy, SecurePassword, SecureProxyConfig
from iziproxy.config_manager import ConfigManager
from iziproxy.env_detector import EnvironmentDetector
from iziproxy.proxy_detector import ProxyDetector


class TestIziProxyIntegration(unittest.TestCase):
    """Tests d'intégration pour IziProxy"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Nettoyer les variables d'environnement
        self.clean_env_vars()
        
        # Créer un fichier de configuration temporaire
        self.config_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yml")
        self.config_data = {
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
                "method": "auto",
                "hostname_patterns": {
                    "local": ["local", "laptop"],
                    "dev": ["dev", "staging"],
                    "prod": ["prod"]
                }
            },
            "credentials": {
                "store_method": "keyring",
                "username": "testuser",
                "password": "testpass",
                "domain": "TESTDOMAIN"
            },
            "system_proxy": {
                "use_system_proxy": True,
                "detect_pac": True
            }
        }
        
        with open(self.config_file.name, 'w') as f:
            yaml.dump(self.config_data, f)
            
    def tearDown(self):
        """Nettoyage après chaque test"""
        # Supprimer le fichier temporaire
        if os.path.exists(self.config_file.name):
            os.unlink(self.config_file.name)
            
        # Réinitialiser les variables d'environnement
        self.clean_env_vars()
        
    def clean_env_vars(self):
        """Nettoie les variables d'environnement pour les tests"""
        for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                    "ENVIRONMENT", "ENV", "PROXY_USERNAME", "PROXY_PASSWORD",
                    "IZI_USERNAME", "IZI_PASSWORD"]:
            if var in os.environ:
                del os.environ[var]

    def test_full_integration(self):
        """Vérifie l'intégration complète avec tous les composants réels"""
        # Patcher la détection d'environnement pour renvoyer 'dev'
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
            # Créer une instance IziProxy avec le fichier de configuration réel
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Vérifier que l'environnement est correctement détecté
            self.assertEqual(proxy.current_env, 'dev')
            
            # Vérifier que la configuration est correctement chargée
            env_config = proxy.config_manager.get_environment_config('dev')
            self.assertEqual(env_config['proxy_url'], 'http://dev-proxy.example.com:8080')
            self.assertTrue(env_config['requires_auth'])
            
            # Vérifier que la configuration proxy est correctement créée
            proxy_config = proxy.get_proxy_config()
            self.assertIsInstance(proxy_config, SecureProxyConfig)
            
            # Obtenir le dictionnaire proxy utilisable
            proxy_dict = proxy.get_proxy_dict()
            self.assertIn('http', proxy_dict)
            self.assertIn('https', proxy_dict)

    def test_environment_detection_flow(self):
        """Vérifie le flux de détection d'environnement"""
        # Configurer une détection d'environnement depuis les variables d'environnement
        os.environ['ENV'] = 'prod'
        
        # Créer une instance sans patcher la détection d'environnement
        proxy = IziProxy(config_path=self.config_file.name)
        
        # Vérifier que l'environnement est correctement détecté
        self.assertEqual(proxy.current_env, 'prod')
        
        # Vérifier que la configuration d'environnement correspondante est utilisée
        env_config = proxy.config_manager.get_environment_config('prod')
        self.assertEqual(env_config['proxy_url'], 'http://prod-proxy.example.com:8080')
        self.assertEqual(env_config['auth_type'], 'ntlm')

    def test_proxy_detection_flow(self):
        """Vérifie le flux de détection de proxy"""
        # Configurer un proxy système via variables d'environnement
        os.environ['HTTP_PROXY'] = 'http://env-proxy.example.com:8080'
        os.environ['HTTPS_PROXY'] = 'http://env-proxy.example.com:8443'
        
        # Patcher pour forcer l'environnement 'local' (qui n'a pas de proxy configuré)
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='local'):
            proxy = IziProxy(config_path=self.config_file.name)
            
            # La détection automatique devrait utiliser le proxy des variables d'environnement
            proxy_dict = proxy.get_proxy_dict()
            
            self.assertEqual(proxy_dict['http'], 'http://env-proxy.example.com:8080')
            self.assertEqual(proxy_dict['https'], 'http://env-proxy.example.com:8443')

    def test_credentials_flow(self):
        """Vérifie le flux d'obtention des identifiants"""
        # Patcher la détection d'environnement pour renvoyer 'dev'
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
            # Configurer les identifiants via variables d'environnement
            os.environ['PROXY_USERNAME'] = 'envuser'
            os.environ['PROXY_PASSWORD'] = 'envpass'
            
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Obtenir les identifiants
            username, password, domain = proxy.get_credentials()
            
            # Vérifier que les variables d'environnement sont utilisées 
            # avec priorité sur la configuration
            self.assertEqual(username, 'envuser')
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), 'envpass')

    def test_keyring_credentials_flow(self):
        """Vérifie le flux d'obtention des identifiants depuis keyring"""
        # Patcher la détection d'environnement pour renvoyer 'dev'
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'), \
             patch('keyring.get_password', return_value='keyringpass'):
            
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Obtenir les identifiants
            username, password, domain = proxy.get_credentials()
            
            # Vérifier que keyring est utilisé
            self.assertEqual(username, 'testuser')  # Depuis la config
            self.assertIsInstance(password, SecurePassword)
            self.assertEqual(password.get_password(), 'keyringpass')  # Depuis keyring

    def test_override_parameters(self):
        """Vérifie que les paramètres d'overrides fonctionnent correctement"""
        proxy = IziProxy(
            config_path=self.config_file.name,
            proxy_url='http://override-proxy.example.com:8080',
            environment='prod',
            username='overrideuser',
            password='overridepass',
            domain='OVERRIDEDOMAIN',
            debug=True
        )
        
        # Vérifier que les overrides sont utilisés
        self.assertEqual(proxy.proxy_url_override, 'http://override-proxy.example.com:8080')
        self.assertEqual(proxy.current_env, 'prod')
        self.assertEqual(proxy.username_override, 'overrideuser')
        self.assertEqual(proxy.password_override, 'overridepass')
        
        # Vérifier que la configuration proxy utilise le proxy override
        proxy_dict = proxy.get_proxy_dict()
        self.assertEqual(proxy_dict['http'], 'http://override-proxy.example.com:8080')
        
        # Vérifier que les identifiants utilisent les overrides
        username, password, domain = proxy.get_credentials()
        self.assertEqual(username, 'overrideuser')
        self.assertEqual(password.get_password(), 'overridepass')
        self.assertEqual(domain, 'OVERRIDEDOMAIN')

    def test_session_creation(self):
        """Vérifie la création et configuration d'une session requests"""
        # Patcher requests.Session
        with patch('requests.Session') as mock_session:
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance
            
            # Patcher la détection d'environnement 
            with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
                proxy = IziProxy(config_path=self.config_file.name)
                
                # Créer une session
                session = proxy.create_session()
                
                # Vérifier que la session est correctement configurée
                self.assertEqual(session, mock_session_instance)
                self.assertEqual(session.proxies, proxy.get_proxy_dict())
                self.assertFalse(session.trust_env)

    def test_pac_detection_integration(self):
        """Vérifie l'intégration avec la détection de fichier PAC"""
        # Patcher la détection d'environnement
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='local'):
            # Patcher ProxyDetector._detect_system_settings pour simuler un PAC
            with patch.object(ProxyDetector, '_detect_system_settings', 
                            return_value={'pac_url': 'http://internal.example.com/proxy.pac'}), \
                patch.object(ProxyDetector, '_fetch_pac', 
                            return_value='function FindProxyForURL(url, host) { return "PROXY proxy.example.com:8080"; }'):
                
                # Simuler pypac disponible
                with patch.dict('sys.modules', {'pypac': MagicMock()}):
                    # Créer un mock pour PACFile et find_proxy_for_url
                    pac_mock = MagicMock()
                    pac_mock.find_proxy_for_url.return_value = "PROXY proxy.example.com:8080"
                    
                    # Patcher le parser de pypac
                    with patch('pypac.parser.PACFile', return_value=pac_mock):
                        proxy = IziProxy(config_path=self.config_file.name)
                        
                        # Obtenir la configuration proxy
                        proxy_dict = proxy.get_proxy_dict()
                        
                        # Vérifier que le PAC est utilisé
                        self.assertEqual(proxy_dict['http'], 'http://proxy.example.com:8080')
                        self.assertEqual(proxy_dict['https'], 'http://proxy.example.com:8080')

    def test_environment_variables_setting(self):
        """Vérifie la définition des variables d'environnement"""
        # Patcher la détection d'environnement
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Définir les variables d'environnement
            env_vars = proxy.set_environment_variables()
            
            # Vérifier que les variables sont définies
            self.assertEqual(os.environ['HTTP_PROXY'], 'http://dev-proxy.example.com:8080')
            self.assertEqual(os.environ['HTTPS_PROXY'], 'http://dev-proxy.example.com:8080')
            self.assertEqual(os.environ['http_proxy'], 'http://dev-proxy.example.com:8080')
            self.assertEqual(os.environ['https_proxy'], 'http://dev-proxy.example.com:8080')
            
            # Nettoyer
            proxy.clear_environment_variables()
            
            # Vérifier que les variables sont supprimées
            self.assertNotIn('HTTP_PROXY', os.environ)
            self.assertNotIn('HTTPS_PROXY', os.environ)

    def test_authentication_handling(self):
        """Vérifie la gestion de l'authentification"""
        # Patcher la détection d'environnement pour renvoyer 'dev'
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'), \
             patch('requests.Session') as mock_session, \
             patch('requests.auth.HTTPProxyAuth') as mock_auth:
            
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance
            
            mock_auth_instance = MagicMock()
            mock_auth.return_value = mock_auth_instance
            
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Créer une session
            session = proxy.create_session()
            
            # Vérifier que l'authentification est configurée
            mock_auth.assert_called_once_with('testuser', 'testpass')
            self.assertEqual(session.auth, mock_auth_instance)

    def test_config_loading_priority(self):
        """Vérifie la priorité de chargement des fichiers de configuration"""
        # Créer un deuxième fichier de configuration avec des valeurs différentes
        config_file2 = tempfile.NamedTemporaryFile(delete=False, suffix=".yml")
        config_data2 = {
            "environments": {
                "dev": {
                    "proxy_url": "http://alternate-proxy.example.com:8080",
                    "requires_auth": True
                }
            }
        }
        with open(config_file2.name, 'w') as f:
            yaml.dump(config_data2, f)
        
        try:
            # Créer une instance avec le premier fichier spécifié explicitement
            with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
                proxy1 = IziProxy(config_path=self.config_file.name)
                proxy_dict1 = proxy1.get_proxy_dict()
                
                # Créer une seconde instance avec le deuxième fichier
                proxy2 = IziProxy(config_path=config_file2.name)
                proxy_dict2 = proxy2.get_proxy_dict()
                
                # Vérifier que les configurations sont différentes
                self.assertEqual(proxy_dict1['http'], 'http://dev-proxy.example.com:8080')
                self.assertEqual(proxy_dict2['http'], 'http://alternate-proxy.example.com:8080')
                
        finally:
            # Nettoyer le second fichier
            if os.path.exists(config_file2.name):
                os.unlink(config_file2.name)
    
    @patch('requests.api')
    def test_monkey_patching(self, mock_requests_api):
        """Vérifie le monkey patching du module requests"""
        import requests
        
        # Sauvegarder les méthodes originales
        original_get = requests.get
        original_post = requests.post
        
        # Créer une instance
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Patcher requests
            proxy.patch_requests()
            
            # Vérifier que les méthodes ont été remplacées
            self.assertNotEqual(requests.get, original_get)
            self.assertNotEqual(requests.post, original_post)
            
            # Restaurer requests
            proxy.unpatch_requests()
            
            # Vérifier que les méthodes ont été restaurées
            self.assertEqual(requests.get, mock_requests_api.get)
            self.assertEqual(requests.post, mock_requests_api.post)

    def test_refresh_method(self):
        """Vérifie la méthode de rafraîchissement"""
        # Patcher la détection d'environnement
        with patch.object(EnvironmentDetector, 'detect_environment', return_value='dev'):
            proxy = IziProxy(config_path=self.config_file.name)
            
            # Patcher les méthodes pour vérifier qu'elles sont appelées
            proxy.env_detector.detect_environment = MagicMock(return_value='prod')
            proxy.proxy_detector.clear_cache = MagicMock()
            
            # Effectuer le rafraîchissement
            result = proxy.refresh()
            
            # Vérifier que les méthodes appropriées ont été appelées
            proxy.env_detector.detect_environment.assert_called_with(force_refresh=True)
            proxy.proxy_detector.clear_cache.assert_called_once()
            
            # Vérifier que l'environnement a été mis à jour
            self.assertEqual(proxy.current_env, 'prod')
            
            # Le résultat devrait être l'instance elle-même (pour le chaînage)
            self.assertEqual(result, proxy)


if __name__ == '__main__':
    unittest.main()
