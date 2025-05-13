"""
Tests unitaires pour le module proxy_manager
"""

import os
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

from iziproxy.proxy_manager import IziProxy
from iziproxy.secure_config import SecurePassword, SecureProxyConfig


class TestIziProxy(unittest.TestCase):
    """Tests pour la classe IziProxy"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Patcher les dépendances pour isoler les tests
        self.env_detector_patcher = patch('iziproxy.proxy_manager.EnvironmentDetector')
        self.config_manager_patcher = patch('iziproxy.proxy_manager.ConfigManager')
        self.proxy_detector_patcher = patch('iziproxy.proxy_manager.ProxyDetector')
        
        # Créer les mocks
        self.mock_env_detector = self.env_detector_patcher.start()
        self.mock_config_manager = self.config_manager_patcher.start()
        self.mock_proxy_detector = self.proxy_detector_patcher.start()
        
        # Configurer les mocks
        self.mock_env_detector_instance = MagicMock()
        self.mock_env_detector_instance.detect_environment.return_value = "dev"
        self.mock_env_detector.return_value = self.mock_env_detector_instance
        
        self.mock_config_manager_instance = MagicMock()
        self.mock_config_manager_instance.get_config.return_value = {
            "environments": {
                "dev": {
                    "proxy_url": "http://dev-proxy.example.com:8080",
                    "requires_auth": True,
                    "auth_type": "basic"
                }
            }
        }
        self.mock_config_manager_instance.get_environment_config.return_value = {
            "proxy_url": "http://dev-proxy.example.com:8080",
            "requires_auth": True,
            "auth_type": "basic"
        }
        self.mock_config_manager_instance.get_credentials.return_value = ("testuser", SecurePassword("testpass"), "")
        self.mock_config_manager.return_value = self.mock_config_manager_instance
        
        self.mock_proxy_detector_instance = MagicMock()
        self.mock_proxy_detector_instance.detect_system_proxy.return_value = {
            "http": "http://system-proxy.example.com:8080",
            "https": "http://system-proxy.example.com:8080"
        }
        self.mock_proxy_detector.return_value = self.mock_proxy_detector_instance
        
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.env_detector_patcher.stop()
        self.config_manager_patcher.stop()
        self.proxy_detector_patcher.stop()
        
        # Réinitialiser les variables d'environnement
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy']:
            if var in os.environ:
                del os.environ[var]

    def test_init_default(self):
        """Vérifie l'initialisation par défaut"""
        proxy = IziProxy()
        
        # Vérifier que les dépendances ont été initialisées
        self.mock_config_manager.assert_called_once()
        self.mock_env_detector.assert_called_once()
        self.mock_proxy_detector.assert_called_once()
        
        # Vérifier que l'environnement a été détecté
        self.mock_env_detector_instance.detect_environment.assert_called_once()
        self.assertEqual(proxy.current_env, "dev")

    def test_init_with_override(self):
        """Vérifie l'initialisation avec des paramètres de substitution"""
        proxy = IziProxy(
            proxy_url="http://custom-proxy.example.com:8080",
            environment="prod",
            username="customuser",
            password="custompass",
            domain="customdomain",
            debug=True
        )
        
        # La détection d'environnement ne devrait pas être appelée
        self.mock_env_detector_instance.detect_environment.assert_not_called()
        
        # Vérifier les paramètres de substitution
        self.assertEqual(proxy.proxy_url_override, "http://custom-proxy.example.com:8080")
        self.assertEqual(proxy.current_env, "prod")
        self.assertEqual(proxy.username_override, "customuser")
        self.assertEqual(proxy.password_override, "custompass")
        self.assertEqual(proxy.domain_override, "customdomain")

    def test_get_proxy_config_with_explicit_url(self):
        """Vérifie la récupération de la configuration avec URL explicite"""
        # Configurer le mock pour simuler une URL explicite
        proxy = IziProxy(proxy_url="http://explicit-proxy.example.com:8080")
        
        config = proxy.get_proxy_config()
        
        # L'URL explicite devrait être utilisée
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://explicit-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://explicit-proxy.example.com:8080")
        
        # Le proxy système ne devrait pas être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_not_called()

    def test_get_proxy_config_from_env_config(self):
        """Vérifie la récupération de la configuration depuis la config d'environnement"""
        proxy = IziProxy()  # Pas d'URL explicite
        
        # Mock pour simuler une URL dans la config d'environnement
        self.mock_config_manager_instance.get_environment_config.return_value = {
            "proxy_url": "http://env-proxy.example.com:8080",
            "requires_auth": False
        }
        
        config = proxy.get_proxy_config()
        
        # L'URL de la config d'environnement devrait être utilisée
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://env-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://env-proxy.example.com:8080")
        
        # Le proxy système ne devrait pas être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_not_called()

    def test_get_proxy_config_system_detection(self):
        """Vérifie la détection automatique du proxy système"""
        # Configurer pour qu'il n'y ait pas d'URL explicite
        self.mock_config_manager_instance.get_environment_config.return_value = {
            "proxy_url": None,
            "requires_auth": False
        }
        
        proxy = IziProxy()
        config = proxy.get_proxy_config()
        
        # Le proxy système devrait être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_called_once()
        
        # La configuration devrait contenir les URLs système
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://system-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://system-proxy.example.com:8080")

    def test_get_proxy_config_with_auth(self):
        """Vérifie l'ajout de l'authentification à l'URL de proxy"""
        # Configurer pour qu'il y ait une URL explicite avec auth requise
        self.mock_config_manager_instance.get_environment_config.return_value = {
            "proxy_url": "http://auth-proxy.example.com:8080",
            "requires_auth": True,
            "auth_type": "basic"
        }
        self.mock_config_manager_instance.get_credentials.return_value = ("authuser", SecurePassword("authpass"), "")
        
        proxy = IziProxy()
        config = proxy.get_proxy_config()
        
        # Vérifier que l'URL contient les identifiants
        real_config = config.get_real_config()
        self.assertIn("authuser:authpass@", real_config["http"])
        self.assertIn("authuser:authpass@", real_config["https"])

    def test_create_session(self):
        """Vérifie la création d'une session requests configurée"""
        with patch('iziproxy.proxy_manager.requests.Session') as mock_session:
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance
            
            proxy = IziProxy(proxy_url="http://session-proxy.example.com:8080")
            session = proxy.create_session()
            
            # La méthode configure_session devrait être appelée
            self.assertEqual(session, mock_session_instance)
            self.assertEqual(session.proxies, proxy.get_proxy_dict())
            self.assertFalse(session.trust_env)

    def test_configure_session(self):
        """Vérifie la configuration d'une session existante"""
        with patch('iziproxy.proxy_manager.requests.Session') as mock_session:
            session = mock_session()
            
            proxy = IziProxy(proxy_url="http://config-proxy.example.com:8080")
            configured_session = proxy.configure_session(session)
            
            # La session devrait être configurée
            self.assertEqual(configured_session, session)
            self.assertEqual(session.proxies, proxy.get_proxy_dict())
            self.assertFalse(session.trust_env)

    def test_set_environment_variables(self):
        """Vérifie la définition des variables d'environnement"""
        # Configurer pour qu'il y ait une URL explicite
        proxy = IziProxy(proxy_url="http://env-var-proxy.example.com:8080")
        
        # Vérifier qu'aucune variable n'est définie avant
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
            self.assertNotIn(var, os.environ)
        
        # Définir les variables
        env_vars = proxy.set_environment_variables()
        
        # Vérifier que les variables sont définies
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
            self.assertIn(var, os.environ)
            self.assertEqual(os.environ[var], "http://env-var-proxy.example.com:8080")
            self.assertEqual(env_vars[var], "http://env-var-proxy.example.com:8080")

    def test_clear_environment_variables(self):
        """Vérifie la suppression des variables d'environnement"""
        # Définir d'abord les variables
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy']:
            os.environ[var] = "http://test-proxy.example.com:8080"
        
        proxy = IziProxy()
        proxy.clear_environment_variables()
        
        # Vérifier que les variables sont supprimées
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy']:
            self.assertNotIn(var, os.environ)

    def test_refresh(self):
        """Vérifie le rafraîchissement des détections"""
        proxy = IziProxy()
        
        # Configurer les mocks pour vérifier qu'ils sont appelés
        proxy.proxy_detector.clear_cache = MagicMock()
        
        # Effectuer le rafraîchissement
        result = proxy.refresh()
        
        # Vérifier que les méthodes appropriées ont été appelées
        self.mock_env_detector_instance.detect_environment.assert_called_with(force_refresh=True)
        proxy.proxy_detector.clear_cache.assert_called_once()
        
        # Le résultat devrait être l'instance elle-même (pour le chaînage)
        self.assertEqual(result, proxy)

    def test_get_current_environment(self):
        """Vérifie la récupération de l'environnement actuel"""
        proxy = IziProxy(environment="test_env")
        
        env = proxy.get_current_environment()
        
        self.assertEqual(env, "test_env")

    def test_get_credentials(self):
        """Vérifie la récupération des identifiants"""
        proxy = IziProxy()
        
        username, password, domain = proxy.get_credentials()
        
        # Les identifiants devraient provenir du ConfigManager
        self.assertEqual(username, "testuser")
        self.assertIsInstance(password, SecurePassword)
        self.assertEqual(password.get_password(), "testpass")
        self.assertEqual(domain, "")

    def test_set_debug(self):
        """Vérifie l'activation/désactivation du mode débogage"""
        with patch('iziproxy.proxy_manager.logger') as mock_logger:
            proxy = IziProxy()
            
            # Activer le débogage
            result = proxy.set_debug(True)
            mock_logger.setLevel.assert_called_with(logging.DEBUG)
            
            # Désactiver le débogage
            result = proxy.set_debug(False)
            mock_logger.setLevel.assert_called_with(logging.WARNING)
            
            # Le résultat devrait être l'instance elle-même (pour le chaînage)
            self.assertEqual(result, proxy)
            
    @patch('iziproxy.proxy_manager.requests')
    def test_patch_requests(self, mock_requests):
        """Vérifie le monkey patching du module requests"""
        proxy = IziProxy()
        
        # Sauvegarder les méthodes originales
        original_get = mock_requests.get
        original_post = mock_requests.post
        
        # Appliquer le patch
        result = proxy.patch_requests()
        
        # Vérifier que les méthodes ont été remplacées
        self.assertNotEqual(mock_requests.get, original_get)
        self.assertNotEqual(mock_requests.post, original_post)
        
        # Le résultat devrait être l'instance elle-même (pour le chaînage)
        self.assertEqual(result, proxy)
        
    @patch('iziproxy.proxy_manager.requests')
    @patch('iziproxy.proxy_manager.requests.api')
    def test_unpatch_requests(self, mock_requests_api, mock_requests):
        """Vérifie la restauration du module requests après monkey patching"""
        proxy = IziProxy()
        
        # Configurer les mocks
        mock_requests_api.get = MagicMock()
        mock_requests_api.post = MagicMock()
        
        # Appliquer le patch puis restaurer
        proxy.patch_requests()
        result = proxy.unpatch_requests()
        
        # Vérifier que les méthodes ont été restaurées
        self.assertEqual(mock_requests.get, mock_requests_api.get)
        self.assertEqual(mock_requests.post, mock_requests_api.post)
        
        # Le résultat devrait être l'instance elle-même (pour le chaînage)
        self.assertEqual(result, proxy)


# Importer à la fin pour éviter des problèmes avec les imports
import logging
