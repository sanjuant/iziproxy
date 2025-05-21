"""
Tests unitaires pour le module proxy_manager
"""
import logging
import os
import unittest
from unittest.mock import patch, MagicMock

from iziproxy.proxy_manager import IziProxy
from iziproxy.secure_config import SecurePassword


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

        # Configuration des environnements
        self.env_configs = {
            "local": {
                "proxy_url": "http://env-var-proxy.example.com:8080",
                "requires_auth": False,
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

        self.mock_config_manager_instance = MagicMock()
        self.mock_config_manager_instance.get_config.return_value = {
            "environments": self.env_configs
        }

        # Utiliser side_effect pour retourner différentes configs selon l'environnement
        self.mock_config_manager_instance.get_environment_config.side_effect = lambda env: self.env_configs.get(env, {})

        # Configuration des identifiants selon l'environnement
        def get_credentials_side_effect(env, service=None):
            if env == "local":
                return (None, None, None)
            elif env == "dev":
                return ("testuser", SecurePassword("testpass"), "")
            elif env == "prod":
                return ("ntlmuser", SecurePassword("ntlmpass"), "domain")
            else:
                return (None, None, None)

        self.mock_config_manager_instance.get_credentials.side_effect = get_credentials_side_effect
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
        # Utiliser l'environnement dev qui a l'authentification basique configurée
        proxy = IziProxy(proxy_url="http://explicit-proxy.example.com:8080", environment="dev")

        config = proxy.get_proxy_config()

        # L'URL explicite avec authentification devrait être utilisée
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://testuser:testpass@explicit-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://testuser:testpass@explicit-proxy.example.com:8080")

        # Vérifier que l'URL stockée dans self._proxy_url contient les identifiants
        self.assertEqual(proxy._proxy_url, "http://testuser:testpass@explicit-proxy.example.com:8080")

        # Le proxy système ne devrait pas être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_not_called()

    def test_get_proxy_config_from_env_config(self):
        """Vérifie la récupération de la configuration depuis la config d'environnement"""
        proxy = IziProxy(environment="local")  # Pas d'URL explicite et pas d'authentification

        config = proxy.get_proxy_config()

        # L'URL de la config d'environnement devrait être utilisée sans authentification
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://env-var-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://env-var-proxy.example.com:8080")

        # Le proxy système ne devrait pas être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_not_called()

    def test_get_proxy_config_system_detection(self):
        """Vérifie la détection automatique du proxy système"""
        # Créer un environnement spécial sans URL de proxy
        self.env_configs["test_env"] = {
            "proxy_url": None,
            "requires_auth": False
        }

        proxy = IziProxy(environment="test_env")
        config = proxy.get_proxy_config()

        # Le proxy système devrait être détecté
        self.mock_proxy_detector_instance.detect_system_proxy.assert_called_once()

        # La configuration devrait contenir les URLs système
        self.assertIn("http", config)
        self.assertEqual(config.get_real_config()["http"], "http://system-proxy.example.com:8080")
        self.assertEqual(config.get_real_config()["https"], "http://system-proxy.example.com:8080")

    def test_get_proxy_config_with_auth(self):
        """Vérifie l'ajout de l'authentification à l'URL de proxy"""
        # Utiliser l'environnement dev avec authentification basique
        proxy = IziProxy(environment="dev")
        config = proxy.get_proxy_config()

        # Vérifier que l'URL contient les identifiants
        real_config = config.get_real_config()
        self.assertIn("testuser:testpass@", real_config["http"])
        self.assertIn("testuser:testpass@", real_config["https"])

    def test_create_session(self):
        """Vérifie la création d'une session requests configurée"""
        with patch('iziproxy.proxy_manager.requests.Session') as mock_session:
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance

            proxy = IziProxy(proxy_url="http://session-proxy.example.com:8080", environment="local")
            session = proxy.create_session()

            # La méthode configure_session devrait être appelée
            self.assertEqual(session, mock_session_instance)
            self.assertEqual(session.proxies, proxy.get_proxy_dict())
            self.assertFalse(session.trust_env)

    def test_configure_session(self):
        """Vérifie la configuration d'une session existante"""
        with patch('iziproxy.proxy_manager.requests.Session') as mock_session:
            session = mock_session()

            proxy = IziProxy(proxy_url="http://config-proxy.example.com:8080", environment="local")
            configured_session = proxy.configure_session(session)

            # La session devrait être configurée
            self.assertEqual(configured_session, session)
            self.assertEqual(session.proxies, proxy.get_proxy_dict())
            self.assertFalse(session.trust_env)

    def test_set_environment_variables(self):
        """Vérifie la définition des variables d'environnement"""
        # Utiliser l'environnement local qui n'a pas d'authentification
        proxy = IziProxy(
            proxy_url="http://env-var-proxy.example.com:8080",
            environment="local"
        )

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
        # Tester les identifiants pour différents environnements
        proxy_dev = IziProxy(environment="dev")
        username_dev, password_dev, domain_dev = proxy_dev.get_credentials()
        self.assertEqual(username_dev, "testuser")
        self.assertIsInstance(password_dev, SecurePassword)
        self.assertEqual(password_dev.get_password(), "testpass")
        self.assertEqual(domain_dev, "")

        # Tester l'environnement prod avec NTLM
        proxy_prod = IziProxy(environment="prod")
        username_prod, password_prod, domain_prod = proxy_prod.get_credentials()
        self.assertEqual(username_prod, "ntlmuser")
        self.assertIsInstance(password_prod, SecurePassword)
        self.assertEqual(password_prod.get_password(), "ntlmpass")
        self.assertEqual(domain_prod, "domain")

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
        # Configurer le mock pour requests (simuler le module complet)
        mock_session = MagicMock()
        mock_session.get = MagicMock(name='session_get')
        mock_session.post = MagicMock(name='session_post')

        # Stocker les méthodes originales
        original_get = MagicMock(name='original_get')
        original_post = MagicMock(name='original_post')
        mock_requests.get = original_get
        mock_requests.post = original_post

        # Créer l'instance et configurer la session patchée
        proxy = IziProxy()
        proxy._patched_session = mock_session

        # Appliquer le patch
        result = proxy.patch_requests()

        # Vérifier que les méthodes ont été remplacées
        self.assertIsNot(mock_requests.get, original_get)
        self.assertIsNot(mock_requests.post, original_post)
        self.assertEqual(mock_requests.get, mock_session.get)
        self.assertEqual(mock_requests.post, mock_session.post)

        # Le résultat devrait être l'instance elle-même (pour le chaînage)
        self.assertEqual(result, proxy)

    @patch('iziproxy.proxy_manager.requests')
    def test_unpatch_requests(self, mock_requests):
        """Vérifie la restauration du module requests après monkey patching"""
        # Créer des mocks pour les méthodes originales et pour l'API
        mock_api = MagicMock()
        mock_api.get = MagicMock(name='api_get')
        mock_api.post = MagicMock(name='api_post')
        mock_api.put = MagicMock(name='api_put')
        mock_api.delete = MagicMock(name='api_delete')
        mock_api.head = MagicMock(name='api_head')
        mock_api.options = MagicMock(name='api_options')
        mock_api.patch = MagicMock(name='api_patch')

        # Remplacer l'attribut 'api' de mock_requests par notre mock_api
        mock_requests.api = mock_api

        # Définir des méthodes personnalisées avant restauration
        custom_get = MagicMock(name='custom_get')
        custom_post = MagicMock(name='custom_post')
        mock_requests.get = custom_get
        mock_requests.post = custom_post

        # Créer l'instance
        proxy = IziProxy()

        # Restaurer les méthodes originales
        result = proxy.unpatch_requests()

        # Vérifier que les méthodes ont été restaurées
        self.assertEqual(mock_requests.get, mock_api.get)
        self.assertEqual(mock_requests.post, mock_api.post)

        # Le résultat devrait être l'instance elle-même (pour le chaînage)
        self.assertEqual(result, proxy)