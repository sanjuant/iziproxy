"""
Tests de l'API publique d'IziProxy
"""

import inspect
import unittest
from unittest.mock import patch, MagicMock

import iziproxy
from iziproxy import IziProxy, SecurePassword, SecureProxyConfig


class TestPublicAPI(unittest.TestCase):
    """Tests pour vérifier l'API publique du package"""

    def setUp(self):
        """Configuration des mocks communs à tous les tests"""
        # Créer les patchs pour les dépendances
        self.env_detector_patcher = patch('iziproxy.proxy_manager.EnvironmentDetector')
        self.config_manager_patcher = patch('iziproxy.proxy_manager.ConfigManager')
        self.requests_patcher = patch('iziproxy.proxy_manager.requests')

        # Démarrer les patchs
        self.mock_env_detector = self.env_detector_patcher.start()
        self.mock_config_manager = self.config_manager_patcher.start()
        self.mock_requests = self.requests_patcher.start()

        # Configurer le comportement du ConfigManager
        self.mock_config_instance = MagicMock()
        self.mock_config_instance.get_credentials.return_value = ("testuser", SecurePassword("testpass"), "TESTDOMAIN")
        self.mock_config_manager.return_value = self.mock_config_instance

        # Configurer le comportement de requests.Session si nécessaire
        self.mock_session = MagicMock()
        self.mock_requests.Session.return_value = self.mock_session

    def tearDown(self):
        """Nettoyer les patchs après chaque test"""
        # Arrêter les patchs
        self.env_detector_patcher.stop()
        self.config_manager_patcher.stop()
        self.requests_patcher.stop()

    def test_package_exports(self):
        """Vérifie que le package exporte les classes attendues via __all__"""
        # Vérifier que __all__ est défini
        self.assertTrue(hasattr(iziproxy, "__all__"))

        # Vérifier que __all__ contient exactement les exports attendus
        expected_all = ["IziProxy", "SecurePassword", "SecureProxyConfig"]
        self.assertEqual(sorted(iziproxy.__all__), sorted(expected_all))

        # Vérifier que toutes les classes déclarées dans __all__ sont disponibles
        for class_name in iziproxy.__all__:
            self.assertTrue(hasattr(iziproxy, class_name),
                            f"La classe {class_name} déclarée dans __all__ n'est pas exportée")

        # Vérifier que ce sont les bonnes classes
        self.assertEqual(iziproxy.IziProxy, IziProxy)
        self.assertEqual(iziproxy.SecurePassword, SecurePassword)
        self.assertEqual(iziproxy.SecureProxyConfig, SecureProxyConfig)

        # Vérifier que __version__ est défini (bien qu'il ne soit pas dans __all__)
        self.assertTrue(hasattr(iziproxy, "__version__"))

    def test_version_number(self):
        """Vérifie que le numéro de version est défini"""
        self.assertTrue(hasattr(iziproxy, "__version__"))
        self.assertIsInstance(iziproxy.__version__, str)
        
        # Vérifier le format de la version (SemVer)
        parts = iziproxy.__version__.split(".")
        self.assertTrue(1 <= len(parts) <= 3)
        
        for part in parts:
            self.assertTrue(part.isdigit() or "-" in part)

    def test_iziproxy_constructor(self):
        """Vérifie la signature du constructeur IziProxy"""
        signature = inspect.signature(IziProxy.__init__)
        parameters = signature.parameters
        
        # Vérifier les paramètres attendus
        expected_params = ["self", "config_path", "proxy_url", "pac_url", 
                          "environment", "username", "password", "domain", "debug"]
        
        for param in expected_params:
            self.assertIn(param, parameters)
            
        # Vérifier que tous les paramètres sauf self sont optionnels
        for name, param in parameters.items():
            if name != "self":
                self.assertNotEqual(param.default, inspect.Parameter.empty)

    def test_iziproxy_public_methods(self):
        """Vérifie les méthodes publiques de IziProxy"""
        # Liste des méthodes publiques attendues
        expected_methods = [
            "get_proxy_config",
            "get_proxy_dict",
            "configure_session",
            "create_session",
            "set_environment_variables",
            "clear_environment_variables",
            "get_current_environment",
            "get_credentials",
            "refresh",
            "set_debug",
            "patch_requests",
            "unpatch_requests",
            "get_proxy_host",
            "get_proxy_port",
            "clear_auth_cache"
        ]
        
        # Vérifier que toutes les méthodes attendues sont présentes
        for method_name in expected_methods:
            self.assertTrue(hasattr(IziProxy, method_name))
            method = getattr(IziProxy, method_name)
            self.assertTrue(callable(method))
        
        # Vérifier qu'il n'y a pas de méthodes publiques non documentées
        for name in dir(IziProxy):
            if not name.startswith("_") and name not in expected_methods:
                # Exclure les propriétés
                if not isinstance(getattr(IziProxy, name), property):
                    self.fail(f"Méthode publique non documentée: {name}")

    def test_securepassword_methods(self):
        """Vérifie les méthodes de SecurePassword"""
        # Liste des méthodes publiques attendues
        expected_methods = ["get_password"]
        
        # Vérifier que toutes les méthodes attendues sont présentes
        for method_name in expected_methods:
            self.assertTrue(hasattr(SecurePassword, method_name))
            method = getattr(SecurePassword, method_name)
            self.assertTrue(callable(method))
        
        # Créer une instance et vérifier le comportement
        password = "test_password"
        secure_pass = SecurePassword(password)
        
        # Vérifier que la représentation masque le mot de passe
        self.assertNotIn(password, str(secure_pass))
        self.assertNotIn(password, repr(secure_pass))
        
        # Vérifier que get_password() retourne le mot de passe original
        self.assertEqual(secure_pass.get_password(), password)

    def test_secureproxyconfig_methods(self):
        """Vérifie les méthodes de SecureProxyConfig"""
        # Liste des méthodes publiques attendues
        expected_methods = ["get_real_config", "get_credentials"]
        
        # Vérifier que toutes les méthodes attendues sont présentes
        for method_name in expected_methods:
            self.assertTrue(hasattr(SecureProxyConfig, method_name))
            method = getattr(SecureProxyConfig, method_name)
            self.assertTrue(callable(method))
        
        # Créer une instance et vérifier le comportement
        proxy_dict = {
            "http": "http://user:password@proxy.example.com:8080",
            "https": "http://user:password@proxy.example.com:8443"
        }
        config = SecureProxyConfig(proxy_dict)
        
        # Vérifier que la représentation masque le mot de passe
        self.assertNotIn("password", str(config))
        
        # Vérifier que get_real_config() retourne les vraies URLs
        real_config = config.get_real_config()
        self.assertEqual(real_config["http"], proxy_dict["http"])
        
        # Vérifier que get_credentials() retourne les identifiants
        username, password = config.get_credentials("http")
        self.assertEqual(username, "user")
        self.assertEqual(password.get_password(), "password")

    def test_importable_submodules(self):
        """Vérifie que les sous-modules sont importables si nécessaire"""
        # Liste des sous-modules qui doivent être importables
        importable_modules = [
            "iziproxy.secure_config",
            "iziproxy.config_manager",
            "iziproxy.env_detector",
            "iziproxy.proxy_detector",
            "iziproxy.logger"
        ]
        
        for module_name in importable_modules:
            try:
                __import__(module_name)
            except ImportError:
                self.fail(f"Le module {module_name} n'est pas importable")

    def test_create_session_returns_object(self):
        """Vérifie que create_session retourne un objet session"""
        # IziProxy utilise les mocks déjà configurés dans setUp
        proxy = IziProxy()

        # Appeler create_session()
        session = proxy.create_session()

        # Vérifier que la session est bien l'objet retourné
        self.assertEqual(session, self.mock_session)

    def test_get_proxy_dict_returns_dict(self):
        """Vérifie que get_proxy_dict retourne un dictionnaire"""
        # Créer une instance IziProxy
        with patch('iziproxy.proxy_manager.EnvironmentDetector'), \
                patch('iziproxy.proxy_manager.ConfigManager') as mock_config:
            # Configurer le mock pour retourner des identifiants
            mock_config_instance = MagicMock()
            mock_config_instance.get_credentials.return_value = ("testuser", SecurePassword("testpass"), "TESTDOMAIN")
            mock_config.return_value = mock_config_instance
            proxy = IziProxy(proxy_url="http://test.example.com:8080")
            
            # Appeler get_proxy_dict()
            proxy_dict = proxy.get_proxy_dict()
            
            # Vérifier que c'est bien un dictionnaire
            self.assertIsInstance(proxy_dict, dict)
            self.assertIn("http", proxy_dict)
            self.assertIn("https", proxy_dict)

    def test_get_credentials_returns_tuple(self):
        """Vérifie que get_credentials retourne un tuple"""
        # Créer une instance IziProxy
        with patch('iziproxy.proxy_manager.EnvironmentDetector'), \
             patch('iziproxy.proxy_manager.ConfigManager') as mock_config:
            # Configurer le mock pour retourner des identifiants
            mock_config_instance = MagicMock()
            mock_config_instance.get_credentials.return_value = ("testuser", SecurePassword("testpass"), "TESTDOMAIN")
            mock_config.return_value = mock_config_instance
            
            proxy = IziProxy()
            
            # Appeler get_credentials()
            credentials = proxy.get_credentials()
            
            # Vérifier que c'est bien un tuple de 3 éléments
            self.assertIsInstance(credentials, tuple)
            self.assertEqual(len(credentials), 3)
            self.assertEqual(credentials[0], "testuser")
            self.assertIsInstance(credentials[1], SecurePassword)
            self.assertEqual(credentials[2], "TESTDOMAIN")

    def test_method_chaining(self):
        """Vérifie que les méthodes supportent le chaînage"""
        # Créer une instance IziProxy avec les mocks déjà configurés
        proxy = IziProxy()

        # Tester le chaînage de méthodes
        result = proxy.set_debug(True).refresh().patch_requests()

        # Vérifier que chaque méthode retourne self
        self.assertEqual(result, proxy)


if __name__ == '__main__':
    unittest.main()
