"""
Tests unitaires pour le module env_detector
"""

import os
import unittest
from unittest.mock import patch

from iziproxy.env_detector import EnvironmentDetector


class TestEnvironmentDetector(unittest.TestCase):
    """Tests pour la classe EnvironmentDetector"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Configuration par défaut
        self.default_config = {
            "environment_detection": {
                "method": "auto",
                "hostname_patterns": {
                    "local": ["local", "laptop"],
                    "dev": ["dev", "staging"],
                    "prod": ["prod"]
                },
                "hostname_regex": {
                    "local": ["^laptop-\\w+$", "^pc-\\w+$"],
                    "dev": ["^dev\\d*-"],
                    "prod": ["^prod\\d*-"]
                },
                "ip_ranges": {
                    "local": ["192.168.1.0/24", "10.0.0.1-10.0.0.255"],
                    "dev": ["172.16.0.0/16"],
                    "prod": ["10.1.0.0/16"]
                }
            }
        }
        
        # Nettoyer les variables d'environnement pour les tests
        self.clean_env_vars()

    def clean_env_vars(self):
        """Nettoie les variables d'environnement pour les tests"""
        for var in ["ENVIRONMENT", "ENV", "APP_ENV", "ENVIRONMENT_TYPE", "PROXY_ENV", "IZIPROXY_ENV"]:
            if var in os.environ:
                del os.environ[var]
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.clean_env_vars()
                
    def test_default_detection(self):
        """Vérifie que la détection par défaut retourne 'local'"""
        # Patcher toutes les méthodes de détection pour qu'elles retournent None
        with patch.object(EnvironmentDetector, '_detect_by_env_var', return_value=None), \
             patch.object(EnvironmentDetector, '_detect_by_hostname', return_value=None), \
             patch.object(EnvironmentDetector, '_detect_by_ip', return_value=None):
            
            detector = EnvironmentDetector(self.default_config)
            env = detector.detect_environment()
            
            # Par défaut, doit retourner 'local'
            self.assertEqual(env, "local")

    def test_detection_from_env_var(self):
        """Vérifie la détection depuis les variables d'environnement"""
        with patch.dict('os.environ', {'ENV': 'prod'}):
            detector = EnvironmentDetector(self.default_config)
            
            # Patcher les autres méthodes pour s'assurer qu'elles ne sont pas utilisées
            with patch.object(detector, '_detect_by_hostname', return_value=None), \
                 patch.object(detector, '_detect_by_ip', return_value=None):
                
                env = detector.detect_environment()
                self.assertEqual(env, "prod")

    def test_detection_from_hostname(self):
        """Vérifie la détection depuis le nom d'hôte"""
        # Simuler un environnement où la variable d'environnement n'est pas définie
        with patch.dict('os.environ', clear=True):
            detector = EnvironmentDetector(self.default_config)
            
            # Patcher les méthodes et system_info pour simuler un nom d'hôte
            detector.system_info = {"hostname": "dev-server-01"}
            with patch.object(detector, '_detect_by_env_var', return_value=None), \
                 patch.object(detector, '_detect_by_ip', return_value=None):
                
                env = detector.detect_environment()
                self.assertEqual(env, "dev")

    def test_detection_with_regex(self):
        """Vérifie la détection avec des expressions régulières"""
        config = {
            "environment_detection": {
                "method": "hostname",
                "hostname_regex": {
                    "dev": ["^dev\\d+"]
                }
            }
        }
        
        detector = EnvironmentDetector(config)
        detector.system_info = {"hostname": "dev123"}
        
        env = detector.detect_environment()
        self.assertEqual(env, "dev")

    def test_detection_caching(self):
        """Vérifie que le résultat est mis en cache"""
        detector = EnvironmentDetector(self.default_config)
        
        # Premier appel - détection réelle
        with patch.object(detector, '_detect_by_env_var', return_value="prod"):
            env1 = detector.detect_environment()
            self.assertEqual(env1, "prod")
        
        # Second appel - devrait utiliser le cache même si la méthode retourne autre chose
        with patch.object(detector, '_detect_by_env_var', return_value="dev"):
            env2 = detector.detect_environment()
            self.assertEqual(env2, "prod")  # Toujours "prod" depuis le cache
        
        # Appel avec force_refresh - devrait détecter à nouveau
        with patch.object(detector, '_detect_by_env_var', return_value="dev"):
            env3 = detector.detect_environment(force_refresh=True)
            self.assertEqual(env3, "dev")  # Maintenant "dev"

    def test_ip_in_range(self):
        """Vérifie la fonction _ip_in_range"""
        # Test avec format CIDR
        result1 = EnvironmentDetector._ip_in_range("192.168.1.10", "192.168.1.0/24")
        self.assertTrue(result1)
        
        # Test avec plage directe
        result2 = EnvironmentDetector._ip_in_range("192.168.1.10", "192.168.1.5-192.168.1.15")
        self.assertTrue(result2)
        
        # Test hors plage
        result3 = EnvironmentDetector._ip_in_range("192.168.2.10", "192.168.1.0/24")
        self.assertFalse(result3)
        
        # Test avec IP hors plage directe
        result4 = EnvironmentDetector._ip_in_range("192.168.1.20", "192.168.1.5-192.168.1.15")
        self.assertFalse(result4)
        
        # Test avec format invalide (devrait retourner False sans erreur)
        result5 = EnvironmentDetector._ip_in_range("192.168.1.10", "invalid_format")
        self.assertFalse(result5)
        
        # Test avec IP invalide (devrait retourner False sans erreur)
        result6 = EnvironmentDetector._ip_in_range("invalid_ip", "192.168.1.0/24")
        self.assertFalse(result6)
        
    def test_ip_to_int(self):
        """Vérifie la conversion d'IP en entier"""
        # Test avec quelques IPs
        self.assertEqual(EnvironmentDetector._ip_to_int("0.0.0.0"), 0)
        self.assertEqual(EnvironmentDetector._ip_to_int("127.0.0.1"), 2130706433)
        self.assertEqual(EnvironmentDetector._ip_to_int("192.168.1.1"), 3232235777)
        self.assertEqual(EnvironmentDetector._ip_to_int("255.255.255.255"), 4294967295)
        
    def test_detection_with_specific_method(self):
        """Vérifie la détection avec une méthode spécifique"""
        # Configurer pour utiliser uniquement la méthode hostname
        config = {
            "environment_detection": {
                "method": "hostname"
            }
        }
        
        with patch.object(EnvironmentDetector, '_detect_by_hostname', return_value="dev"):
            detector = EnvironmentDetector(config)
            env = detector.detect_environment()
            self.assertEqual(env, "dev")
            
        # Vérifier que seule la méthode hostname a été utilisée
        with patch.object(EnvironmentDetector, '_detect_by_hostname', return_value="dev") as mock_hostname, \
             patch.object(EnvironmentDetector, '_detect_by_env_var') as mock_env_var, \
             patch.object(EnvironmentDetector, '_detect_by_ip') as mock_ip:
                
            detector = EnvironmentDetector(config)
            env = detector.detect_environment()
            
            mock_hostname.assert_called_once()
            mock_env_var.assert_not_called()
            mock_ip.assert_not_called()
            
    def test_get_system_info(self):
        """Vérifie la collecte des informations système"""
        with patch('socket.gethostname', return_value="TEST-HOST"), \
             patch('platform.system', return_value="TestOS"), \
             patch('socket.gethostbyname', return_value="192.168.1.100"):
            
            detector = EnvironmentDetector()
            system_info = detector._get_system_info()
            
            self.assertEqual(system_info["hostname"], "test-host")
            self.assertEqual(system_info["os"], "testos")
            self.assertEqual(system_info["ip"], "192.168.1.100")
            
    def test_get_system_info_error_handling(self):
        """Vérifie la gestion des erreurs lors de la collecte des informations système"""
        # Simuler une erreur lors de la récupération de l'IP
        with patch('socket.gethostname', return_value="TEST-HOST"), \
             patch('platform.system', return_value="TestOS"), \
             patch('socket.gethostbyname', side_effect=Exception("Network error")):
            
            detector = EnvironmentDetector()
            system_info = detector._get_system_info()
            
            # Vérifier que les autres informations sont récupérées malgré l'erreur
            self.assertEqual(system_info["hostname"], "test-host")
            self.assertEqual(system_info["os"], "testos")
            self.assertIsNone(system_info["ip"])  # IP devrait être None en cas d'erreur
            
    def test_detection_methods_priority(self):
        """Vérifie que les méthodes de détection sont appliquées dans le bon ordre"""
        # Configurer pour que toutes les méthodes retournent une valeur
        with patch.object(EnvironmentDetector, '_detect_by_env_var', return_value="prod") as mock_env_var, \
             patch.object(EnvironmentDetector, '_detect_by_hostname', return_value="dev") as mock_hostname, \
             patch.object(EnvironmentDetector, '_detect_by_ip', return_value="local") as mock_ip:
            
            detector = EnvironmentDetector(self.default_config)
            env = detector.detect_environment()
            
            # La première méthode (env_var) devrait être utilisée
            self.assertEqual(env, "prod")
            mock_env_var.assert_called_once()
            mock_hostname.assert_not_called()
            mock_ip.assert_not_called()
            
    def test_environment_pattern_override(self):
        """Vérifie que les motifs de détection peuvent être personnalisés"""
        # Configurer avec des motifs personnalisés
        custom_config = {
            "environment_detection": {
                "method": "auto",
                "hostname_patterns": {
                    "local": ["custom-local"],
                    "dev": ["custom-dev"],
                    "prod": ["custom-prod"]
                }
            }
        }
        
        # Patcher _get_system_info pour renvoyer un hostname personnalisé
        with patch.object(EnvironmentDetector, '_get_system_info', return_value={"hostname": "custom-dev-server", "os": "linux", "ip": None}), \
             patch.object(EnvironmentDetector, '_detect_by_env_var', return_value=None):
            
            detector = EnvironmentDetector(custom_config)
            env = detector.detect_environment()
            
            # La détection devrait utiliser les motifs personnalisés
            self.assertEqual(env, "dev")
            
    def test_ask_user_method(self):
        """Vérifie la méthode de demande interactive"""
        # Configurer pour utiliser uniquement la méthode ask
        config = {
            "environment_detection": {
                "method": "ask"
            }
        }
        
        # Simuler une entrée utilisateur
        with patch('builtins.input', return_value="2"):  # 2 = dev
            detector = EnvironmentDetector(config)
            env = detector.detect_environment()
            self.assertEqual(env, "dev")
            
        # Simuler une entrée invalide
        with patch('builtins.input', return_value="invalid"):
            detector = EnvironmentDetector(config)
            env = detector.detect_environment()
            # Devrait retourner local par défaut en cas d'entrée invalide
            self.assertEqual(env, "local")
            
        # Simuler une erreur (pas de terminal)
        with patch('builtins.input', side_effect=Exception("No terminal")):
            detector = EnvironmentDetector(config)
            env = detector.detect_environment()
            # Devrait retourner local par défaut en cas d'erreur
            self.assertEqual(env, "local")


if __name__ == '__main__':
    unittest.main()
