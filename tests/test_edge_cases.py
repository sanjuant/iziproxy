"""
Tests pour les cas limites et la résilience d'IziProxy
"""
import json
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

import yaml

from iziproxy import IziProxy, SecurePassword


class TestEdgeCases(unittest.TestCase):
    """Tests pour les cas limites et les comportements de résilience"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Nettoyer les variables d'environnement
        self.clean_env_vars()
        
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.clean_env_vars()
        
    def clean_env_vars(self):
        """Nettoie les variables d'environnement pour les tests"""
        env_vars = [
            "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", 
            "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
            "ENVIRONMENT", "ENV", "PROXY_USERNAME", "PROXY_PASSWORD",
            "IZI_USERNAME", "IZI_PASSWORD"
        ]
        for var in env_vars:
            if var in os.environ:
                del os.environ[var]

    def test_corrupted_config_file(self):
        """Vérifie la résilience face à un fichier de configuration corrompu"""
        # Créer un fichier de configuration temporaire avec du contenu YAML invalide
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml", mode="w") as temp_file:
            temp_file.write("this: is: not: valid: yaml: structure:")
        
        try:
            # Créer une instance IziProxy avec le fichier corrompu
            proxy = IziProxy(config_path=temp_file.name)
            
            # Vérifier que l'instance a été créée avec succès et utilise les valeurs par défaut
            self.assertIsNotNone(proxy.config)
            self.assertIn("environments", proxy.config)
            
            # Devrait pouvoir utiliser les fonctionnalités normalement
            proxy_dict = proxy.get_proxy_dict()
            self.assertIsInstance(proxy_dict, dict)
        finally:
            # Nettoyer
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)

    def test_invalid_environment(self):
        """Vérifie le comportement avec un environnement invalide spécifié"""
        # Créer une instance avec un environnement qui n'existe pas
        proxy = IziProxy(environment="invalid_env")
        
        # L'environnement devrait être accepté tel quel
        self.assertEqual(proxy.current_env, "invalid_env")
        
        # Mais l'environnement n'existant pas dans la configuration, la détection du proxy devrait retourner un dict vide
        proxy_dict = proxy.get_proxy_dict()
        self.assertEqual(proxy_dict, {})

    def test_non_existent_config_path(self):
        """Vérifie le comportement avec un chemin de configuration qui n'existe pas"""
        # Créer une instance avec un chemin qui n'existe pas
        proxy = IziProxy(config_path="/path/that/does/not/exist.yml")
        
        # Devrait utiliser la configuration par défaut
        self.assertIsNotNone(proxy.config)
        self.assertIn("environments", proxy.config)
        
        # Devrait pouvoir utiliser les fonctionnalités normalement
        proxy_dict = proxy.get_proxy_dict()
        self.assertIsInstance(proxy_dict, dict)

    def test_special_characters_in_password(self):
        """Vérifie le comportement avec des caractères spéciaux dans le mot de passe"""
        # Mot de passe avec des caractères spéciaux
        special_password = "P@ssw0rd!@#$%^&*()_+[]{}|;:'\",.<>/?`~"
        
        # Créer une instance avec ce mot de passe
        proxy = IziProxy(username="testuser", password=special_password)
        
        # Récupérer les identifiants
        username, password, domain = proxy.get_credentials()
        
        # Vérifier que le mot de passe est récupérable tel quel
        self.assertEqual(password.get_password(), special_password)

    def test_unicode_characters(self):
        """Vérifie le comportement avec des caractères Unicode"""
        # Identifiants avec des caractères Unicode
        unicode_user = "utilisateur_àéèçñß"
        unicode_password = "mot_de_passe_öäüÖÄÜ"
        unicode_domain = "доменное_имя"
        
        # Créer une instance avec ces identifiants
        proxy = IziProxy(username=unicode_user, password=unicode_password, domain=unicode_domain)
        
        # Récupérer les identifiants
        username, password, domain = proxy.get_credentials()
        
        # Vérifier que les caractères Unicode sont préservés
        self.assertEqual(username, unicode_user)
        self.assertEqual(password.get_password(), unicode_password)
        self.assertEqual(domain, unicode_domain)

    def test_empty_credentials(self):
        """Vérifie le comportement avec des identifiants vides"""
        # Créer une instance avec des identifiants vides
        proxy = IziProxy(username="", password="", domain="")
        
        # Vérifier que les identifiants vides sont acceptés
        username, password, domain = proxy._get_credentials()
        self.assertEqual(username, None)
        self.assertEqual(password, None)
        self.assertEqual(domain, None)

    def test_http_https_mismatch(self):
        """Vérifie le comportement avec des proxies HTTP et HTTPS différents"""
        # Configurer des proxies différents pour HTTP et HTTPS
        os.environ["HTTP_PROXY"] = "http://http-proxy.example.com:8080"
        os.environ["HTTPS_PROXY"] = "http://https-proxy.example.com:8443"
        
        # Créer une instance
        proxy = IziProxy()
        
        # Récupérer la configuration
        proxy_dict = proxy.get_proxy_dict()
        
        # Vérifier que les deux proxies sont correctement détectés
        self.assertEqual(proxy_dict["http"], "http://http-proxy.example.com:8080")
        self.assertEqual(proxy_dict["https"], "http://https-proxy.example.com:8443")

    def test_missing_env_section(self):
        """Vérifie le comportement avec une configuration manquant la section environments"""
        # Créer un fichier de configuration temporaire sans section environments
        config_data = {
            "system_proxy": {
                "use_system_proxy": True
            }
        }
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml", mode="w") as temp_file:
            yaml.dump(config_data, temp_file)
        
        try:
            # Créer une instance avec cette configuration
            proxy = IziProxy(config_path=temp_file.name)
            
            # Vérifier que la configuration a été fusionnée avec les valeurs par défaut
            self.assertIn("environments", proxy.config)
            self.assertTrue(proxy.config["system_proxy"]["use_system_proxy"])
            
            # Devrait pouvoir utiliser les fonctionnalités normalement
            proxy_dict = proxy.get_proxy_dict()
            self.assertIsInstance(proxy_dict, dict)
        finally:
            # Nettoyer
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)

    def test_keyring_unavailable(self):
        """Vérifie le comportement lorsque keyring n'est pas disponible"""
        # Patcher keyring.get_password pour lever une exception
        with patch('keyring.get_password', side_effect=Exception("Keyring unavailable")), \
             patch('keyring.set_password', side_effect=Exception("Keyring unavailable")):
            
            # Créer une instance avec authentification
            proxy = IziProxy(environment="dev", username="testuser", password="testpass")
            
            # Récupérer les identifiants (ne devrait pas planter)
            username, password, domain = proxy.get_credentials()
            
            # Devrait utiliser les identifiants fournis
            self.assertEqual(username, "testuser")
            self.assertEqual(password.get_password(), "testpass")

    def test_network_error_resilience(self):
        """Vérifie la résilience face aux erreurs réseau"""
        # Patcher socket.create_connection pour simuler une erreur réseau
        with patch('socket.create_connection', side_effect=socket.error("Network error")):
            # Créer une instance
            proxy = IziProxy()
            
            # Récupérer la configuration proxy (ne devrait pas planter)
            proxy_dict = proxy.get_proxy_dict()
            
            # Devrait retourner un dictionnaire vide ou avec seulement les configurations explicites
            self.assertIsInstance(proxy_dict, dict)

    def test_environment_switching(self):
        """Vérifie le comportement lors du changement d'environnement"""
        # Créer une instance avec environnement dev
        proxy = IziProxy(environment="dev")
        self.assertEqual(proxy.current_env, "dev")
        
        # Simuler un changement d'environnement
        proxy.current_env = "prod"
        proxy._proxy_config = None  # Réinitialiser le cache
        
        # Vérifier que la modification manuelle de l'environnement fonctionne
        self.assertEqual(proxy.current_env, "prod")
        
        # Rafraîchir la détection pour mettre à jour l'environnement
        # Patcher la détection pour qu'elle retourne "local"
        with patch.object(proxy.env_detector, 'detect_environment', return_value="local"):
            proxy.refresh()
            # L'environnement reste à "prod" car il a été forcé lors de l'initialisation
            self.assertEqual(proxy.current_env, "prod")

    def test_long_urls(self):
        """Vérifie le comportement avec des URLs très longues"""
        # Créer une URL très longue
        long_path = "/path/" + "very_long_segment_" * 50
        long_url = f"http://proxy.example.com:8080{long_path}"
        
        # Créer une instance avec cette URL
        proxy = IziProxy(proxy_url=long_url)
        
        # Récupérer la configuration
        proxy_dict = proxy.get_proxy_dict()
        
        # Vérifier que l'URL longue est correctement gérée
        self.assertEqual(proxy_dict["http"], long_url)
        self.assertEqual(proxy_dict["https"], long_url)

    def test_malformed_proxy_urls(self):
        """Vérifie le comportement avec des URLs de proxy malformées"""
        malformed_urls = [
            "not-a-url",          # Pas une URL
            "http://:8080",       # Sans hostname
            "http://proxy",       # Sans port
            "ftp://proxy:8080"    # Protocole non supporté
        ]
        
        for url in malformed_urls:
            # Créer une instance avec l'URL malformée
            proxy = IziProxy(proxy_url=url)
            
            # Récupérer la configuration (ne devrait pas planter)
            proxy_dict = proxy.get_proxy_dict()
            
            # L'URL devrait être acceptée telle quelle
            self.assertEqual(proxy_dict["http"], url)
            self.assertEqual(proxy_dict["https"], url)

    def test_concurrent_usage(self):
        """Vérifie le comportement en cas d'utilisation concurrente"""
        # Simuler une utilisation concurrente en créant plusieurs instances
        proxy1 = IziProxy(environment="dev")
        proxy2 = IziProxy(environment="prod")
        
        # Récupérer les configurations
        proxy_dict1 = proxy1.get_proxy_dict()
        proxy_dict2 = proxy2.get_proxy_dict()
        
        # Vérifier que les instances sont indépendantes
        self.assertEqual(proxy1.current_env, "dev")
        self.assertEqual(proxy2.current_env, "prod")
        
        # Modifier une instance ne devrait pas affecter l'autre
        proxy1.current_env = "local"
        self.assertEqual(proxy1.current_env, "local")
        self.assertEqual(proxy2.current_env, "prod")

    def test_secure_password_safety(self):
        """Vérifie que SecurePassword masque correctement le mot de passe dans les logs"""
        # Créer un mot de passe sécurisé
        password = "very_secret_password"
        secure_pass = SecurePassword(password)
        
        # Convertir en JSON pour simuler un log
        password_dict = {"password": secure_pass}
        json_str = json.dumps(str(password_dict))
        
        # Vérifier que le mot de passe n'apparaît pas en clair
        self.assertNotIn(password, json_str)
        self.assertIn("***********", json_str)

    def test_module_reload(self):
        """Vérifie le comportement lors du rechargement du module"""
        # Importer le module
        import iziproxy as iziproxy_orig
        
        # Créer une instance
        proxy1 = iziproxy_orig.IziProxy()
        
        # Recharger le module
        import importlib
        importlib.reload(iziproxy_orig)
        
        # Créer une nouvelle instance
        proxy2 = iziproxy_orig.IziProxy()
        
        # Vérifier que les deux instances fonctionnent
        self.assertIsInstance(proxy1.get_proxy_dict(), dict)
        self.assertIsInstance(proxy2.get_proxy_dict(), dict)


if __name__ == '__main__':
    unittest.main()
