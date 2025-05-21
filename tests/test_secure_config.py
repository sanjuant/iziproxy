"""
Tests unitaires pour le module secure_config
"""

import unittest
from unittest.mock import patch, MagicMock
from urllib.parse import quote

from iziproxy.secure_config import SecurePassword, SecureProxyConfig


class TestSecurePassword(unittest.TestCase):
    """Tests pour la classe SecurePassword"""

    def test_password_masking(self):
        """Vérifie que le mot de passe est masqué dans les représentations"""
        password = "secret_password"
        secure_pass = SecurePassword(password)
        
        # Vérifier le masquage dans str() et repr()
        self.assertEqual(str(secure_pass), "***********")
        self.assertIn("***********", repr(secure_pass))
        
        # Vérifier que le mot de passe original est récupérable
        self.assertEqual(secure_pass.get_password(), password)

    def test_nested_secure_password(self):
        """Vérifie qu'une instance peut être créée à partir d'une autre instance"""
        password = "original_password"
        secure_pass1 = SecurePassword(password)
        secure_pass2 = SecurePassword(secure_pass1)
        
        # Les deux instances doivent retourner le même mot de passe
        self.assertEqual(secure_pass1.get_password(), secure_pass2.get_password())
        self.assertEqual(secure_pass2.get_password(), password)
        
    def test_non_string_password(self):
        """Vérifie qu'un mot de passe non-string est converti correctement"""
        # Tester avec un entier
        secure_pass = SecurePassword(12345)
        self.assertEqual(secure_pass.get_password(), "12345")
        
        # Tester avec None (devrait être converti en chaîne "None")
        secure_pass = SecurePassword(None)
        self.assertEqual(secure_pass.get_password(), "None")
        
    def test_empty_password(self):
        """Vérifie qu'un mot de passe vide est géré correctement"""
        secure_pass = SecurePassword("")
        
        # Le mot de passe vide reste vide
        self.assertEqual(secure_pass.get_password(), "")
        # Mais sa représentation est toujours masquée
        self.assertEqual(str(secure_pass), "***********")
        
    @patch('iziproxy.secure_config.Fernet')
    def test_encryption_process(self, mock_fernet):
        """Vérifie que le processus de chiffrement est utilisé correctement"""
        # Configurer le mock
        mock_fernet_instance = MagicMock()
        mock_fernet.generate_key.return_value = b'test_key'
        mock_fernet.return_value = mock_fernet_instance
        mock_fernet_instance.encrypt.return_value = b'encrypted_password'
        mock_fernet_instance.decrypt.return_value = b'decrypted_password'
        
        # Créer un mot de passe sécurisé
        secure_pass = SecurePassword("test_password")
        
        # Vérifier que Fernet a été utilisé correctement
        mock_fernet.generate_key.assert_called_once()
        mock_fernet.assert_called_once_with(b'test_key')
        mock_fernet_instance.encrypt.assert_called_once()
        
        # Vérifier que decrypt est appelé lors de l'obtention du mot de passe
        self.assertEqual(secure_pass.get_password(), "decrypted_password")
        mock_fernet_instance.decrypt.assert_called_once_with(b'encrypted_password')


class TestSecureProxyConfig(unittest.TestCase):
    """Tests pour la classe SecureProxyConfig"""

    def test_empty_config(self):
        """Vérifie qu'une configuration vide est gérée correctement"""
        config = SecureProxyConfig()
        self.assertEqual(len(config), 0)
        
        # La méthode get_real_config() devrait retourner un dict vide
        self.assertEqual(config.get_real_config(), {})

    def test_config_without_auth(self):
        """Vérifie que les URLs sans authentification sont gérées correctement"""
        proxy_dict = {
            "http": "http://proxy.example.com:8080",
            "https": "http://proxy.example.com:8080"
        }
        
        config = SecureProxyConfig(proxy_dict)
        
        # Les URLs ne doivent pas être modifiées
        self.assertEqual(config["http"], proxy_dict["http"])
        self.assertEqual(config["https"], proxy_dict["https"])
        
        # get_real_config() doit retourner le même dictionnaire
        real_config = config.get_real_config()
        self.assertEqual(real_config, proxy_dict)

    def test_config_with_auth(self):
        """Vérifie que les URLs avec authentification sont sécurisées"""
        proxy_dict = {
            "http": "http://user:password@proxy.example.com:8080",
            "https": "http://user:password@proxy.example.com:8080"
        }
        
        config = SecureProxyConfig(proxy_dict)
        
        # Vérifier que les mots de passe sont masqués dans les représentations
        self.assertNotIn("password", str(config))
        self.assertIn("***********", str(config))
        
        # Mais get_real_config() doit retourner les URLs avec mots de passe
        real_config = config.get_real_config()
        self.assertEqual(real_config["http"], proxy_dict["http"])
        self.assertEqual(real_config["https"], proxy_dict["https"])

    def test_get_credentials(self):
        """Vérifie que get_credentials() retourne les bons identifiants"""
        proxy_dict = {
            "http": "http://user:password@proxy.example.com:8080"
        }

        config = SecureProxyConfig(proxy_dict)

        # Tester get_credentials pour http
        username, secure_password = config.get_credentials("http")
        self.assertEqual(username, "user")
        self.assertIsInstance(secure_password, SecurePassword)
        self.assertEqual(secure_password.get_password(), "password")

        # Tester pour un type non présent
        username, secure_password = config.get_credentials("ftp")
        self.assertIsNone(username)
        self.assertIsNone(secure_password)
        
    def test_str_and_repr(self):
        """Vérifie que str() et repr() masquent correctement les mots de passe"""
        proxy_dict = {
            "http": "http://user:s3cr3t@proxy.example.com:8080",
            "https": "http://user:s3cr3t@proxy.example.com:8443"
        }
        
        config = SecureProxyConfig(proxy_dict)
        
        # Vérifier que les représentations masquent les mots de passe
        str_repr = str(config)
        repr_str = repr(config)
        
        self.assertNotIn("s3cr3t", str_repr)
        self.assertNotIn("s3cr3t", repr_str)
        self.assertIn("***********", str_repr)
        self.assertIn("***********", repr_str)
    
    def test_special_characters_in_password(self):
        """Vérifie que les caractères spéciaux dans les mots de passe sont gérés correctement"""
        special_chars = "!@#$%^&*(testpass)_+-=[]{}|;:'\",.<>/?~`"
        proxy_url = f"http://user:{special_chars}@proxy.example.com:8080"
        
        config = SecureProxyConfig({"http": proxy_url})
        
        # Le mot de passe doit être récupérable tel quel
        username, password = config.get_credentials("http")
        self.assertEqual(password.get_password(), special_chars)
        
        # get_real_config() doit retourner l'URL avec le mot de passe encodé
        real_config = config.get_real_config()

        encoded_password = quote(special_chars, safe='')
        expected_url = f"http://user:{encoded_password}@proxy.example.com:8080"
        self.assertEqual(real_config["http"], expected_url)

    def test_multiple_proxy_types(self):
        """Vérifie que plusieurs types de proxy sont gérés correctement"""
        proxy_dict = {
            "http": "http://user1:pass1@proxy1.example.com:8080",
            "https": "http://user2:pass2@proxy2.example.com:8443",
            "ftp": "http://user3:pass3@proxy3.example.com:2121",
            "no_proxy": "localhost,127.0.0.1"
        }

        config = SecureProxyConfig(proxy_dict)

        # Vérifier que tous les types sont présents
        self.assertEqual(len(config), 4)

        # Vérifier que les identifiants peuvent être récupérés pour chaque type
        username1, secure_password1 = config.get_credentials("http")
        self.assertEqual(username1, "user1")
        self.assertIsInstance(secure_password1, SecurePassword)
        self.assertEqual(secure_password1.get_password(), "pass1")

        username2, secure_password2 = config.get_credentials("https")
        self.assertEqual(username2, "user2")
        self.assertIsInstance(secure_password2, SecurePassword)
        self.assertEqual(secure_password2.get_password(), "pass2")

        username3, secure_password3 = config.get_credentials("ftp")
        self.assertEqual(username3, "user3")
        self.assertIsInstance(secure_password3, SecurePassword)
        self.assertEqual(secure_password3.get_password(), "pass3")

    def test_malformed_urls(self):
        """Vérifie que les URLs malformées sont gérées correctement"""
        malformed_urls = {
            "valid": "http://user:pass@proxy.example.com:8080",
            "no_password": "http://user@proxy.example.com:8080",  # Sans mot de passe
            "no_auth": "http://proxy.example.com:8080",          # Sans auth
            "invalid": "not-a-url",                             # Pas une URL
            "empty": "",                                        # Chaîne vide
            "none": None                                         # None
        }

        config = SecureProxyConfig(malformed_urls)

        # Vérifier que toutes les URLs sont présentes
        self.assertEqual(len(config), 6)

        # Vérifier que get_real_config() ne plante pas
        real_config = config.get_real_config()
        self.assertEqual(len(real_config), 6)

        # Vérifier get_credentials pour chaque type
        # URL valide avec auth
        username, secure_password = config.get_credentials("valid")
        self.assertEqual(username, "user")
        self.assertIsInstance(secure_password, SecurePassword)
        self.assertEqual(secure_password.get_password(), "pass")

        # URL avec username mais sans password
        username, secure_password = config.get_credentials("no_password")
        self.assertEqual(username, "user")
        self.assertIsNone(secure_password)

        # URL sans auth
        username, secure_password = config.get_credentials("no_auth")
        self.assertIsNone(username)
        self.assertIsNone(secure_password)

        # Valeurs non URL
        for key in ["invalid", "empty", "none"]:
            username, secure_password = config.get_credentials(key)
            self.assertIsNone(username)
            self.assertIsNone(secure_password)

