"""
Tests unitaires pour le module ntlm_auth
"""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import socket
import ssl
import base64

from iziproxy.secure_config import SecurePassword

# Créer des mocks pour les dépendances NTLM
class MockNtlmContext:
    def __init__(self, *args, **kwargs):
        pass
    
    def step(self, challenge=None):
        if challenge:
            return b'NTLM_AUTH_MSG'
        return b'NTLM_NEGOTIATE_MSG'

# Mock pour ntlm_auth
ntlm_auth_mock = MagicMock()
ntlm_auth_mock.ntlm.NtlmContext = MockNtlmContext

# Mock pour socket et SSL
class MockSocket:
    def __init__(self, *args, **kwargs):
        self.sent_data = []
        self.responses = []
        self.closed = False
    
    def sendall(self, data):
        self.sent_data.append(data)
    
    def recv(self, size):
        if self.responses:
            return self.responses.pop(0)
        return b''
    
    def close(self):
        self.closed = True

class MockSSLSocket(MockSocket):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sock = sock


# Patch les modules
@patch.dict('sys.modules', {'ntlm_auth.ntlm': ntlm_auth_mock})
class TestNtlmAuth(unittest.TestCase):
    """Tests pour l'authentification NTLM"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Importer le module dans le setup pour que les mocks soient appliqués
        try:
            from iziproxy.ntlm_auth import NtlmProxyManager, NtlmProxyTunnel, is_ntlm_auth_available
            self.NtlmProxyManager = NtlmProxyManager
            self.NtlmProxyTunnel = NtlmProxyTunnel
            self.is_ntlm_auth_available = is_ntlm_auth_available
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Module ntlm_auth non disponible")

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_tunnel_establishment(self, mock_ssl_context, mock_create_connection):
        """Vérifie l'établissement d'un tunnel NTLM"""
        # Configurer les mocks
        mock_socket = MockSocket()
        mock_create_connection.return_value = mock_socket
        
        mock_ssl_socket = MockSSLSocket(mock_socket)
        mock_ssl_context = MagicMock()
        mock_ssl_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_ssl_context
        
        # Configurer les réponses pour simuler une authentification réussie
        mock_socket.responses = [
            b'HTTP/1.1 407 Proxy Authentication Required\r\n'
            b'Proxy-Authenticate: NTLM TlRMTVNTUAABAAAAB4IIAA==\r\n'
            b'\r\n',
            
            b'HTTP/1.1 200 Connection established\r\n'
            b'\r\n'
        ]
        
        # Créer le tunnel
        tunnel = self.NtlmProxyTunnel(
            proxy_host='proxy.example.com',
            proxy_port=8080,
            username='testuser',
            password=SecurePassword('testpass'),
            domain='TESTDOMAIN',
            workstation='TESTPC'
        )
        
        # Établir la connexion
        ssl_sock = tunnel.open_tunnel('target.example.com', 443)
        
        # Vérifier que les requêtes CONNECT ont été envoyées
        self.assertEqual(len(mock_socket.sent_data), 2)
        
        # Vérifier que la première requête contient le message Negotiate
        self.assertIn(b'CONNECT target.example.com:443', mock_socket.sent_data[0])
        self.assertIn(b'Proxy-Authorization: NTLM', mock_socket.sent_data[0])
        
        # Vérifier que la deuxième requête contient le message Authenticate
        self.assertIn(b'CONNECT target.example.com:443', mock_socket.sent_data[1])
        self.assertIn(b'Proxy-Authorization: NTLM', mock_socket.sent_data[1])
        
        # Vérifier que la connexion SSL a été établie
        self.assertEqual(ssl_sock, mock_ssl_socket)

    def test_ntlm_proxy_manager_creation(self):
        """Vérifie la création du gestionnaire de proxy NTLM"""
        # Patcher les dépendances
        with patch('iziproxy.ntlm_auth.NtlmProxyAdapter') as mock_adapter:
            mock_adapter_instance = MagicMock()
            mock_adapter.return_value = mock_adapter_instance
            
            with patch('requests.Session') as mock_session:
                mock_session_instance = MagicMock()
                mock_session.return_value = mock_session_instance
                
                # Créer le gestionnaire
                manager = self.NtlmProxyManager()
                session = manager.create_ntlm_proxy_session(
                    proxy_host='proxy.example.com',
                    proxy_port=8080,
                    username='testuser',
                    password='testpass',
                    domain='TESTDOMAIN'
                )
                
                # Vérifier que l'adaptateur NTLM a été créé avec les bons paramètres
                mock_adapter.assert_called_with(
                    proxy_host='proxy.example.com',
                    proxy_port=8080,
                    username='testuser',
                    password='testpass',
                    domain='TESTDOMAIN',
                    workstation='WORKSTATION',
                    debug=False
                )
                
                # Vérifier que l'adaptateur a été monté sur la session
                mock_session_instance.mount.assert_any_call('https://', mock_adapter_instance)
                mock_session_instance.mount.assert_any_call('http://', mock_adapter_instance)
                
                # Vérifier que les paramètres de session sont corrects
                self.assertEqual(mock_session_instance.proxies, {})
                self.assertFalse(mock_session_instance.trust_env)

    def test_is_ntlm_auth_available(self):
        """Vérifie la détection de la disponibilité de ntlm_auth"""
        # Le mock est en place, donc ntlm_auth devrait être disponible
        self.assertTrue(self.is_ntlm_auth_available())


if __name__ == '__main__':
    unittest.main()
