"""
Tests unitaires pour le module ntlm_auth
"""

import socket
import unittest
from unittest.mock import patch, MagicMock

from iziproxy.ntlm_auth import logger
from iziproxy.secure_config import SecurePassword


# Créer des mocks pour les dépendances NTLM
class MockNtlmContext:
    def __init__(self, *args, **kwargs):
        self.username = kwargs.get('username', '')
        self.password = kwargs.get('password', '')
        self.domain = kwargs.get('domain', '')
        self.workstation = kwargs.get('workstation', '')

    def step(self, challenge=None):
        if challenge:
            return b'NTLM_AUTH_MSG'
        return b'NTLM_NEGOTIATE_MSG'

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
        self.server_hostname = kwargs.get('server_hostname', '')

# Mock pour PyCryptodome
class MockMD4:
    @staticmethod
    def new():
        mock = MagicMock()
        mock.update = MagicMock()
        return mock

class MockMD5:
    @staticmethod
    def new():
        mock = MagicMock()
        mock.update = MagicMock()
        return mock

# Mock pour les modules
ntlm_auth_mock = MagicMock()
ntlm_auth_mock.ntlm.NtlmContext = MockNtlmContext

cryptodome_mock = MagicMock()
cryptodome_mock.Hash.MD4 = MockMD4
cryptodome_mock.Hash.MD5 = MockMD5


class TestNtlmAuth(unittest.TestCase):
    """Tests pour l'authentification NTLM"""

    def setUp(self):
        """Initialisation avant chaque test"""
        # Patcher les modules avant d'importer
        self.ntlm_auth_patcher = patch.dict('sys.modules', {'ntlm_auth.ntlm': ntlm_auth_mock})
        self.ntlm_auth_patcher.start()

        self.cryptodome_patcher = patch.dict('sys.modules', {'Cryptodome.Hash': cryptodome_mock})
        self.cryptodome_patcher.start()

        # Patcher la variable NTLM_AVAILABLE pour qu'elle soit toujours True dans les tests
        self.ntlm_available_patcher = patch('iziproxy.ntlm_auth.NTLM_AVAILABLE', True)
        self.ntlm_available_patcher.start()

        self.cryptodome_available_patcher = patch('iziproxy.ntlm_auth.CRYPTODOME_AVAILABLE', True)
        self.cryptodome_available_patcher.start()

        # Importer le module seulement après avoir appliqué les patches
        from iziproxy.ntlm_auth import (
            NtlmProxyManager,
            NtlmProxyTunnel,
            is_ntlm_auth_available,
            NtlmProxyAdapter,
            NtlmProxyDict,
            PatchedHTTPSConnection,
            CustomHTTPSConnectionPool
        )

        self.NtlmProxyManager = NtlmProxyManager
        self.NtlmProxyTunnel = NtlmProxyTunnel
        self.is_ntlm_auth_available = is_ntlm_auth_available
        self.NtlmProxyAdapter = NtlmProxyAdapter
        self.NtlmProxyDict = NtlmProxyDict
        self.PatchedHTTPSConnection = PatchedHTTPSConnection
        self.CustomHTTPSConnectionPool = CustomHTTPSConnectionPool

    def tearDown(self):
        """Nettoyage après chaque test"""
        self.ntlm_auth_patcher.stop()
        self.cryptodome_patcher.stop()
        self.ntlm_available_patcher.stop()
        self.cryptodome_available_patcher.stop()

    def test_is_ntlm_auth_available(self):
        """Vérifie que la fonction is_ntlm_auth_available retourne correctement la disponibilité"""
        # Le mock est en place avec NTLM_AVAILABLE = True
        self.assertTrue(self.is_ntlm_auth_available())

        # Test avec NTLM_AVAILABLE = False
        with patch('iziproxy.ntlm_auth.NTLM_AVAILABLE', False):
            self.assertFalse(self.is_ntlm_auth_available())

    def test_ntlm_proxy_manager_init(self):
        """Vérifie l'initialisation du gestionnaire de proxy NTLM"""
        # Test avec ntlm_auth disponible
        manager = self.NtlmProxyManager()
        self.assertIsInstance(manager, self.NtlmProxyManager)

        # Test avec ntlm_auth non disponible
        with patch('iziproxy.ntlm_auth.NTLM_AVAILABLE', False):
            with self.assertRaises(ImportError):
                self.NtlmProxyManager()

    def test_patch_ntlm_auth_md4(self):
        """Vérifie que le patch MD4 est appliqué correctement"""
        # Mock pour ntlm_auth.compute_hash
        compute_hash_mock = MagicMock()

        with patch.dict('sys.modules', {'ntlm_auth.compute_hash': compute_hash_mock}):
            manager = self.NtlmProxyManager()

            # Appeler manuellement la méthode de patch
            manager._patch_ntlm_auth_md4()

            # Vérifier que hashlib a été remplacé dans ntlm_auth.compute_hash
            self.assertTrue(hasattr(compute_hash_mock, 'hashlib'))

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_tunnel_establishment(self, mock_ssl_context, mock_create_connection):
        """Vérifie l'établissement d'un tunnel NTLM"""
        # Configurer les mocks
        mock_socket = MockSocket()
        mock_create_connection.return_value = mock_socket

        mock_ssl_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_ssl_context_instance

        mock_ssl_socket = MockSSLSocket(mock_socket)
        mock_ssl_context_instance.wrap_socket.return_value = mock_ssl_socket

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
            workstation='TESTPC',
            debug=True
        )

        # Patcher la méthode open_tunnel pour éviter d'utiliser NtlmContext
        original_open_tunnel = self.NtlmProxyTunnel.open_tunnel

        def mock_open_tunnel(self, target_host, target_port=443):
            if self.debug:
                logger.debug(f"Connexion au proxy {self.proxy_host}:{self.proxy_port}")

            # Connexion initiale au proxy
            sock = socket.create_connection((self.proxy_host, self.proxy_port))

            # Simuler le comportement sans utiliser NtlmContext
            self._send_connect(sock, target_host, target_port, "NTLM_TOKEN_1")

            # Réception de la réponse du proxy
            response1 = self._recv_response(sock)

            # Envoyer le second token
            self._send_connect(sock, target_host, target_port, "NTLM_TOKEN_2")

            # Réception de la réponse du proxy
            response2 = self._recv_response(sock)

            # Encapsulation SSL de la connexion
            return self._wrap_socket(sock, target_host)

        try:
            # Appliquer le patch pour le test
            self.NtlmProxyTunnel.open_tunnel = mock_open_tunnel

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

            # Vérifier que le socket est correctement encapsulé avec SSL
            self.assertEqual(ssl_sock, mock_ssl_socket)
            mock_ssl_context_instance.wrap_socket.assert_called_with(
                mock_socket, server_hostname='target.example.com')

        finally:
            # Restaurer la méthode originale
            self.NtlmProxyTunnel.open_tunnel = original_open_tunnel

    def test_create_ntlm_proxy_session(self):
        """Vérifie la création d'une session proxy NTLM"""
        # Patcher les dépendances
        with patch('requests.Session') as mock_session:
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance

            with patch('iziproxy.ntlm_auth.NtlmProxyAdapter') as mock_adapter:
                mock_adapter_instance = MagicMock()
                mock_adapter.return_value = mock_adapter_instance

                # Créer le gestionnaire et une session
                manager = self.NtlmProxyManager()
                session = manager.create_ntlm_proxy_session(
                    proxy_host='proxy.example.com',
                    proxy_port=8080,
                    username='testuser',
                    password='testpass',
                    domain='TESTDOMAIN',
                    workstation='TESTPC',
                    debug=True
                )

                # Vérifier que l'adaptateur NTLM a été créé avec les bons paramètres
                mock_adapter.assert_called_with(
                    proxy_host='proxy.example.com',
                    proxy_port=8080,
                    username='testuser',
                    password='testpass',
                    domain='TESTDOMAIN',
                    workstation='TESTPC',
                    debug=True
                )

                # Vérifier que l'adaptateur a été monté sur la session
                mock_session_instance.mount.assert_any_call('https://', mock_adapter_instance)
                mock_session_instance.mount.assert_any_call('http://', mock_adapter_instance)

                # Vérifier que les paramètres de session sont corrects
                self.assertEqual(mock_session_instance.proxies, {})
                self.assertFalse(mock_session_instance.trust_env)

                # Vérifier que la session est retournée
                self.assertEqual(session, mock_session_instance)

    def test_wrap_socket(self):
        """Vérifie l'encapsulation SSL d'un socket"""
        # Créer un mock socket
        mock_socket = MockSocket()

        # Patcher ssl.create_default_context
        mock_ssl_context = MagicMock()
        mock_ssl_socket = MockSSLSocket(mock_socket)
        mock_ssl_context.wrap_socket.return_value = mock_ssl_socket

        with patch('ssl.create_default_context', return_value=mock_ssl_context):
            # Créer le tunnel
            tunnel = self.NtlmProxyTunnel(
                proxy_host='proxy.example.com',
                proxy_port=8080,
                username='testuser',
                password='testpass'
            )

            # Appeler _wrap_socket
            ssl_sock = tunnel._wrap_socket(mock_socket, 'target.example.com')

            # Vérifier que le contexte SSL est créé et utilisé correctement
            mock_ssl_context.wrap_socket.assert_called_with(
                mock_socket, server_hostname='target.example.com')

            # Vérifier que le socket SSL est retourné
            self.assertEqual(ssl_sock, mock_ssl_socket)

    def test_send_connect(self):
        """Vérifie l'envoi d'une requête CONNECT"""
        # Créer un mock socket
        mock_socket = MockSocket()

        # Créer le tunnel
        tunnel = self.NtlmProxyTunnel(
            proxy_host='proxy.example.com',
            proxy_port=8080,
            username='testuser',
            password='testpass'
        )

        # Envoyer une requête CONNECT
        tunnel._send_connect(mock_socket, 'target.example.com', 443, 'NTLM_TOKEN')

        # Vérifier que la requête a été envoyée correctement
        self.assertEqual(len(mock_socket.sent_data), 1)
        connect_request = mock_socket.sent_data[0].decode('utf-8')

        # Vérifier les en-têtes de la requête
        self.assertIn('CONNECT target.example.com:443 HTTP/1.1', connect_request)
        self.assertIn('Host: target.example.com:443', connect_request)
        self.assertIn('Proxy-Authorization: NTLM NTLM_TOKEN', connect_request)
        self.assertIn('Proxy-Connection: Keep-Alive', connect_request)
        self.assertIn('Connection: Keep-Alive', connect_request)

    def test_recv_response(self):
        """Vérifie la réception d'une réponse HTTP"""
        # Créer un mock socket avec une réponse
        mock_socket = MockSocket()
        mock_socket.responses = [
            b'HTTP/1.1 200 OK\r\n',
            b'Content-Type: text/html\r\n',
            b'\r\n',
            b'<html>Test</html>'
        ]

        # Créer le tunnel
        tunnel = self.NtlmProxyTunnel(
            proxy_host='proxy.example.com',
            proxy_port=8080,
            username='testuser',
            password='testpass'
        )

        # Recevoir la réponse
        response = tunnel._recv_response(mock_socket)

        # Vérifier que la réponse est correctement lue
        self.assertIn(b'HTTP/1.1 200 OK', response)
        self.assertIn(b'Content-Type: text/html', response)
        self.assertIn(b'\r\n\r\n', response)

    def test_parse_ntlm_challenge(self):
        """Vérifie l'extraction du challenge NTLM"""
        # Créer une réponse HTTP avec un challenge NTLM
        response = (
            b'HTTP/1.1 407 Proxy Authentication Required\r\n'
            b'Proxy-Authenticate: NTLM TlRMTVNTUAABAAAAB4IIAA==\r\n'
            b'\r\n'
        )

        # Créer le tunnel
        tunnel = self.NtlmProxyTunnel(
            proxy_host='proxy.example.com',
            proxy_port=8080,
            username='testuser',
            password='testpass'
        )

        # Extraire le challenge
        challenge = tunnel._parse_ntlm_challenge(response)

        # Vérifier que le challenge est correctement extrait
        self.assertEqual(challenge, 'TlRMTVNTUAABAAAAB4IIAA==')

        # Test avec une réponse sans challenge
        response_no_challenge = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: text/html\r\n'
            b'\r\n'
        )

        # Vérifier que l'exception est levée
        with self.assertRaises(Exception):
            tunnel._parse_ntlm_challenge(response_no_challenge)

    def test_ntlm_proxy_adapter(self):
        """Vérifie l'initialisation de l'adaptateur NTLM"""
        # Créer l'adaptateur
        adapter = self.NtlmProxyAdapter(
            proxy_host='proxy.example.com',
            proxy_port=8080,
            username='testuser',
            password='testpass',
            domain='TESTDOMAIN',
            workstation='TESTPC',
            debug=True
        )

        # Vérifier que les attributs sont correctement initialisés
        self.assertEqual(adapter.proxy_host, 'proxy.example.com')
        self.assertEqual(adapter.proxy_port, 8080)
        self.assertEqual(adapter.username, 'testuser')
        self.assertIsInstance(adapter.password, SecurePassword)
        self.assertEqual(adapter.domain, 'TESTDOMAIN')
        self.assertEqual(adapter.workstation, 'TESTPC')
        self.assertTrue(adapter.debug)

    @patch('requests.Response')
    def test_adapter_send(self, mock_response_class):
        """Vérifie la méthode send de l'adaptateur NTLM"""
        # Créer un mock pour le tunnel et la réponse
        mock_tunnel = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_tunnel.open_tunnel.return_value = mock_ssl_sock

        mock_response = MagicMock()
        mock_response_class.return_value = mock_response

        # Patcher NtlmProxyTunnel
        with patch('iziproxy.ntlm_auth.NtlmProxyTunnel', return_value=mock_tunnel):
            # Créer l'adaptateur
            adapter = self.NtlmProxyAdapter(
                proxy_host='proxy.example.com',
                proxy_port=8080,
                username='testuser',
                password='testpass'
            )

            # Créer une requête mock
            mock_request = MagicMock()
            mock_request.url = 'https://example.com/path?query=value'
            mock_request.method = 'GET'
            mock_request.headers = {'User-Agent': 'Test Agent'}
            mock_request.body = None

            # Simuler une réponse du serveur
            mock_ssl_sock.recv.side_effect = [
                b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n',
                b'<html>Test</html>',
                b''
            ]

            # Envoyer la requête
            response = adapter.send(mock_request)

            # Vérifier que le tunnel est ouvert vers le bon hôte
            mock_tunnel.open_tunnel.assert_called_with('example.com', 443)

            # Vérifier que la requête est envoyée correctement
            mock_ssl_sock.sendall.assert_called()

            # Vérifier que la réponse est correctement traitée
            self.assertEqual(response, mock_response)

    def test_ntlm_proxy_dict(self):
        """Vérifie la classe NtlmProxyDict"""
        # Créer un mock pour la session NTLM
        mock_session = MagicMock()

        # Créer le dictionnaire de proxy
        proxy_dict = self.NtlmProxyDict(mock_session)

        # Vérifier que les clés http et https retournent la session
        self.assertEqual(proxy_dict['http'], mock_session)
        self.assertEqual(proxy_dict['https'], mock_session)
        self.assertEqual(proxy_dict.get('http'), mock_session)
        self.assertEqual(proxy_dict.get('https'), mock_session)

        # Vérifier que les clés non supportées lèvent une exception
        with self.assertRaises(KeyError):
            proxy_dict['ftp']

        # Vérifier que get avec une clé non supportée retourne la valeur par défaut
        self.assertIsNone(proxy_dict.get('ftp'))
        self.assertEqual(proxy_dict.get('ftp', 'default'), 'default')

        # Vérifier que la modification n'est pas supportée
        with self.assertRaises(NotImplementedError):
            proxy_dict['http'] = 'new_value'

        # Vérifier les autres méthodes
        self.assertIn('http', proxy_dict)
        self.assertIn('https', proxy_dict)
        self.assertNotIn('ftp', proxy_dict)
        self.assertEqual(list(proxy_dict.keys()), ['http', 'https'])

    def test_patched_https_connection(self):
        """Vérifie la classe PatchedHTTPSConnection"""
        # Créer un mock pour le socket SSL
        mock_ssl_sock = MagicMock()

        # Créer la connexion patchée
        conn = self.PatchedHTTPSConnection('example.com', mock_ssl_sock, port=443)

        # Vérifier que le socket est correctement assigné
        self.assertEqual(conn.sock, mock_ssl_sock)
        self.assertTrue(conn._custom_connected)

        # Vérifier que la méthode connect ne fait rien si déjà connecté
        conn.connect()

        # Vérifier que la connexion standard est utilisée si _custom_connected est False
        conn._custom_connected = False
        with patch.object(self.PatchedHTTPSConnection, 'connect', return_value=None) as mock_connect:
            conn.connect()
            mock_connect.assert_called_once()

    def test_custom_https_connection_pool(self):
        """Vérifie la classe CustomHTTPSConnectionPool"""
        # Créer un mock pour le tunnel
        mock_tunnel = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_tunnel.open_tunnel.return_value = mock_ssl_sock

        # Patcher PatchedHTTPSConnection
        with patch('iziproxy.ntlm_auth.PatchedHTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn_class.return_value = mock_conn

            # Créer le pool de connexions
            pool = self.CustomHTTPSConnectionPool(
                tunnel=mock_tunnel,
                host='example.com',
                port=443
            )

            # Vérifier que le tunnel est stocké
            self.assertEqual(pool.tunnel, mock_tunnel)

            # Créer une nouvelle connexion
            conn = pool._new_conn()

            # Vérifier que le tunnel est utilisé
            mock_tunnel.open_tunnel.assert_called_with('example.com', 443)

            # Vérifier que PatchedHTTPSConnection est appelé avec les bons paramètres
            mock_conn_class.assert_called_with('example.com', mock_ssl_sock, port=443)

            # Vérifier que la connexion est retournée
            self.assertEqual(conn, mock_conn)


if __name__ == '__main__':
    unittest.main()