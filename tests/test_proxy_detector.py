"""
Tests unitaires pour le module proxy_detector
"""

import os
import unittest
import urllib
from unittest.mock import patch, MagicMock

from iziproxy.proxy_detector import ProxyDetector


class TestProxyDetector(unittest.TestCase):
    """Tests pour la classe ProxyDetector"""

    def setUp(self):
        """Initialisation avant chaque test"""
        self.config = {
            "use_system_proxy": True,
            "detect_pac": True
        }
        
        # Nettoyer les variables d'environnement pour les tests
        self.clean_env_vars()
        
    def clean_env_vars(self):
        """Nettoie les variables d'environnement pour les tests"""
        for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", 
                   "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"]:
            if var in os.environ:
                del os.environ[var]
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        self.clean_env_vars()
        
    def test_empty_detection(self):
        """Vérifie que la détection retourne un dict vide par défaut"""
        # Patcher toutes les méthodes de détection pour qu'elles retournent un dict vide
        with patch.object(ProxyDetector, '_detect_env_vars', return_value={}), \
             patch.object(ProxyDetector, '_detect_system_settings', return_value={}), \
             patch.object(ProxyDetector, '_detect_pac_file', return_value={}):
            
            detector = ProxyDetector(self.config)
            proxies = detector.detect_system_proxy()
            
            self.assertEqual(proxies, {})

    def test_detect_from_env_vars(self):
        """Vérifie la détection depuis les variables d'environnement"""
        env_vars = {
            'HTTP_PROXY': 'http://proxy.example.com:8080',
            'HTTPS_PROXY': 'http://proxy.example.com:8443'
        }
        
        with patch.dict('os.environ', env_vars):
            detector = ProxyDetector(self.config)
            
            # Patcher les autres méthodes pour s'assurer qu'elles ne sont pas utilisées
            with patch.object(detector, '_detect_system_settings', return_value={}), \
                 patch.object(detector, '_detect_pac_file', return_value={}):
                
                proxies = detector.detect_system_proxy()
                
                self.assertEqual(proxies['http'], 'http://proxy.example.com:8080')
                self.assertEqual(proxies['https'], 'http://proxy.example.com:8443')

    def test_both_http_https_from_http(self):
        """Vérifie que HTTP est utilisé pour HTTPS si HTTPS n'est pas défini"""
        env_vars = {
            'HTTP_PROXY': 'http://proxy.example.com:8080',
        }
        
        with patch.dict('os.environ', env_vars):
            detector = ProxyDetector(self.config)
            
            # Patcher les autres méthodes
            with patch.object(detector, '_detect_system_settings', return_value={}), \
                 patch.object(detector, '_detect_pac_file', return_value={}):
                
                proxies = detector.detect_system_proxy()
                
                self.assertEqual(proxies['http'], 'http://proxy.example.com:8080')
                self.assertEqual(proxies['https'], 'http://proxy.example.com:8080')

    def test_pac_detection(self):
        """Vérifie la détection et l'utilisation de fichier PAC"""
        # Simuler une URL PAC détectée dans les paramètres système
        with patch.object(ProxyDetector, '_detect_system_settings', 
                          return_value={'pac_url': 'http://internal.example.com/proxy.pac'}), \
             patch.object(ProxyDetector, '_fetch_pac', 
                          return_value='function FindProxyForURL(url, host) { return "PROXY proxy.example.com:8080"; }'):
            
            detector = ProxyDetector(self.config)
            
            # Simuler pypac disponible
            with patch.dict('sys.modules', {'pypac': MagicMock()}):
                # Créer un mock pour PACFile et find_proxy_for_url
                pac_mock = MagicMock()
                pac_mock.find_proxy_for_url.return_value = "PROXY proxy.example.com:8080"
                
                # Patcher le parser de pypac pour retourner notre mock
                with patch('pypac.parser.PACFile', return_value=pac_mock):
                    proxies = detector.detect_system_proxy('https://example.com')
                    
                    self.assertEqual(proxies['http'], 'http://proxy.example.com:8080')
                    self.assertEqual(proxies['https'], 'http://proxy.example.com:8080')

    def test_caching(self):
        """Vérifie que les résultats sont mis en cache"""
        detector = ProxyDetector(self.config)
        
        # Premier appel - détection réelle
        with patch.object(detector, '_detect_env_vars', 
                          return_value={'http': 'http://proxy1.example.com'}):
            proxies1 = detector.detect_system_proxy()
            self.assertEqual(proxies1['http'], 'http://proxy1.example.com')
        
        # Second appel - devrait utiliser le cache même si la méthode retourne autre chose
        with patch.object(detector, '_detect_env_vars', 
                          return_value={'http': 'http://proxy2.example.com'}):
            proxies2 = detector.detect_system_proxy()
            self.assertEqual(proxies2['http'], 'http://proxy1.example.com')  # Toujours proxy1
        
        # Appel avec force_refresh - devrait détecter à nouveau
        with patch.object(detector, '_detect_env_vars', 
                          return_value={'http': 'http://proxy2.example.com'}):
            proxies3 = detector.detect_system_proxy(force_refresh=True)
            self.assertEqual(proxies3['http'], 'http://proxy2.example.com')  # Maintenant proxy2

    def test_clear_cache(self):
        """Vérifie que clear_cache() vide correctement le cache"""
        detector = ProxyDetector(self.config)
        
        # Remplir le cache
        with patch.object(detector, '_detect_env_vars', 
                          return_value={'http': 'http://proxy1.example.com'}):
            proxies1 = detector.detect_system_proxy()
            self.assertEqual(proxies1['http'], 'http://proxy1.example.com')
        
        # Vider le cache
        detector.clear_cache()
        
        # Le prochain appel devrait refaire la détection
        with patch.object(detector, '_detect_env_vars', 
                          return_value={'http': 'http://proxy2.example.com'}):
            proxies2 = detector.detect_system_proxy()
            self.assertEqual(proxies2['http'], 'http://proxy2.example.com')
            
    def test_proxy_detection_disabled(self):
        """Vérifie que la détection peut être désactivée via la configuration"""
        config = {
            "use_system_proxy": False,
            "detect_pac": True
        }
        
        detector = ProxyDetector(config)
        
        # Même avec des variables d'environnement définies, aucun proxy ne devrait être détecté
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://proxy.example.com:8080'}):
            proxies = detector.detect_system_proxy()
            
            # Devrait retourner un dictionnaire vide
            self.assertEqual(proxies, {})
            
    def test_system_detection_fallback(self):
        """Vérifie le fallback entre les méthodes de détection"""
        detector = ProxyDetector(self.config)
        
        # Simuler un échec de la première méthode (_detect_env_vars)
        with patch.object(detector, '_detect_env_vars', return_value={}), \
             patch.object(detector, '_detect_system_settings', 
                          return_value={'http': 'http://system-proxy.example.com:8080'}), \
             patch.object(detector, '_detect_pac_file', return_value={}):
            
            proxies = detector.detect_system_proxy()
            
            # Devrait utiliser la deuxième méthode
            self.assertEqual(proxies['http'], 'http://system-proxy.example.com:8080')
            
    def test_all_proxy_variable(self):
        """Vérifie que ALL_PROXY est utilisé pour HTTP et HTTPS"""
        env_vars = {
            'ALL_PROXY': 'http://all-proxy.example.com:8080'
        }
        
        with patch.dict('os.environ', env_vars):
            detector = ProxyDetector(self.config)
            
            with patch.object(detector, '_detect_system_settings', return_value={}), \
                 patch.object(detector, '_detect_pac_file', return_value={}):
                
                proxies = detector.detect_system_proxy()
                
                # ALL_PROXY devrait être utilisé pour HTTP et HTTPS
                self.assertEqual(proxies['http'], 'http://all-proxy.example.com:8080')
                self.assertEqual(proxies['https'], 'http://all-proxy.example.com:8080')
                
    def test_no_proxy_variable(self):
        """Vérifie que NO_PROXY est correctement détecté"""
        env_vars = {
            'HTTP_PROXY': 'http://proxy.example.com:8080',
            'NO_PROXY': 'localhost,127.0.0.1,example.com'
        }
        
        with patch.dict('os.environ', env_vars):
            detector = ProxyDetector(self.config)
            
            with patch.object(detector, '_detect_system_settings', return_value={}), \
                 patch.object(detector, '_detect_pac_file', return_value={}):
                
                proxies = detector.detect_system_proxy()
                
                # NO_PROXY devrait être inclus dans le résultat
                self.assertEqual(proxies['no_proxy'], 'localhost,127.0.0.1,example.com')
                
    def test_get_system_info(self):
        """Vérifie la récupération des informations système"""
        with patch('platform.system', return_value='TestOS'), \
             patch('platform.version', return_value='1.0'), \
             patch('platform.release', return_value='test'), \
             patch('socket.gethostname', return_value='TEST-HOST'):
            
            detector = ProxyDetector(self.config)
            system_info = detector._get_system_info()
            
            self.assertEqual(system_info['os'], 'testos')
            self.assertEqual(system_info['os_version'], '1.0')
            self.assertEqual(system_info['os_release'], 'test')
            self.assertEqual(system_info['hostname'], 'test-host')
                
    @patch('urllib.request.urlopen')
    def test_fetch_pac(self, mock_urlopen):
        """Vérifie le téléchargement de fichier PAC"""
        # Configurer la réponse mock
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'function FindProxyForURL(url, host) { return "DIRECT"; }'
        mock_urlopen.return_value = mock_response
        
        detector = ProxyDetector(self.config)
        pac_content = detector._fetch_pac('http://example.com/proxy.pac')
        
        # Vérifier que le contenu est correctement récupéré
        self.assertEqual(pac_content, 'function FindProxyForURL(url, host) { return "DIRECT"; }')
        
        # Vérifier que urlopen a été appelé avec les bons paramètres
        mock_urlopen.assert_called_once()
        args, kwargs = mock_urlopen.call_args
        self.assertEqual(args[0], 'http://example.com/proxy.pac')
        self.assertEqual(kwargs['timeout'], 5)
        
    @patch('urllib.request.urlopen')
    def test_fetch_pac_error(self, mock_urlopen):
        """Vérifie la gestion des erreurs lors du téléchargement de fichier PAC"""
        # Simuler une erreur
        mock_urlopen.side_effect = urllib.error.URLError('Failed to download PAC')
        
        detector = ProxyDetector(self.config)
        pac_content = detector._fetch_pac('http://example.com/proxy.pac')
        
        # Devrait retourner None en cas d'erreur
        self.assertIsNone(pac_content)

    @patch('sys.platform', 'win32')
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_detect_windows_proxy(self, mock_query_value, mock_open_key):
        """Vérifie la détection de proxy sur Windows"""
        # Cette fonction n'est testée que sur Windows, on simule donc l'environnement

        # Configurer les mocks pour simuler un proxy Windows
        mock_open_key.return_value = MagicMock()

        # Définir un comportement basé sur les arguments d'appel
        def query_value_side_effect(key, value_name):
            if value_name == 'ProxyEnable':
                return (1, 0)  # Proxy activé
            elif value_name == 'ProxyServer':
                return ('proxy.example.com:8080', 0)  # Serveur proxy
            elif value_name == 'ProxyOverride':
                return ('localhost;127.0.0.1', 0)  # Exceptions
            elif value_name == 'AutoConfigURL':
                # Simuler l'absence de fichier PAC
                raise FileNotFoundError()
            return None

        mock_query_value.side_effect = query_value_side_effect

        detector = ProxyDetector(self.config)
        result = detector._detect_windows_proxy()

        # Vérifier que le proxy est correctement détecté
        self.assertEqual(result['http'], 'http://proxy.example.com:8080')
        self.assertEqual(result['https'], 'http://proxy.example.com:8080')
        self.assertEqual(result['no_proxy'], 'localhost,127.0.0.1')
        
    @patch('sys.platform', 'win32')
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_detect_windows_proxy_with_pac(self, mock_query_value, mock_open_key):
        """Vérifie la détection de fichier PAC sur Windows"""

        # Configurer les mocks pour simuler un fichier PAC Windows
        mock_open_key.return_value = MagicMock()
        
        # Simuler un PAC configuré
        mock_query_value.side_effect = [
            ('http://internal.example.com/proxy.pac', 0),  # AutoConfigURL
            (0, 0)  # ProxyEnable = 0 (désactivé)
        ]
        
        detector = ProxyDetector(self.config)
        result = detector._detect_windows_proxy()
        
        # Vérifier que l'URL PAC est correctement détectée
        self.assertEqual(result['pac_url'], 'http://internal.example.com/proxy.pac')
        self.assertEqual(detector._pac_url, 'http://internal.example.com/proxy.pac')

    @patch('sys.platform', 'win32')
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_detect_windows_proxy_per_protocol(self, mock_query_value, mock_open_key):
        """Vérifie la détection de proxy par protocole sur Windows"""

        # Configurer les mocks pour simuler un proxy Windows avec différentes adresses par protocole
        mock_open_key.return_value = MagicMock()

        # Définir un comportement basé sur les arguments d'appel
        def query_value_side_effect(key, value_name):
            if value_name == 'ProxyEnable':
                return (1, 0)  # Proxy activé
            elif value_name == 'ProxyServer':
                return ('http=proxy-http.example.com:8080;https=proxy-https.example.com:8443', 0)  # Serveur proxy par protocole
            elif value_name == 'ProxyOverride':
                return ('localhost', 0)  # Exceptions
            elif value_name == 'AutoConfigURL':
                # Simuler l'absence de fichier PAC
                raise FileNotFoundError()
            return None

        mock_query_value.side_effect = query_value_side_effect

        detector = ProxyDetector(self.config)
        result = detector._detect_windows_proxy()

        # Vérifier que les proxies par protocole sont correctement détectés
        self.assertEqual(result['http'], 'http://proxy-http.example.com:8080')
        self.assertEqual(result['https'], 'http://proxy-https.example.com:8443')
        self.assertEqual(result['no_proxy'], 'localhost')
        
    def test_pac_detection_without_pypac(self):
        """Vérifie la gestion lorsque pypac n'est pas disponible"""
        # Simuler une URL PAC détectée
        detector = ProxyDetector(self.config)
        detector._pac_url = 'http://internal.example.com/proxy.pac'
        
        # Simuler pypac non disponible
        with patch.dict('sys.modules', {'pypac': None}):
            proxies = detector._detect_pac_file('https://example.com')
            
            # Devrait retourner un dictionnaire vide
            self.assertEqual(proxies, {})
        
    def test_detect_different_url(self):
        """Vérifie la détection pour différentes URLs cibles"""
        detector = ProxyDetector(self.config)
        
        # Simuler un PAC qui retourne différents proxies selon l'URL
        def mock_detect_pac(url):
            if url == 'https://example.com':
                return {'http': 'http://proxy1.example.com:8080', 'https': 'http://proxy1.example.com:8080'}
            elif url == 'https://example.org':
                return {'http': 'http://proxy2.example.com:8080', 'https': 'http://proxy2.example.com:8080'}
            return {}
            
        with patch.object(detector, '_detect_env_vars', return_value={}), \
             patch.object(detector, '_detect_system_settings', return_value={}), \
             patch.object(detector, '_detect_pac_file', side_effect=mock_detect_pac):
                
            # Détecter pour la première URL
            proxies1 = detector.detect_system_proxy('https://example.com')
            self.assertEqual(proxies1['http'], 'http://proxy1.example.com:8080')
            
            # Détecter pour la seconde URL
            proxies2 = detector.detect_system_proxy('https://example.org')
            self.assertEqual(proxies2['http'], 'http://proxy2.example.com:8080')

    @patch('sys.platform', 'darwin')
    @patch('subprocess.check_output')
    def test_detect_macos_proxy(self, mock_check_output):
        """Vérifie la détection de proxy sur macOS"""
        # Reste du test inchangé
        mock_check_output.side_effect = [
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet",
            "Enabled: Yes\nServer: proxy.example.com\nPort: 8080\nAuthenticated Proxy Enabled: 0",
            "Enabled: Yes\nServer: proxy-https.example.com\nPort: 8443\nAuthenticated Proxy Enabled: 0",
            "Enabled: No"
        ]

        detector = ProxyDetector(self.config)
        result = detector._detect_macos_proxy()

        self.assertEqual(result['http'], 'http://proxy.example.com:8080')
        self.assertEqual(result['https'], 'http://proxy-https.example.com:8443')

    @patch('sys.platform', 'linux')  # Simule Linux
    @patch('subprocess.check_output')
    def test_detect_linux_proxy(self, mock_check_output):
        """Vérifie la détection de proxy sur Linux"""
        # Reste du test inchangé
        mock_check_output.side_effect = [
            "'manual'",
            "'proxy.example.com'",
            "8080",
            "'proxy-https.example.com'",
            "8443",
            "['localhost', '127.0.0.1']"
        ]

        detector = ProxyDetector(self.config)
        result = detector._detect_linux_proxy()

        self.assertEqual(result['http'], 'http://proxy.example.com:8080')
        self.assertEqual(result['https'], 'http://proxy-https.example.com:8443')
        self.assertEqual(result['no_proxy'], 'localhost,127.0.0.1')


if __name__ == '__main__':
    unittest.main()
