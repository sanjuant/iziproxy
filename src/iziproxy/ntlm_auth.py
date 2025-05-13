"""
Module d'authentification NTLM pour IziProxy
"""

import gzip
import io
import ssl
import socket
import base64
import logging
import requests
from urllib.parse import urlparse
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool

from iziproxy.secure_config import SecurePassword

# Configuration du logger
logger = logging.getLogger("iziproxy")

# Importations conditionnelles pour les dépendances NTLM
try:
    from ntlm_auth.ntlm import NtlmContext
    NTLM_AVAILABLE = True
except ImportError:
    logger.debug("Package ntlm_auth non disponible, le support NTLM ne sera pas activé")
    NTLM_AVAILABLE = False

# Essayer d'importer PyCryptodome pour le support MD4/MD5
try:
    from Cryptodome.Hash import MD4, MD5
    CRYPTODOME_AVAILABLE = True
except ImportError:
    logger.debug("Package pycryptodomex non disponible, le patch MD4 ne sera pas activé")
    CRYPTODOME_AVAILABLE = False


def is_ntlm_auth_available():
    """
    Vérifie si les dépendances pour l'authentification NTLM sont disponibles
    
    Returns:
        bool: True si les dépendances sont disponibles
    """
    return NTLM_AVAILABLE


class NtlmProxyManager:
    """
    Gestionnaire de proxy NTLM pour l'authentification sur les proxys d'entreprise
    
    Cette classe simplifie l'utilisation de l'authentification NTLM avec requests
    """

    def __init__(self):
        """
        Initialise le gestionnaire NTLM
        
        Raises:
            ImportError: Si le package ntlm_auth n'est pas disponible
        """
        # Vérifier les dépendances
        if not NTLM_AVAILABLE:
            raise ImportError("Le package ntlm_auth est requis pour utiliser l'authentification NTLM")

        # Appliquer le patch MD4 si PyCryptodome est disponible
        if CRYPTODOME_AVAILABLE:
            self._patch_ntlm_auth_md4()

    def _patch_ntlm_auth_md4(self):
        """
        Applique un patch pour ntlm_auth afin d'utiliser PyCryptodome pour MD4/MD5
        
        Cette méthode remplace l'implémentation hashlib de ntlm_auth par PyCryptodome,
        qui fournit une implémentation native de MD4 (nécessaire pour NTLM)
        """
        try:
            import ntlm_auth.compute_hash

            # Créer une implémentation de hashlib compatible avec ntlm_auth
            class FakeHashlib:
                @staticmethod
                def new(name, data=b''):
                    if name.lower() == 'md4':
                        h = MD4.new()
                        h.update(data)
                        return h
                    elif name.lower() == 'md5':
                        h = MD5.new()
                        h.update(data)
                        return h
                    else:
                        raise ValueError(f"Unsupported hash type: {name}")

                @staticmethod
                def md5(data=b''):
                    h = MD5.new()
                    h.update(data)
                    return h

            # Remplacer l'implémentation hashlib dans ntlm_auth
            ntlm_auth.compute_hash.hashlib = FakeHashlib
            logger.debug("Patch MD4/MD5 appliqué avec succès pour ntlm_auth")
        except Exception as e:
            logger.warning(f"Erreur lors de l'application du patch MD4: {e}")

    def create_ntlm_proxy_session(self, proxy_host, proxy_port, username, password, domain='', workstation='WORKSTATION', debug=False):
        """
        Crée une session requests configurée pour utiliser l'authentification NTLM
        
        Args:
            proxy_host (str): Hôte du proxy
            proxy_port (int): Port du proxy
            username (str): Nom d'utilisateur
            password (str): Mot de passe
            domain (str, optional): Domaine (optionnel)
            workstation (str, optional): Nom du poste de travail (optionnel)
            debug (bool, optional): Activer le mode débogage
            
        Returns:
            requests.Session: Session configurée avec l'adaptateur NTLM
        """
        session = requests.Session()
        adapter = NtlmProxyAdapter(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            username=username,
            password=password,
            domain=domain,
            workstation=workstation,
            debug=debug
        )
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        session.proxies = {}
        session.trust_env = False

        logger.debug(f"Session NTLM créée pour {username}@{proxy_host}:{proxy_port}")
        return session


class NtlmProxyTunnel:
    """
    Établit un tunnel HTTPS à travers un proxy avec authentification NTLM
    
    Cette classe gère la création et l'authentification d'un tunnel SSL
    à travers un proxy NTLM.
    """

    def __init__(self, proxy_host, proxy_port, username, password, domain='', workstation='WORKSTATION', debug=False):
        """
        Initialise le tunnel proxy NTLM
        
        Args:
            proxy_host (str): Hôte du proxy
            proxy_port (int): Port du proxy
            username (str): Nom d'utilisateur
            password (str ou SecurePassword): Mot de passe
            domain (str, optional): Domaine (optionnel)
            workstation (str, optional): Nom du poste de travail (optionnel)
            debug (bool, optional): Activer le mode débogage
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        # Assurer que le mot de passe est sécurisé
        if isinstance(password, SecurePassword):
            self.password = password
        else:
            self.password = SecurePassword(password)
        self.domain = domain
        self.workstation = workstation
        self.debug = debug

    def open_tunnel(self, target_host, target_port=443):
        """
        Ouvre un tunnel vers l'hôte cible via le proxy NTLM
        
        Args:
            target_host (str): Hôte de destination
            target_port (int, optional): Port de destination (443 par défaut)
            
        Returns:
            socket: Socket SSL connecté à la destination
            
        Raises:
            Exception: Si l'établissement du tunnel échoue
        """
        if self.debug:
            logger.debug(f"Connexion au proxy {self.proxy_host}:{self.proxy_port}")

        # Connexion initiale au proxy
        sock = socket.create_connection((self.proxy_host, self.proxy_port))

        # Création du contexte NTLM
        context = NtlmContext(
            username=self.username,
            password=self.password.get_password(),
            domain=self.domain,
            workstation=self.workstation,
        )

        # Étape 1: Envoi du message NTLM Negotiate
        negotiate_token = base64.b64encode(context.step()).decode('ascii')
        self._send_connect(sock, target_host, target_port, negotiate_token)

        # Réception de la réponse du proxy
        response1 = self._recv_response(sock)

        if b"407" not in response1:
            # Si le proxy ne demande pas d'authentification, vérifiez si la connexion est établie
            if b"200 connection established" in response1.lower():
                if self.debug:
                    logger.debug("Tunnel établi avec succès sans authentification")
                return self._wrap_socket(sock, target_host)
            else:
                raise Exception("Échec de l'établissement du tunnel proxy sans authentification.")

        # Extraction du challenge NTLM
        challenge_token = self._parse_ntlm_challenge(response1)
        if self.debug:
            logger.debug("Challenge NTLM reçu")

        # Étape 2: Envoi du message NTLM Authenticate
        authenticate_token = base64.b64encode(context.step(base64.b64decode(challenge_token))).decode('ascii')
        self._send_connect(sock, target_host, target_port, authenticate_token)

        # Réception de la réponse du proxy
        response2 = self._recv_response(sock)

        if self.debug:
            logger.debug("Réponse du proxy après authentification")
            logger.debug(response2.decode(errors='ignore').strip())

        if b"200 connection established" not in response2.lower():
            raise Exception("Échec de l'établissement du tunnel proxy après authentification.")

        if self.debug:
            logger.debug("Tunnel établi avec succès après authentification")

        # Encapsulation SSL de la connexion
        return self._wrap_socket(sock, target_host)

    def _wrap_socket(self, sock, target_host):
        """
        Encapsule la connexion avec SSL et retourne le socket SSL
        
        Args:
            sock (socket): Socket connecté au proxy
            target_host (str): Nom d'hôte cible pour la vérification SSL
            
        Returns:
            socket: Socket SSL connecté
        """
        ssl_context = ssl.create_default_context()
        return ssl_context.wrap_socket(sock, server_hostname=target_host)

    def _send_connect(self, sock, target_host, target_port, token):
        """
        Envoie une requête CONNECT avec l'authentification NTLM
        
        Args:
            sock (socket): Socket connecté au proxy
            target_host (str): Hôte de destination
            target_port (int): Port de destination
            token (str): Token d'authentification NTLM
        """
        connect_request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Authorization: NTLM {token}\r\n"
            f"Proxy-Connection: Keep-Alive\r\n"
            f"Connection: Keep-Alive\r\n"
            f"\r\n"
        )
        sock.sendall(connect_request.encode('utf-8'))

    def _recv_response(self, sock):
        """
        Reçoit une réponse HTTP du proxy
        
        Args:
            sock (socket): Socket connecté au proxy
            
        Returns:
            bytes: Réponse du proxy
        """
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            data = sock.recv(4096)
            if not data:
                break
            buffer += data
        return buffer

    def _parse_ntlm_challenge(self, response):
        """
        Extrait le challenge NTLM de la réponse du proxy
        
        Args:
            response (bytes): Réponse du proxy
            
        Returns:
            str: Token de challenge NTLM
            
        Raises:
            Exception: Si le challenge NTLM n'est pas trouvé
        """
        headers = response.decode(errors='ignore').split('\r\n')
        for header in headers:
            if header.lower().startswith('proxy-authenticate:'):
                header_value = header[len('proxy-authenticate:'):].strip()
                if header_value.startswith('NTLM'):
                    return header_value[len('NTLM'):].strip()
        raise Exception("Challenge NTLM non trouvé dans la réponse du proxy")


# Adaptations des classes de connexion pour l'intégration NTLM
class PatchedHTTPSConnection(HTTPSConnection):
    """
    Connexion HTTPS patchée pour utiliser un socket SSL préconnecté
    
    Cette classe modifie HTTPSConnection pour utiliser un socket SSL
    déjà établi par le tunnel NTLM.
    """

    def __init__(self, host, ssl_sock, port=443, timeout=60):
        """
        Initialise la connexion patchée
        
        Args:
            host (str): Hôte de destination
            ssl_sock (socket): Socket SSL préconnecté
            port (int, optional): Port de destination
            timeout (int, optional): Timeout en secondes
        """
        super().__init__(host, port=port, timeout=timeout)
        self.sock = ssl_sock
        self._custom_connected = True

    def connect(self):
        """
        Méthode connect surchargée pour utiliser le socket préconnecté
        """
        if getattr(self, '_custom_connected', False):
            return
        super().connect()


class CustomHTTPSConnectionPool(HTTPSConnectionPool):
    """
    Pool de connexions HTTPS personnalisé pour gérer le tunnel NTLM
    
    Cette classe étend HTTPSConnectionPool pour créer des connexions
    à travers un tunnel NTLM.
    """

    def __init__(self, tunnel, host, port):
        """
        Initialise le pool de connexions
        
        Args:
            tunnel (NtlmProxyTunnel): Instance de NtlmProxyTunnel
            host (str): Hôte de destination
            port (int): Port de destination
        """
        self.tunnel = tunnel
        super().__init__(host=host, port=port)

    def _new_conn(self):
        """
        Crée une nouvelle connexion à travers le tunnel NTLM
        
        Returns:
            PatchedHTTPSConnection: Connexion HTTPS patchée
        """
        ssl_sock = self.tunnel.open_tunnel(self.host, self.port)
        return PatchedHTTPSConnection(self.host, ssl_sock, port=self.port)


class NtlmProxyAdapter(requests.adapters.BaseAdapter):
    """
    Adaptateur requests pour l'authentification NTLM avec les proxys
    
    Cette classe implémente un adaptateur requests personnalisé qui gère
    l'authentification NTLM pour les proxys d'entreprise.
    """

    def __init__(self, proxy_host, proxy_port, username, password, domain='', workstation='WORKSTATION', debug=False):
        """
        Initialise l'adaptateur NTLM
        
        Args:
            proxy_host (str): Hôte du proxy
            proxy_port (int): Port du proxy
            username (str): Nom d'utilisateur
            password (str): Mot de passe
            domain (str, optional): Domaine (optionnel)
            workstation (str, optional): Nom du poste de travail (optionnel)
            debug (bool, optional): Activer le mode débogage
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = SecurePassword(password)
        self.domain = domain
        self.workstation = workstation
        self.debug = debug

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """
        Envoie une requête via le tunnel NTLM
        
        Cette méthode établit un tunnel NTLM puis envoie la requête HTTP
        à travers ce tunnel. Elle gère également la lecture et le traitement
        de la réponse.
        
        Args:
            request (PreparedRequest): Requête requests à envoyer
            stream (bool, optional): Activer le streaming
            timeout (int, optional): Timeout en secondes
            verify (bool, optional): Vérifier le certificat SSL
            cert (str, optional): Certificat client
            proxies (dict, optional): Configurations de proxy (ignorées)
            
        Returns:
            requests.Response: Réponse à la requête
            
        Raises:
            Exception: Si une erreur survient lors de l'envoi de la requête
        """
        parsed_url = urlparse(request.url)
        hostname = parsed_url.hostname

        # Créer le tunnel NTLM
        tunnel = NtlmProxyTunnel(
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            username=self.username,
            password=self.password,
            domain=self.domain,
            workstation=self.workstation,
            debug=self.debug
        )

        # Créer le pool de connexions et obtenir une connexion
        pool = CustomHTTPSConnectionPool(tunnel=tunnel, host=hostname, port=443)
        conn = pool._new_conn()

        # Construire la requête HTTP
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query

        request_line = f"{request.method} {path} HTTP/1.1\r\n"
        headers = ''.join(f"{k}: {v}\r\n" for k, v in request.headers.items())
        full_request = (request_line +
                        f"Host: {hostname}\r\n" +
                        headers +
                        "\r\n").encode()

        if request.body:
            full_request += request.body if isinstance(request.body, bytes) else request.body.encode()

        # Envoyer la requête
        conn.sock.sendall(full_request)

        # Étape 1: Lire les headers
        response_buffer = b""
        while b"\r\n\r\n" not in response_buffer:
            chunk = conn.sock.recv(4096)
            if not chunk:
                raise Exception("Connexion fermée avant réception des headers")
            response_buffer += chunk

        header_data, _, remaining = response_buffer.partition(b"\r\n\r\n")

        # Parser les headers
        header_lines = header_data.decode(errors='ignore').split("\r\n")
        status_line = header_lines[0]
        headers = {}

        for line in header_lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.strip()] = value.strip()

        # Vérifier Content-Length si disponible
        content_length = None
        if "Content-Length" in headers:
            try:
                content_length = int(headers["Content-Length"])
            except ValueError:
                content_length = None

        # Étape 2: Lire le body
        body_data = remaining

        if content_length is not None:
            # Lire exactement le nombre d'octets spécifié
            while len(body_data) < content_length:
                chunk = conn.sock.recv(content_length - len(body_data))
                if not chunk:
                    break
                body_data += chunk
        else:
            # Pas de Content-Length: lire jusqu'à fermeture
            # Vérifier s'il s'agit d'un transfert chunked
            is_chunked = headers.get("Transfer-Encoding", "").lower() == "chunked"

            if is_chunked:
                # Gestion du transfert chunked
                decoded_body = b""
                chunk_data = body_data

                while True:
                    # Si pas de données chunk, lire plus
                    if not chunk_data:
                        chunk_data = conn.sock.recv(4096)
                        if not chunk_data:
                            break

                    # Trouver la taille du chunk
                    chunk_size_end = chunk_data.find(b"\r\n")
                    if chunk_size_end == -1:
                        # Taille incomplète, lire plus
                        more_data = conn.sock.recv(4096)
                        if not more_data:
                            break
                        chunk_data += more_data
                        continue

                    # Extraire la taille du chunk
                    try:
                        chunk_size_hex = chunk_data[:chunk_size_end].decode('ascii').strip()
                        chunk_size = int(chunk_size_hex, 16)
                    except (ValueError, UnicodeDecodeError):
                        # Format invalide
                        break

                    # Si taille zéro, fin du body
                    if chunk_size == 0:
                        break

                    # Calculer où le chunk se termine
                    chunk_end = chunk_size_end + 2 + chunk_size + 2

                    # Si le chunk n'est pas complet, lire plus
                    while len(chunk_data) < chunk_end:
                        more_data = conn.sock.recv(4096)
                        if not more_data:
                            break
                        chunk_data += more_data

                    # Extraire le chunk et ajouter au body
                    chunk_content = chunk_data[chunk_size_end + 2:chunk_size_end + 2 + chunk_size]
                    decoded_body += chunk_content

                    # Passer au chunk suivant
                    chunk_data = chunk_data[chunk_end:]

                body_data = decoded_body
            else:
                # Transfert standard, lire jusqu'à fermeture
                while True:
                    chunk = conn.sock.recv(4096)
                    if not chunk:
                        break
                    body_data += chunk

        # Étape 3: Créer la réponse Requests
        http_version, status_code, *reason_parts = status_line.split(' ', 2)
        reason = ' '.join(reason_parts) if reason_parts else ""

        response = requests.Response()
        response.status_code = int(status_code)
        response.reason = reason
        response.headers = headers
        response._content = body_data
        response.url = request.url
        response.request = request
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)

        # Vérifiez si le contenu est compressé avec gzip
        if 'Content-Encoding' in headers and headers['Content-Encoding'] == 'gzip':
            # Utilisez un BytesIO pour décompresser le contenu gzip
            with gzip.GzipFile(fileobj=io.BytesIO(body_data)) as gzip_file:
                decompressed_data = gzip_file.read()
            response._content = decompressed_data
        else:
            response._content = body_data
        return response

    def close(self):
        """Ferme l'adaptateur et ses ressources associées"""
        pass


class NtlmProxyDict:
    """
    Classe pour encapsuler une session NTLM comme un dictionnaire de proxy
    
    Cette classe permet d'utiliser une session NTLM comme un dictionnaire
    de proxy standard, compatible avec les API requests
    """
    
    def __init__(self, ntlm_session):
        """
        Initialise un dictionnaire de proxy NTLM
        
        Args:
            ntlm_session (requests.Session): Session NTLM à encapsuler
        """
        self.ntlm_session = ntlm_session

    def __getitem__(self, key):
        """
        Retourne la session NTLM pour http ou https
        
        Args:
            key (str): Protocole ('http' ou 'https')
            
        Returns:
            requests.Session: Session NTLM
            
        Raises:
            KeyError: Si le protocole n'est pas supporté
        """
        # Retourner la session NTLM pour http ou https
        if key in ('http', 'https'):
            return self.ntlm_session
        # Lever une erreur pour les clés non supportées
        raise KeyError(f"Proxy key '{key}' not found.")

    def __setitem__(self, key, value):
        """
        Ne pas autoriser la modification des proxies
        
        Raises:
            NotImplementedError: Toujours levée car non supporté
        """
        # Ne pas autoriser la modification des proxies
        raise NotImplementedError("Modification of proxy settings is not allowed.")

    def get(self, key, default=None):
        """
        Gérer l'appel pour un proxy
        
        Args:
            key (str): Protocole ('http' ou 'https')
            default: Valeur par défaut si non trouvé
            
        Returns:
            requests.Session: Session NTLM ou default
        """
        # Gérer l'appel pour un proxy
        return self.__getitem__(key) if key in ('http', 'https') else default

    def keys(self):
        """
        Retourne les clés supportées
        
        Returns:
            list: Liste des protocoles supportés
        """
        # Retourne les clés supportées
        return ['http', 'https']

    def __contains__(self, key):
        """
        Permet de vérifier si une clé est dans le dictionnaire
        
        Args:
            key (str): Protocole à vérifier
            
        Returns:
            bool: True si le protocole est supporté
        """
        # Permet de vérifier si une clé est dans le dictionnaire
        return key in ('http', 'https')
