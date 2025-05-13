"""
Module principal d'IziProxy pour la gestion intelligente des proxys
"""

import os
import logging
import requests
from urllib.parse import urlparse

from .logger import get_logger
from .env_detector import EnvironmentDetector
from .config_manager import ConfigManager
from .proxy_detector import ProxyDetector
from .secure_config import SecurePassword, SecureProxyConfig

# Configuration du logger
logger = get_logger("iziproxy", level=logging.WARNING)

# Vérifier la disponibilité du support NTLM
try:
    from .ntlm_auth import NtlmProxyManager, is_ntlm_auth_available
    NTLM_SUPPORT = is_ntlm_auth_available()
except ImportError:
    NTLM_SUPPORT = False
    logger.debug("Support NTLM non disponible")


class IziProxy:
    """
    Gestion intelligente des proxys avec détection automatique 
    de l'environnement et des configurations
    
    Cette classe est le point d'entrée principal d'IziProxy et permet de:
    - Détecter automatiquement l'environnement d'exécution
    - Trouver et configurer le proxy approprié
    - Gérer l'authentification (basique ou NTLM)
    - Créer des sessions requests préconfigurées
    - Obtenir des dictionnaires de proxy utilisables
    """

    def __init__(self, config_path=None, proxy_url=None, pac_url=None,
                 environment=None, username=None, password=None, domain=None,
                 debug=False):
        """
        Initialise IziProxy avec les options spécifiées
        
        Args:
            config_path (str, optional): Chemin vers un fichier de configuration YAML
            proxy_url (str, optional): URL du proxy à utiliser (prioritaire)
            pac_url (str, optional): URL du fichier PAC à utiliser
            environment (str, optional): Forcer un environnement ('local', 'dev', 'prod')
            username (str, optional): Nom d'utilisateur pour l'authentification
            password (str, optional): Mot de passe pour l'authentification
            domain (str, optional): Domaine pour l'authentification NTLM
            debug (bool, optional): Activer le mode débogage
        """
        # Configuration du logger
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug("Mode débogage activé")

        # Stockage des paramètres fournis
        self.proxy_url_override = proxy_url
        self.pac_url_override = pac_url
        self.env_override = environment
        self.username_override = username
        self.password_override = password
        self.domain_override = domain

        # Chargement de la configuration
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()

        # Initialisation des sous-systèmes
        self.env_detector = EnvironmentDetector(self.config)
        self.proxy_detector = ProxyDetector(self.config.get("system_proxy", {}))

        # Détection de l'environnement
        if self.env_override:
            self.current_env = self.env_override
            logger.info(f"Environnement forcé: {self.current_env}")
        else:
            self.current_env = self.env_detector.detect_environment()

        # Variables d'état
        self._proxy_config = None
        self._ntlm_session = None
        self._proxy_url = None

        logger.debug(f"IziProxy initialisé (environnement: {self.current_env})")

    def get_proxy_config(self, url=None, force_refresh=False):
        """
        Obtient la configuration de proxy appropriée
        
        Args:
            url (str, optional): URL cible pour laquelle obtenir la configuration
            force_refresh (bool, optional): Forcer le rafraîchissement du cache
            
        Returns:
            SecureProxyConfig: Configuration de proxy à utiliser
        """
        # Utiliser le cache si disponible et non forcé
        if self._proxy_config is not None and not force_refresh:
            return self._proxy_config

        # Obtenir la configuration selon l'environnement
        proxy_url = self._determine_proxy_url()
        self._proxy_url = proxy_url  # Stocker pour référence future

        if proxy_url:
            # Utiliser l'URL explicite avec authentification si nécessaire
            logger.debug(f"Utilisation du proxy explicite: {proxy_url}")
            proxy_dict = self._create_proxy_dict(proxy_url)
            self._proxy_config = SecureProxyConfig(proxy_dict)
        else:
            # Sinon, détecter automatiquement
            logger.debug("Détection automatique du proxy système")

            # Si PAC URL est spécifié, l'utiliser pour la détection
            if self.pac_url_override:
                logger.debug(f"Utilisation du PAC spécifié: {self.pac_url_override}")

                # Utiliser le proxy_detector existant et définir l'URL PAC
                self.proxy_detector._pac_url = self.pac_url_override

                # Utiliser la méthode de détection PAC existante
                pac_proxy_dict = self.proxy_detector._detect_pac_file(url)

                if pac_proxy_dict:
                    logger.debug(f"Proxy détecté via PAC: {pac_proxy_dict}")
                    self._proxy_config = SecureProxyConfig(pac_proxy_dict)
                    return self._proxy_config

            # Détecter le proxy système
            proxy_dict = self.proxy_detector.detect_system_proxy(url)

            if proxy_dict:
                logger.debug(f"Proxy système détecté: {proxy_dict}")
                self._proxy_config = SecureProxyConfig(proxy_dict)
            else:
                logger.debug("Aucun proxy détecté, connexion directe")
                self._proxy_config = SecureProxyConfig({})

        return self._proxy_config

    def get_proxy_dict(self, url=None, force_refresh=False):
        """
        Obtient un dictionnaire de proxy utilisable avec requests
        
        Args:
            url (str, optional): URL cible pour laquelle obtenir la configuration
            force_refresh (bool, optional): Forcer le rafraîchissement du cache
            
        Returns:
            dict: Dictionnaire de proxy {'http': '...', 'https': '...'}
        """
        config = self.get_proxy_config(url, force_refresh)
        return config.get_real_config()

    def get_proxy_host(self):
        """
        Récupère le nom d'hôte du proxy actuellement configuré

        Returns:
            str: Nom d'hôte du proxy ou None si aucun proxy n'est configuré
        """
        # S'assurer que la configuration est à jour
        self.get_proxy_config()

        if not self._proxy_url:
            return None

        parsed = urlparse(self._proxy_url)
        return parsed.hostname

    def get_proxy_port(self):
        """
        Récupère le port du proxy actuellement configuré

        Returns:
            int: Port du proxy ou None si aucun proxy n'est configuré
        """
        # S'assurer que la configuration est à jour
        config = self.get_proxy_config()

        if not self._proxy_url:
            return None

        parsed = urlparse(self._proxy_url)
        # Retourner le port spécifié ou le port par défaut selon le schéma
        if parsed.port:
            return parsed.port
        elif parsed.scheme == 'https':
            return 443
        else:
            return 80  # http par défaut

    def configure_session(self, session):
        """
        Configure une session requests avec le proxy approprié
        
        Args:
            session (requests.Session): Session requests à configurer
            
        Returns:
            requests.Session: Session configurée
        """
        # Vérifier si l'authentification NTLM est requise
        if self._is_ntlm_required():
            if not NTLM_SUPPORT:
                logger.warning("Authentification NTLM requise mais non disponible")
                logger.warning("Installer: pip install iziproxy[ntlm]")
                # Essayer de configurer normalement
                session.proxies = self.get_proxy_dict()
            else:
                # Configurer une session NTLM
                self._configure_ntlm_session(session)
        else:
            # Configuration standard
            proxy_config = self.get_proxy_config()
            session.proxies = proxy_config.get_real_config()

            # Ajouter l'authentification basique si nécessaire
            self._add_basic_auth_if_needed(session)

        # Désactiver la confiance dans les variables d'environnement
        # pour éviter des interférences
        session.trust_env = False

        return session

    def create_session(self):
        """
        Crée une nouvelle session requests configurée avec le proxy approprié
        
        Returns:
            requests.Session: Nouvelle session configurée
        """
        session = requests.Session()
        return self.configure_session(session)

    def set_environment_variables(self):
        """
        Configure les variables d'environnement avec les paramètres de proxy
        
        Cette méthode est utile pour les applications qui n'utilisent pas requests
        mais respectent les variables d'environnement standard.
        
        Returns:
            dict: Les variables d'environnement définies
        """
        proxy_dict = self.get_proxy_dict()
        env_vars = {}
        
        # Définir les variables d'environnement standard
        if 'http' in proxy_dict and proxy_dict['http']:
            os.environ['HTTP_PROXY'] = proxy_dict['http']
            os.environ['http_proxy'] = proxy_dict['http']
            env_vars['HTTP_PROXY'] = proxy_dict['http']
            env_vars['http_proxy'] = proxy_dict['http']
            
        if 'https' in proxy_dict and proxy_dict['https']:
            os.environ['HTTPS_PROXY'] = proxy_dict['https']
            os.environ['https_proxy'] = proxy_dict['https']
            env_vars['HTTPS_PROXY'] = proxy_dict['https']
            env_vars['https_proxy'] = proxy_dict['https']
            
        if 'no_proxy' in proxy_dict and proxy_dict['no_proxy']:
            os.environ['NO_PROXY'] = proxy_dict['no_proxy']
            os.environ['no_proxy'] = proxy_dict['no_proxy']
            env_vars['NO_PROXY'] = proxy_dict['no_proxy']
            env_vars['no_proxy'] = proxy_dict['no_proxy']
            
        logger.debug(f"Variables d'environnement proxy définies: {env_vars}")
        return env_vars
        
    def clear_environment_variables(self):
        """
        Supprime les variables d'environnement de proxy définies précédemment
        """
        for var in ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy']:
            if var in os.environ:
                del os.environ[var]
                
        logger.debug("Variables d'environnement proxy supprimées")

    def get_current_environment(self):
        """
        Retourne l'environnement actuellement détecté
        
        Returns:
            str: Environnement ('local', 'dev', 'prod')
        """
        return self.current_env

    def get_credentials(self):
        """
        Retourne les identifiants de proxy actuels (sécurisés)
        
        Returns:
            tuple: (username, password, domain)
        """
        return self._get_credentials()

    def refresh(self):
        """
        Force le rafraîchissement de toutes les détections et caches
        
        Returns:
            IziProxy: Instance actuelle pour chaînage
        """
        # Rafraîchir l'environnement détecté
        if not self.env_override:
            self.current_env = self.env_detector.detect_environment(force_refresh=True)
            
        # Vider les caches
        self._proxy_config = None
        self.proxy_detector.clear_cache()
        
        # Redétecter la configuration
        self.get_proxy_config(force_refresh=True)
        
        logger.debug("Rafraîchissement terminé")
        return self

    def _determine_proxy_url(self):
        """
        Détermine l'URL du proxy à utiliser en fonction des priorités
        
        Returns:
            str: URL du proxy ou None
        """
        # 1. URL de proxy explicite (la plus prioritaire)
        if self.proxy_url_override:
            return self.proxy_url_override

        # 2. URL de proxy dans la configuration d'environnement
        env_config = self.config_manager.get_environment_config(self.current_env)
        if env_config and "proxy_url" in env_config and env_config["proxy_url"]:
            return env_config["proxy_url"]

        # 3. Pas d'URL explicite, utiliser la détection automatique
        return None

    def _create_proxy_dict(self, proxy_url):
        """
        Crée un dictionnaire de proxy à partir d'une URL
        
        Args:
            proxy_url (str): URL du proxy
            
        Returns:
            dict: Dictionnaire de proxy {'http': '...', 'https': '...'}
        """
        # Vérifier si l'authentification est requise
        requires_auth = self._requires_authentication()

        # Si authentification requise et pas déjà dans l'URL
        if requires_auth and '@' not in proxy_url:
            username, password, _ = self._get_credentials()

            if username and password:
                # Ajouter l'authentification à l'URL
                parsed = urlparse(proxy_url)
                auth_url = f"{parsed.scheme}://{username}:{SecurePassword(password)}@{parsed.netloc}{parsed.path or ''}"
                logger.debug(f"URL de proxy avec authentification: {auth_url}")
                proxy_url = auth_url

        # Créer le dictionnaire
        return {
            'http': proxy_url,
            'https': proxy_url
        }

    def _requires_authentication(self):
        """
        Vérifie si l'environnement actuel nécessite une authentification
        
        Returns:
            bool: True si l'authentification est requise
        """
        env_config = self.config_manager.get_environment_config(self.current_env)
        return env_config.get("requires_auth", False)

    def _is_ntlm_required(self):
        """
        Vérifie si l'authentification NTLM est requise
        
        Returns:
            bool: True si l'authentification NTLM est requise
        """
        env_config = self.config_manager.get_environment_config(self.current_env)
        return env_config.get("auth_type", "").lower() == "ntlm"

    def _get_credentials(self):
        """
        Obtient les identifiants pour l'authentification proxy
        
        Returns:
            tuple: (username, password, domain)
        """
        # Vérifier si des identifiants ont été fournis explicitement
        if self.username_override:
            password = self.password_override or ""
            if not isinstance(password, SecurePassword) and password:
                password = SecurePassword(password)
            domain = self.domain_override or ""
            return self.username_override, password, domain

        # Sinon, utiliser le gestionnaire de configuration
        return self.config_manager.get_credentials(self.current_env, "iziproxy")

    def _add_basic_auth_if_needed(self, session):
        """
        Ajoute l'authentification basique à une session si nécessaire
        
        Args:
            session (requests.Session): Session requests à configurer
        """
        if not self._requires_authentication():
            return

        # Ne pas ajouter si déjà dans l'URL de proxy
        proxy_config = session.proxies
        if any('@' in url for url in proxy_config.values() if url):
            return

        # Obtenir les identifiants
        username, password, _ = self._get_credentials()

        if username and password:
            from requests.auth import HTTPProxyAuth
            if isinstance(password, SecurePassword):
                password = password.get_password()
            session.auth = HTTPProxyAuth(username, password)

    def _configure_ntlm_session(self, session):
        """
        Configure une session avec l'authentification NTLM
        
        Args:
            session (requests.Session): Session requests à configurer
        """
        if not NTLM_SUPPORT:
            logger.error("Support NTLM non disponible")
            return

        # Obtenir les informations du proxy
        proxy_url = self._determine_proxy_url()
        if not proxy_url:
            # Essayer de détecter automatiquement
            proxy_config = self.proxy_detector.detect_system_proxy()
            http_proxy = proxy_config.get('http', '')
            if http_proxy:
                proxy_url = http_proxy

        if not proxy_url:
            logger.error("Impossible de déterminer l'URL du proxy pour NTLM")
            return

        # Parser l'URL
        parsed = urlparse(proxy_url)
        proxy_host = parsed.hostname
        proxy_port = parsed.port or 8080

        # Obtenir les identifiants
        username, password, domain = self._get_credentials()

        if not username:
            logger.error("Nom d'utilisateur manquant pour l'authentification NTLM")
            return

        # Si le mot de passe est un SecurePassword, récupérer sa valeur réelle
        if isinstance(password, SecurePassword):
            password_str = password.get_password()
        else:
            password_str = password or ""

        # Créer le gestionnaire NTLM
        try:
            ntlm_manager = NtlmProxyManager()

            # Créer une nouvelle session NTLM
            ntlm_session = ntlm_manager.create_ntlm_proxy_session(
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                username=username,
                password=password_str,
                domain=domain or '',
                debug=logger.level <= logging.DEBUG
            )

            # Copier les attributs importants vers la session fournie
            session.mount('https://', ntlm_session.adapters['https://'])
            session.mount('http://', ntlm_session.adapters['http://'])
            session.proxies = {}
            session.trust_env = False

            logger.debug(f"Session NTLM configurée pour {username}@{proxy_host}:{proxy_port}")

            # Stocker la session NTLM pour référence
            self._ntlm_session = ntlm_session

        except Exception as e:
            logger.error(f"Erreur lors de la configuration NTLM: {e}")
            # Fallback à la configuration standard
            session.proxies = self.get_proxy_dict()

    def set_debug(self, enabled=True):
        """
        Active ou désactive le mode débogage
        
        Args:
            enabled (bool): True pour activer le débogage, False pour le désactiver
            
        Returns:
            IziProxy: Instance actuelle pour chaînage
        """
        if enabled:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.WARNING)

        logger.debug(f"Mode débogage {'activé' if enabled else 'désactivé'}")
        return self
        
    def patch_requests(self):
        """
        Remplace les méthodes du module requests par celles de la session préconfigurée
        
        Cette méthode effectue un "monkey patching" du module requests
        pour que toutes les requêtes utilisent automatiquement la configuration proxy.
        
        Utile pour les applications existantes ou les bibliothèques tierces
        qui utilisent requests.get(), requests.post(), etc. directement.
        
        Returns:
            IziProxy: Instance actuelle pour chaînage
        """
        import requests
        
        # Créer une session préconfigurée si nécessaire
        if not hasattr(self, '_patched_session'):
            self._patched_session = self.create_session()
        
        # Remplacer les méthodes du module requests
        requests.get = self._patched_session.get
        requests.post = self._patched_session.post
        requests.put = self._patched_session.put
        requests.delete = self._patched_session.delete
        requests.head = self._patched_session.head
        requests.options = self._patched_session.options
        requests.patch = self._patched_session.patch
        
        logger.info("Module requests patché avec la configuration proxy")
        return self
        
    def unpatch_requests(self):
        """
        Restaure les méthodes originales du module requests
        
        Returns:
            IziProxy: Instance actuelle pour chaînage
        """
        import requests
        import requests.api
        
        # Restaurer les méthodes originales
        requests.get = requests.api.get
        requests.post = requests.api.post
        requests.put = requests.api.put
        requests.delete = requests.api.delete
        requests.head = requests.api.head
        requests.options = requests.api.options
        requests.patch = requests.api.patch
        
        logger.info("Module requests restauré à son état original")
        return self
