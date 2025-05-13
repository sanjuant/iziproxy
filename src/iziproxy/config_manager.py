"""
Module de gestion de la configuration d'IziProxy
"""

import os
import yaml
import logging
import keyring
import getpass
import socket
import platform
sys_platform = platform.system().lower()
from pathlib import Path
import re

from .secure_config import SecurePassword

# Configuration du logger
logger = logging.getLogger("iziproxy")


class ConfigManager:
    """
    Gère la configuration d'IziProxy depuis différentes sources
    
    Cette classe permet de:
    - Charger la configuration depuis un fichier YAML
    - Rechercher automatiquement les fichiers de configuration
    - Gérer les valeurs par défaut
    - Sécuriser les identifiants avec keyring
    """

    DEFAULT_CONFIG_PATHS = [
        "./iziproxy.yml",
        "./iziproxy.yaml",
        "~/.config/iziproxy.yml",
        "~/.config/iziproxy.yaml",
        "~/.iziproxy.yml",
        "~/.iziproxy.yaml",
    ]

    def __init__(self, config_path=None):
        """
        Initialise le gestionnaire de configuration
        
        Args:
            config_path (str, optional): Chemin vers un fichier de configuration
        """
        self.config_path = config_path
        self.config = {}
        self._load_config()

    def _load_config(self):
        """
        Charge la configuration depuis un fichier YAML ou utilise la configuration par défaut
        """
        if self.config_path:
            # Utilisation du fichier spécifié
            config_path = Path(self.config_path).expanduser().resolve()
            if config_path.exists():
                self._load_yaml_config(str(config_path))
                return
            else:
                logger.warning(f"Fichier de configuration spécifié introuvable: {self.config_path}")

        # Recherche dans les emplacements par défaut
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                self._load_yaml_config(expanded_path)
                return

        # Pas de configuration trouvée, utiliser les valeurs par défaut
        logger.debug("Aucun fichier de configuration trouvé, utilisation des valeurs par défaut")
        self.config = self._get_default_config()

    def _get_current_session_info(self):
        """
        Détecte les informations de la session en cours (nom d'utilisateur et domaine)
        
        Returns:
            tuple: (username, domain)
        """
        username = None
        domain = None
        
        # Détection du nom d'utilisateur
        try:
            # Essayer d'obtenir le nom d'utilisateur via getpass (multi-plateforme)
            username = getpass.getuser()
        except Exception as e:
            logger.debug(f"Erreur lors de la détection du nom d'utilisateur: {e}")
            # Alternative via les variables d'environnement
            if sys_platform == 'windows':
                username = os.environ.get('USERNAME')
            else:
                username = os.environ.get('USER')
        
        # Détection du domaine (spécifique à Windows pour le domaine AD)
        if sys_platform == 'windows':
            # Récupérer le domaine Windows
            domain = os.environ.get('USERDOMAIN')
            
            # Si le domaine est le même que le nom de la machine, il ne s'agit pas d'un domaine AD
            computer_name = os.environ.get('COMPUTERNAME')
            if domain and computer_name and domain.upper() == computer_name.upper():
                # Ce n'est pas un domaine AD mais un groupe de travail
                domain = None
                
            # Alternative: extraire le domaine du nom d'utilisateur au format domain\username
            if not domain and username and '\\' in username:
                domain, username = username.split('\\', 1)
        else:
            # Pour Unix/Linux/Mac, essayer de récupérer le domaine DNS
            try:
                fqdn = socket.getfqdn()
                if '.' in fqdn:
                    # Extraire le domaine du FQDN (apres le premier point)
                    domain = fqdn.split('.', 1)[1]
            except Exception as e:
                logger.debug(f"Erreur lors de la détection du domaine: {e}")
        
        logger.debug(f"Informations de session détectées - Utilisateur: {username}, Domaine: {domain}")
        return username, domain

    def _load_yaml_config(self, path):
        """
        Charge la configuration depuis un fichier YAML
        
        Args:
            path (str): Chemin vers le fichier de configuration
        """
        try:
            with open(path, 'r', encoding='utf-8') as file:
                loaded_config = yaml.safe_load(file)
                if loaded_config:
                    logger.info(f"Configuration chargée depuis {path}")
                    # Fusionner avec les valeurs par défaut pour assurer la complétude
                    default_config = self._get_default_config()
                    self._deep_merge(default_config, loaded_config)
                    self.config = default_config
                else:
                    logger.warning(f"Fichier de configuration vide: {path}")
                    self.config = self._get_default_config()
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            self.config = self._get_default_config()

    def _deep_merge(self, target, source):
        """
        Fusionne récursivement deux dictionnaires
        
        Args:
            target (dict): Dictionnaire cible (sera modifié)
            source (dict): Dictionnaire source
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def _get_default_config(self):
        """
        Retourne la configuration par défaut
        
        Returns:
            dict: Configuration par défaut
        """
        return {
            "environments": {
                "local": {
                    "proxy_url": None,
                    "requires_auth": False
                },
                "dev": {
                    "proxy_url": None,
                    "requires_auth": False
                },
                "prod": {
                    "proxy_url": None,
                    "requires_auth": False
                }
            },
            "environment_detection": {
                "method": "auto",
                "hostname_patterns": {
                    "local": ["local", "laptop", "desktop", "dev-pc"],
                    "dev": ["dev", "staging", "test", "preprod"],
                    "prod": ["prod", "production"]
                },
                "hostname_regex": {
                    "local": ["^laptop-\\w+$", "^pc-\\w+$", "^desktop-\\w+$"],
                    "dev": ["^dev\\d*-", "^staging\\d*-", "^test\\d*-"],
                    "prod": ["^prod\\d*-", "^production\\d*-"]
                },
                "ip_ranges": {}
            },
            "credentials": {
                # Les identifiants doivent être définis via variables d'environnement ou .env
                # L'authentification est gérée par keyring et la saisie interactive si nécessaire
            },
            "system_proxy": {
                "use_system_proxy": True,
                "detect_pac": True
            }
        }

    def get_config(self):
        """
        Retourne la configuration complète
        
        Returns:
            dict: Configuration complète
        """
        return self.config

    def get_environment_config(self, env_type):
        """
        Retourne la configuration spécifique à un environnement
        
        Args:
            env_type (str): Type d'environnement ('local', 'dev', 'prod')
            
        Returns:
            dict: Configuration de l'environnement
        """
        if "environments" in self.config and env_type in self.config["environments"]:
            return self.config["environments"][env_type]
        return {}

    def _get_credentials_from_config(self, cred_config, domain):
        """
        Récupère les identifiants depuis la configuration YAML
        Cette méthode est conservée pour compatibilité mais ne fait plus rien
        car les identifiants doivent être stockés dans des variables d'environnement ou .env
        
        Args:
            cred_config (dict): Configuration des identifiants
            domain (str): Domaine actuel
            
        Returns:
            tuple: (username, password, domain)
        """
        # Les identifiants ne doivent plus être stockés dans la config YAML
        # Cette méthode est conservée pour compatibilité
        return None, None, domain
        
    def _load_dotenv(self):
        """
        Charge les variables d'environnement depuis un fichier .env

        Returns:
            dict: Variables d'environnement chargées
        """
        env_vars = {}
        env_paths = [
            "./.env",
            "~/.config/.env",
            "~/.env",
        ]

        for path in env_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if '=' in line:
                                    key, value = line.split('=', 1)
                                    env_vars[key.strip()] = value.strip().strip('"\'')
                    logger.debug(f"Variables d'environnement chargées depuis {expanded_path}")
                    break
                except Exception as e:
                    logger.debug(f"Erreur lors du chargement du fichier .env: {e}")

        return env_vars
        
    def _get_credentials_from_env_vars(self, username, password, domain):
        """
        Récupère les identifiants depuis les variables d'environnement et le fichier .env
        
        Args:
            username (str): Nom d'utilisateur actuel ou None
            password (str): Mot de passe actuel ou None
            domain (str): Domaine actuel ou None
            
        Returns:
            tuple: (username, password, domain)
        """
        # Charger les variables depuis le fichier .env
        env_vars = self._load_dotenv()
        
        # Liste des noms de variables à vérifier (en majuscules et minuscules)
        var_names = {
            'username': [
                "IZI_USERNAME", "izi_username",  # Nouvelles variables avec préfixe IZI
                "PROXY_USERNAME", "proxy_username"  # Variables originales pour rétrocompatibilité
            ],
            'password': [
                "IZI_PASSWORD", "izi_password",  # Nouvelles variables avec préfixe IZI
                "PROXY_PASSWORD", "proxy_password"  # Variables originales pour rétrocompatibilité
            ],
            'domain': [
                "IZI_DOMAIN", "izi_domain",  # Nouvelles variables avec préfixe IZI
                "PROXY_DOMAIN", "proxy_domain"  # Variables originales pour rétrocompatibilité
            ]
        }
        
        # Récupérer le nom d'utilisateur s'il n'est pas déjà défini
        if not username:
            for var_name in var_names['username']:
                if var_name in os.environ:
                    username = os.environ[var_name]
                    logger.debug(f"Nom d'utilisateur trouvé dans la variable d'environnement {var_name}")
                    break
                elif var_name in env_vars:
                    username = env_vars[var_name]
                    logger.debug(f"Nom d'utilisateur trouvé dans le fichier .env ({var_name})")
                    break
        
        # Récupérer le mot de passe s'il n'est pas déjà défini
        if not password:
            for var_name in var_names['password']:
                if var_name in os.environ:
                    password = os.environ[var_name]
                    logger.debug(f"Mot de passe trouvé dans la variable d'environnement {var_name}")
                    break
                elif var_name in env_vars:
                    password = env_vars[var_name]
                    logger.debug(f"Mot de passe trouvé dans le fichier .env ({var_name})")
                    break
        
        # Récupérer le domaine s'il n'est pas déjà défini
        if not domain:
            for var_name in var_names['domain']:
                if var_name in os.environ:
                    domain = os.environ[var_name]
                    logger.debug(f"Domaine trouvé dans la variable d'environnement {var_name}")
                    break
                elif var_name in env_vars:
                    domain = env_vars[var_name]
                    logger.debug(f"Domaine trouvé dans le fichier .env ({var_name})")
                    break

        if username and password:
            logger.debug(f"Identifiants trouvés dans les variables d'environnement ou le fichier .env")
            
        return username, password, domain
        
    def _get_credentials_from_keyring(self, username, password, domain, keyring_service, username_key, service_name):
        """
        Récupère les identifiants depuis le keyring
        
        Args:
            username (str): Nom d'utilisateur actuel ou None
            password (str): Mot de passe actuel ou None
            domain (str): Domaine actuel ou None
            keyring_service (str): Nom du service keyring pour le mot de passe
            username_key (str): Clé pour stocker le nom d'utilisateur
            service_name (str): Nom du service
            
        Returns:
            tuple: (username, password, domain)
        """
            
        # Essayer de récupérer le nom d'utilisateur depuis keyring
        if not username:
            try:
                username = keyring.get_password(service_name, username_key)
                if username:
                    logger.debug(f"Nom d'utilisateur récupéré depuis keyring: {username}")
            except Exception as e:
                logger.debug(f"Erreur lors de la récupération du nom d'utilisateur depuis keyring: {e}")

        # Essayer de récupérer le mot de passe depuis keyring
        if username and not password:
            try:
                stored_password = keyring.get_password(keyring_service, username)
                if stored_password:
                    password = stored_password
                    logger.debug(f"Mot de passe récupéré depuis keyring pour {username}")
            except Exception as e:
                logger.debug(f"Erreur lors de la récupération du mot de passe depuis keyring: {e}")
                
        return username, password, domain
        
    def _get_credentials_from_session(self, username, password, domain, keyring_service, auth_type):
        """
        Récupère les identifiants depuis la session en cours
        
        Args:
            username (str): Nom d'utilisateur actuel ou None
            password (str): Mot de passe actuel ou None
            domain (str): Domaine actuel ou None
            keyring_service (str): Nom du service keyring pour le mot de passe
            auth_type (str): Type d'authentification (basic, ntlm)
            
        Returns:
            tuple: (username, password, domain)
        """
        if not username or (not domain and auth_type.lower() == "ntlm"):
            session_username, session_domain = self._get_current_session_info()
            
            # Utiliser le nom d'utilisateur de la session si non défini ailleurs
            if not username and session_username:
                username = session_username
                logger.debug(f"Nom d'utilisateur récupéré depuis la session en cours: {username}")
            
            # Utiliser le domaine de la session si non défini ailleurs et si NTLM est requis
            if not domain and session_domain and auth_type.lower() == "ntlm":
                domain = session_domain
                logger.debug(f"Domaine récupéré depuis la session en cours: {domain}")

        # Vérifier si un mot de passe existe dans keyring pour le nom d'utilisateur de la session
        if username and not password:
            try:
                stored_password = keyring.get_password(keyring_service, username)
                if stored_password:
                    password = stored_password
                    logger.debug(f"Mot de passe récupéré depuis keyring pour {username} (utilisateur de session)")
            except Exception as e:
                logger.debug(f"Erreur lors de la récupération du mot de passe depuis keyring: {e}")
                
        return username, password, domain
        
    def _get_credentials_interactively(self, username, password, domain, keyring_service, username_key, 
                                        service_name, auth_type):
        """
        Demande les identifiants manquants interactivement
        
        Args:
            username (str): Nom d'utilisateur actuel ou None
            password (str): Mot de passe actuel ou None
            domain (str): Domaine actuel ou None
            keyring_service (str): Nom du service keyring pour le mot de passe
            username_key (str): Clé pour stocker le nom d'utilisateur
            service_name (str): Nom du service
            auth_type (str): Type d'authentification (basic, ntlm)
            
        Returns:
            tuple: (username, password, domain)
        """
            
        try:
            logger.info("Identifiants manquants, demande interactive")
            
            # Demander le nom d'utilisateur si manquant
            if not username:
                username = input("Nom d'utilisateur pour le proxy: ")

            # Demander le domaine si nécessaire pour NTLM
            if not domain and auth_type.lower() == "ntlm":
                domain = input("Domaine pour l'authentification NTLM (vide si aucun): ")

            # Demander le mot de passe si manquant
            if not password:
                password = getpass.getpass(f"Mot de passe pour {username}: ")

            # Stocker dans keyring
            self._store_credentials_in_keyring(username, password, domain, keyring_service, 
                                               username_key, service_name)
                
        except Exception as e:
            logger.warning(f"Erreur lors de la demande interactive d'identifiants: {e}")
            
        return username, password, domain
        
    def _store_credentials_in_keyring(self, username, password, domain, keyring_service, 
                                       username_key, service_name):
        """
        Stocke les identifiants dans le keyring
        
        Args:
            username (str): Nom d'utilisateur à stocker
            password (str): Mot de passe à stocker
            domain (str): Domaine (non stocké dans keyring)
            keyring_service (str): Nom du service keyring pour le mot de passe
            username_key (str): Clé pour stocker le nom d'utilisateur
            service_name (str): Nom du service
        """
        if not username or not password:
            return
            
        try:
            # Stocker le mot de passe
            keyring.set_password(keyring_service, username, password)
            
            # Stocker également le nom d'utilisateur
            keyring.set_password(service_name, username_key, username)
            
            logger.debug(f"Identifiants stockés dans keyring pour {username}")
        except Exception as e:
            logger.debug(f"Impossible de stocker les identifiants dans keyring: {e}")
            
    def get_credentials(self, env_type, service_name="iziproxy"):
        """
        Obtient les identifiants pour un environnement donné
        
        Args:
            env_type (str): Type d'environnement
            service_name (str, optional): Nom du service pour le stockage des identifiants
            
        Returns:
            tuple: (username, password, domain)
        """
        # Vérifier si l'authentification est requise
        env_config = self.get_environment_config(env_type)
        if not env_config.get("requires_auth", False):
            return None, None, None

        # Obtenir le type d'authentification
        auth_type = env_config.get("auth_type", "basic")
        
        # Initialiser le domaine
        domain = ""
        
        # Définir les noms des clés pour keyring
        keyring_service = f"{service_name}_{env_type}-{auth_type}"
        username_key = f"{service_name}_{env_type}-username"
        
        # Ordre de priorité pour les identifiants
        username, password, domain = self._get_credentials_from_config({}, domain)
        if username and password:
            return username, password, domain
            
        username, password, domain = self._get_credentials_from_env_vars(username, password, domain)
        if username and password:
            return username, password, domain
            
        username, password, domain = self._get_credentials_from_keyring(
            username, password, domain, 
            keyring_service, username_key, 
            service_name
        )
        if username and password:
            return username, password, domain
            
        username, password, domain = self._get_credentials_from_session(
            username, password, domain, 
            keyring_service,
            auth_type
        )
        if username and password:
            return username, password, domain
            
        # Demande interactive en dernier recours (toujours activée)
        username, password, domain = self._get_credentials_interactively(
            username, password, domain, 
            keyring_service, username_key, service_name,
            auth_type
        )
        
        # Sécuriser le mot de passe avant de le retourner
        if password and not isinstance(password, SecurePassword):
            password = SecurePassword(password)
            
        return username, password, domain
