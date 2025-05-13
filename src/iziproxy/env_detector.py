"""
Module de détection automatique de l'environnement d'exécution
"""

import os
import re
import socket
import logging
import platform

# Configuration du logger
logger = logging.getLogger("iziproxy")


class EnvironmentDetector:
    """
    Détecte automatiquement l'environnement d'exécution (local, dev, prod)
    
    Cette classe permet de:
    - Identifier l'environnement d'exécution actuel
    - Utiliser différentes méthodes de détection
    - Personnaliser les règles de détection
    """

    ENV_TYPES = ["local", "dev", "prod"]
    ENV_VAR_NAMES = ["ENVIRONMENT", "ENV", "APP_ENV", "ENVIRONMENT_TYPE", "PROXY_ENV", "IZIPROXY_ENV"]

    def __init__(self, config=None):
        """
        Initialise le détecteur d'environnement
        
        Args:
            config (dict, optional): Configuration avec des règles de détection personnalisées
        """
        self.config = config or {}
        self.detection_cache = None
        self.system_info = self._get_system_info()

    def detect_environment(self, force_refresh=False):
        """
        Détecte l'environnement actuel en utilisant différentes méthodes
        
        Args:
            force_refresh (bool): Force le rafraîchissement du cache
            
        Returns:
            str: Type d'environnement détecté ('local', 'dev', 'prod')
        """
        # Utiliser le cache si disponible et pas de rafraîchissement forcé
        if self.detection_cache and not force_refresh:
            return self.detection_cache

        # Déterminer la méthode de détection
        method = self._get_detection_method()

        detected_env = None

        # Appliquer les méthodes de détection dans l'ordre
        if method == "env_var" or method == "auto":
            detected_env = self._detect_by_env_var()

        if not detected_env and (method == "hostname" or method == "auto"):
            detected_env = self._detect_by_hostname()

        if not detected_env and (method == "ip" or method == "auto"):
            detected_env = self._detect_by_ip()

        if not detected_env and method == "ask":
            detected_env = self._ask_user()

        # Par défaut, considérer comme environnement local
        if not detected_env:
            logger.info("Environnement non détecté, utilisation de 'local' par défaut")
            detected_env = "local"

        # Mettre en cache le résultat
        self.detection_cache = detected_env

        logger.info(f"Environnement détecté: {detected_env}")
        return detected_env

    def _get_system_info(self):
        """
        Collecte les informations système pour faciliter la détection
        
        Returns:
            dict: Informations système
        """
        info = {
            "hostname": socket.gethostname().lower(),
            "os": platform.system().lower(),
            "ip": None,
        }
        
        # Tenter d'obtenir l'adresse IP locale
        try:
            info["ip"] = socket.gethostbyname(socket.gethostname())
        except:
            pass
            
        return info

    def _get_detection_method(self):
        """
        Détermine la méthode de détection à utiliser
        
        Returns:
            str: Méthode de détection ("auto", "env_var", "hostname", "ip", "ask")
        """
        if "environment_detection" in self.config:
            detection_config = self.config["environment_detection"]
            if "method" in detection_config:
                return detection_config["method"].lower()

        return "auto"

    def _detect_by_env_var(self):
        """
        Détecte l'environnement via les variables d'environnement
        
        Returns:
            str: Type d'environnement détecté ou None
        """
        # Vérifier d'abord la variable spécifique à IziProxy
        if "IZIPROXY_ENV" in os.environ:
            env_value = os.environ["IZIPROXY_ENV"].lower()
            if env_value in self.ENV_TYPES:
                logger.debug(f"Environnement détecté via IZIPROXY_ENV: {env_value}")
                return env_value
        
        # Vérifier les autres variables d'environnement
        for var_name in self.ENV_VAR_NAMES:
            if var_name in os.environ:
                env_value = os.environ[var_name].lower()

                # Correspondance directe avec un type d'environnement
                if env_value in self.ENV_TYPES:
                    logger.debug(f"Environnement détecté via variable {var_name}: {env_value}")
                    return env_value

                # Recherche partielle (ex: "production" -> "prod")
                for env_type in self.ENV_TYPES:
                    if env_type in env_value or env_value in env_type:
                        logger.debug(f"Correspondance partielle via {var_name}: {env_value} -> {env_type}")
                        return env_type

        return None

    def _detect_by_hostname(self):
        """
        Détecte l'environnement via le nom d'hôte de la machine
        
        Returns:
            str: Type d'environnement détecté ou None
        """
        hostname = self.system_info["hostname"]
        logger.debug(f"Détection par hostname: {hostname}")

        # Vérifier les motifs de nom d'hôte dans la configuration
        patterns = self._get_hostname_patterns()
        for env_type, host_patterns in patterns.items():
            for pattern in host_patterns:
                if pattern.lower() in hostname:
                    logger.debug(f"Environnement détecté via hostname pattern: {pattern} -> {env_type}")
                    return env_type

        # Vérifier les regex de nom d'hôte
        regex_patterns = self._get_hostname_regex()
        for env_type, regex_list in regex_patterns.items():
            for regex in regex_list:
                try:
                    if re.search(regex, hostname, re.IGNORECASE):
                        logger.debug(f"Environnement détecté via hostname regex: {regex} -> {env_type}")
                        return env_type
                except re.error:
                    logger.warning(f"Expression régulière invalide: {regex}")

        # Recherche basique par mots clés connus
        if any(word in hostname for word in ["prod", "production"]):
            return "prod"
        elif any(word in hostname for word in ["dev", "development", "staging", "test"]):
            return "dev"
        elif any(word in hostname for word in ["local", "laptop", "desktop", "pc-"]):
            return "local"

        return None

    def _detect_by_ip(self):
        """
        Détecte l'environnement via l'adresse IP
        
        Returns:
            str: Type d'environnement détecté ou None
        """
        # Récupérer les plages d'IP configurées
        ip_ranges = self._get_ip_ranges()
        if not ip_ranges:
            return None

        # Obtenir l'IP locale
        ip = self.system_info["ip"]
        if not ip:
            return None

        # Vérifier dans quelle plage se trouve l'IP
        for env_type, ip_range_list in ip_ranges.items():
            for ip_range in ip_range_list:
                try:
                    if self._ip_in_range(ip, ip_range):
                        logger.debug(f"Environnement détecté via IP range: {ip} in {ip_range} -> {env_type}")
                        return env_type
                except Exception as e:
                    logger.debug(f"Erreur lors de la vérification de la plage IP {ip_range}: {e}")

        return None

    def _ask_user(self):
        """
        Demande l'environnement à l'utilisateur
        
        Returns:
            str: Type d'environnement choisi
        """
        try:
            print("\nIziProxy ne peut pas détecter automatiquement l'environnement.")
            print("Veuillez sélectionner votre environnement:")
            print("1. Local (développement local)")
            print("2. Dev (environnement de développement/staging)")
            print("3. Prod (environnement de production)")

            choice = input("Votre choix (1/2/3): ")

            if choice == "1":
                return "local"
            elif choice == "2":
                return "dev"
            elif choice == "3":
                return "prod"
            else:
                print("Choix non valide, utilisation de 'local' par défaut")
                return "local"
        except:
            # En cas d'erreur (par exemple, exécution sans terminal), utiliser local
            return "local"

    def _get_hostname_patterns(self):
        """
        Récupère les motifs de nom d'hôte depuis la configuration
        
        Returns:
            dict: Motifs de nom d'hôte par type d'environnement
        """
        default_patterns = {
            "local": ["local", "laptop", "desktop", "dev-pc"],
            "dev": ["dev", "staging", "test", "preprod"],
            "prod": ["prod", "production"]
        }

        if "environment_detection" in self.config and "hostname_patterns" in self.config["environment_detection"]:
            configured = self.config["environment_detection"]["hostname_patterns"]
            # Fusionner avec les valeurs par défaut
            for env_type in self.ENV_TYPES:
                if env_type in configured:
                    default_patterns[env_type].extend(configured[env_type])

        return default_patterns

    def _get_hostname_regex(self):
        """
        Récupère les expressions régulières de nom d'hôte depuis la configuration
        
        Returns:
            dict: Regex de nom d'hôte par type d'environnement
        """
        default_regex = {
            "local": ["^laptop-\\w+$", "^pc-\\w+$", "^desktop-\\w+$"],
            "dev": ["^dev\\d*-", "^staging\\d*-", "^test\\d*-"],
            "prod": ["^prod\\d*-", "^production\\d*-"]
        }

        if "environment_detection" in self.config and "hostname_regex" in self.config["environment_detection"]:
            configured = self.config["environment_detection"]["hostname_regex"]
            # Fusionner avec les valeurs par défaut
            for env_type in self.ENV_TYPES:
                if env_type in configured:
                    default_regex[env_type].extend(configured[env_type])

        return default_regex

    def _get_ip_ranges(self):
        """
        Récupère les plages IP depuis la configuration
        
        Returns:
            dict: Plages IP par type d'environnement
        """
        if "environment_detection" in self.config and "ip_ranges" in self.config["environment_detection"]:
            return self.config["environment_detection"]["ip_ranges"]

        return {}

    @staticmethod
    def _ip_in_range(ip, ip_range):
        """
        Vérifie si une IP est dans une plage donnée (CIDR ou plage simple)
        
        Args:
            ip (str): Adresse IP à vérifier
            ip_range (str): Plage IP (format CIDR "192.168.1.0/24" ou plage "192.168.1.0-192.168.1.255")
            
        Returns:
            bool: True si l'IP est dans la plage
        """
        try:
            if "/" in ip_range:  # Format CIDR
                from ipaddress import ip_network, ip_address
                return ip_address(ip) in ip_network(ip_range, strict=False)
            elif "-" in ip_range:  # Format plage
                start, end = ip_range.split("-")
                return EnvironmentDetector._ip_to_int(start) <= EnvironmentDetector._ip_to_int(ip) <= EnvironmentDetector._ip_to_int(end)
        except Exception as e:
            logger.debug(f"Erreur lors de la vérification de plage IP: {e}")
            return False

        return False

    @staticmethod
    def _ip_to_int(ip):
        """
        Convertit une adresse IP en entier pour faciliter les comparaisons
        
        Args:
            ip (str): Adresse IP au format string
            
        Returns:
            int: Représentation entière de l'adresse IP
        """
        return sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(ip.split('.')))
