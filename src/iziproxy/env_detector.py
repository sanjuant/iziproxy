"""
Détection de l'environnement d'exécution (local, dev, prod).
"""

import ipaddress
import logging
import os
import re
import socket
import sys

logger = logging.getLogger("iziproxy")

# Valeurs reconnues dans les variables d'environnement
ENV_ALIASES = {
    "local": "local", "localhost": "local", "workstation": "local", "laptop": "local",
    "dev": "dev", "develop": "dev", "development": "dev", "staging": "dev", "stage": "dev",
    "test": "dev", "testing": "dev", "qa": "dev", "uat": "dev", "preprod": "dev",
    "pre-prod": "dev", "recette": "dev", "int": "dev", "integration": "dev",
    "prod": "prod", "production": "prod", "prd": "prod", "live": "prod",
}


def normalize_environment(value):
    """
    Convertit une valeur libre ('Production', 'staging'...) en type d'environnement.

    Returns:
        str|None: 'local', 'dev', 'prod' ou None si non reconnu
    """
    if not value:
        return None
    return ENV_ALIASES.get(str(value).strip().lower())


class EnvironmentDetector:
    """
    Détecte l'environnement courant.

    Méthodes (configuration « environment_detection.method ») :
    - env_var : variables IZIPROXY_ENV, APP_ENV, ENVIRONMENT...
    - hostname : motifs et expressions régulières sur le nom d'hôte
    - ip : plages d'adresses IP
    - ask : question posée à l'utilisateur
    - auto : env_var, puis hostname, puis ip
    """

    ENV_TYPES = ["local", "dev", "prod"]
    # IZIPROXY_ENV est prioritaire ; ENV seul est ignoré (utilisé par sh pour un fichier)
    ENV_VAR_NAMES = ["IZIPROXY_ENV", "PROXY_ENV", "APP_ENV", "ENVIRONMENT", "ENVIRONMENT_TYPE",
                     "DEPLOY_ENV", "STAGE"]

    def __init__(self, config=None):
        """
        Args:
            config (dict): Configuration complète d'IziProxy
        """
        self.config = config or {}
        self.detection_cache = None
        self.system_info = self._get_system_info()

    @property
    def _detection_config(self):
        return self.config.get("environment_detection") or {}

    def detect_environment(self, force_refresh=False):
        """
        Returns:
            str: 'local', 'dev' ou 'prod' ('local' par défaut)
        """
        if self.detection_cache and not force_refresh:
            return self.detection_cache

        method = self._get_detection_method()
        detected = None
        if method in ("env_var", "auto"):
            detected = self._detect_by_env_var()
        if not detected and method in ("hostname", "auto"):
            detected = self._detect_by_hostname()
        if not detected and method in ("ip", "auto"):
            detected = self._detect_by_ip()
        if not detected and method == "ask":
            detected = self._ask_user()

        if not detected:
            logger.debug("Environment not detected, defaulting to 'local'")
            detected = "local"

        self.detection_cache = detected
        logger.info("Environment detected: %s", detected)
        return detected

    @staticmethod
    def _get_local_ip():
        """
        Adresse IP de l'interface utilisée pour sortir (aucun paquet n'est envoyé).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("10.255.255.255", 1))
                ip = sock.getsockname()[0]
                if not ip.startswith("0."):
                    return ip
        except OSError:
            pass
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None

    def _get_system_info(self):
        """Nom d'hôte et adresse IP locale."""
        return {"hostname": socket.gethostname().lower(), "ip": self._get_local_ip()}

    def _get_detection_method(self):
        method = self._detection_config.get("method") or "auto"
        return str(method).lower()

    def _detect_by_env_var(self):
        """Lit le type d'environnement dans les variables d'environnement."""
        names = list(self.ENV_VAR_NAMES)
        custom = self._detection_config.get("env_var_name")
        if custom:
            names.insert(0, custom)
        for name in names:
            value = os.environ.get(name)
            env = normalize_environment(value)
            if env:
                logger.debug("Environment detected from %s=%s", name, value)
                return env
        return None

    def _detect_by_hostname(self):
        """Compare le nom d'hôte aux motifs (sous-chaînes) puis aux regex."""
        hostname = self.system_info["hostname"]

        for env_type, patterns in self._get_hostname_patterns().items():
            for pattern in patterns:
                if pattern and str(pattern).lower() in hostname:
                    logger.debug("Environment detected from hostname pattern %r", pattern)
                    return env_type

        for env_type, expressions in self._get_hostname_regex().items():
            for expression in expressions:
                try:
                    if re.search(expression, hostname, re.IGNORECASE):
                        logger.debug("Environment detected from hostname regex %r", expression)
                        return env_type
                except re.error:
                    logger.warning("Invalid hostname regex: %s", expression)
        return None

    def _detect_by_ip(self):
        """Cherche l'adresse IP locale dans les plages configurées."""
        ip = self.system_info["ip"]
        if not ip:
            return None
        for env_type, ranges in self._get_ip_ranges().items():
            for ip_range in ranges or []:
                if self._ip_in_range(ip, ip_range):
                    logger.debug("Environment detected from IP %s in %s", ip, ip_range)
                    return env_type
        return None

    def _ask_user(self):
        """Pose la question en console (si un terminal est disponible)."""
        if not (sys.stdin and sys.stdin.isatty()):
            return None
        try:
            print("IziProxy could not detect the environment.", file=sys.stderr)
            print("  1. local\n  2. dev\n  3. prod", file=sys.stderr)
            choice = input("Your choice (1/2/3): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        return {"1": "local", "2": "dev", "3": "prod"}.get(choice) or normalize_environment(choice)

    def _merged(self, key, defaults):
        """Motifs par défaut complétés par ceux de la configuration."""
        merged = {env: list(values) for env, values in defaults.items()}
        configured = self._detection_config.get(key) or {}
        for env_type in self.ENV_TYPES:
            for value in configured.get(env_type) or []:
                if value not in merged[env_type]:
                    merged[env_type].append(value)
        return merged

    def _get_hostname_patterns(self):
        return self._merged("hostname_patterns", {
            "local": ["local", "laptop", "desktop", "dev-pc"],
            "dev": ["dev", "staging", "test", "preprod"],
            "prod": ["prod", "production"],
        })

    def _get_hostname_regex(self):
        return self._merged("hostname_regex", {
            "local": ["^laptop-\\w+$", "^pc-\\w+$", "^desktop-\\w+$"],
            "dev": ["^dev\\d*-", "^staging\\d*-", "^test\\d*-"],
            "prod": ["^prod\\d*-", "^production\\d*-"],
        })

    def _get_ip_ranges(self):
        return self._detection_config.get("ip_ranges") or {}

    @staticmethod
    def _ip_in_range(ip, ip_range):
        """
        Vérifie si une IP appartient à une plage CIDR ("10.0.0.0/8") ou
        début-fin ("10.0.0.1-10.0.0.50").
        """
        try:
            address = ipaddress.ip_address(ip)
            ip_range = str(ip_range).strip()
            if "-" in ip_range:
                start, end = (ipaddress.ip_address(p.strip()) for p in ip_range.split("-", 1))
                return start <= address <= end
            return address in ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return False
