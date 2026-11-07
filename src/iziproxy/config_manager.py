"""
Chargement de la configuration d'IziProxy et recherche des identifiants.
"""

import copy
import getpass
import logging
import os
import platform
import socket
from pathlib import Path

import keyring
import keyring.errors
import yaml

from .password_manager import PasswordManager
from .secure_config import SecurePassword

logger = logging.getLogger("iziproxy")

DEFAULT_CONFIG = {
    "environments": {
        "local": {"proxy_url": None, "requires_auth": None},
        "dev": {"proxy_url": None, "requires_auth": None},
        "prod": {"proxy_url": None, "requires_auth": None},
    },
    # Les motifs par défaut sont dans EnvironmentDetector ; la configuration les complète
    "environment_detection": {
        "method": "auto",
        "hostname_patterns": {},
        "hostname_regex": {},
        "ip_ranges": {},
    },
    "system_proxy": {
        "use_system_proxy": True,
        "detect_env_vars": True,
        "detect_pac": True,
    },
    "credentials": {
        "prompt": True,
    },
}

# Variables d'environnement (ou du fichier .env) lues pour les identifiants
CREDENTIAL_ENV_VARS = {
    "username": "IZIPROXY_USERNAME",
    "password": "IZIPROXY_PASSWORD",
    "domain": "IZIPROXY_DOMAIN",
}

# Clés du nom d'utilisateur et du domaine dans le trousseau
USERNAME_KEY = "__username__"
DOMAIN_KEY = "__domain__"


class ConfigManager:
    """
    Gère la configuration d'IziProxy.

    - Charge un fichier YAML (chemin explicite ou emplacements standards)
    - Fusionne avec les valeurs par défaut
    - Recherche les identifiants : variables d'environnement, fichier .env,
      trousseau système (keyring), session courante, saisie interactive
    """

    DEFAULT_CONFIG_PATHS = [
        "./iziproxy.yml",
        "./iziproxy.yaml",
        "~/.config/iziproxy.yml",
        "~/.config/iziproxy.yaml",
        "~/.iziproxy.yml",
        "~/.iziproxy.yaml",
    ]

    DOTENV_PATHS = ["./.env", "~/.config/.env", "~/.env"]

    def __init__(self, config_path=None):
        """
        Args:
            config_path (str, optional): Fichier de configuration YAML
        """
        self.config_path = config_path
        self.loaded_from = None
        self.config = {}
        self._password_manager = None
        self._load_config()

    @property
    def password_manager(self):
        """Gestionnaire de saisie, créé à la demande."""
        if self._password_manager is None:
            self._password_manager = PasswordManager(logger)
        return self._password_manager

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #
    def _load_config(self):
        """Charge le premier fichier trouvé, sinon la configuration par défaut."""
        candidates = []
        if self.config_path:
            path = Path(self.config_path).expanduser()
            if path.exists():
                candidates.append(path)
            else:
                logger.warning("Configuration file not found: %s", self.config_path)
        candidates += [Path(p).expanduser() for p in self.DEFAULT_CONFIG_PATHS]

        for path in candidates:
            if path.is_file():
                self.config = self._load_yaml_config(path)
                return

        logger.debug("No configuration file found, using defaults")
        self.config = self._get_default_config()

    def _load_yaml_config(self, path):
        """
        Lit un fichier YAML et le fusionne avec la configuration par défaut.

        Returns:
            dict: Configuration complète
        """
        config = self._get_default_config()
        try:
            with open(path, "r", encoding="utf-8") as file:
                loaded = yaml.safe_load(file)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Cannot load configuration %s: %s", path, exc)
            return config

        if loaded is None:
            logger.warning("Empty configuration file: %s", path)
            return config
        if not isinstance(loaded, dict):
            logger.error("Invalid configuration %s: expected a mapping", path)
            return config

        self._deep_merge(config, loaded)
        self.loaded_from = str(path)
        logger.info("Configuration loaded from %s", path)
        self._warn_if_untrusted(path, loaded)
        return config

    def _warn_if_untrusted(self, path, loaded):
        """
        Signale un fichier du répertoire courant qui choisit le proxy.

        Un dépôt cloné peut contenir un iziproxy.yml : s'il désigne un proxy,
        un PAC ou désactive la vérification TLS, tout le trafic (et
        l'authentification NTLM / Basic) partirait vers ce proxy.
        """
        if self.config_path and Path(path) == Path(self.config_path).expanduser():
            # Fichier désigné explicitement par l'application (un config_path
            # introuvable, lui, se rabat sur les emplacements standards)
            return
        try:
            in_cwd = Path(path).resolve().parent == Path.cwd().resolve()
        except OSError:
            return
        if not in_cwd:
            return
        sensitive = sorted(self._sensitive_keys(loaded))
        if sensitive:
            logger.warning(
                "Configuration %s from the current directory sets %s: make sure you trust this "
                "directory, or move the file to ~/.config/iziproxy.yml or pass config_path=",
                path, ", ".join(sensitive))

    @staticmethod
    def _sensitive_keys(loaded):
        """Clés qui décident où part le trafic ou comment il est vérifié."""
        found = set()
        if "verify" in loaded:
            found.add("verify")
        environments = loaded.get("environments")
        if not isinstance(environments, dict):
            environments = {}
        sources = [loaded] + [env for env in environments.values() if isinstance(env, dict)]
        for source in sources:
            found.update(key for key in ("proxy_url", "pac_url", "auth_proxies") if source.get(key))
        return found

    def _deep_merge(self, target, source):
        """Fusionne récursivement source dans target."""
        for key, value in source.items():
            if isinstance(target.get(key), dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    @staticmethod
    def _get_default_config():
        """Retourne une copie de la configuration par défaut."""
        return copy.deepcopy(DEFAULT_CONFIG)

    def get_config(self):
        """Retourne la configuration complète."""
        return self.config

    def get_environment_config(self, env_type):
        """
        Retourne la configuration d'un environnement.

        Returns:
            dict: Configuration ({} si inconnu)
        """
        envs = self.config.get("environments")
        env = envs.get(env_type) if isinstance(envs, dict) else None
        return env if isinstance(env, dict) else {}

    # ------------------------------------------------------------------ #
    # Sources d'identifiants
    # ------------------------------------------------------------------ #
    def _load_dotenv(self):
        """
        Lit les fichiers .env dans l'ordre de DOTENV_PATHS.

        Chaque variable est prise dans le premier fichier qui la définit : le
        .env d'un projet sans variables IZIPROXY_* ne masque donc pas ~/.env.

        Returns:
            dict: Variables lues
        """
        values = {}
        for path in self.DOTENV_PATHS:
            expanded = os.path.expanduser(path)
            if not os.path.isfile(expanded):
                continue
            try:
                with open(expanded, "r", encoding="utf-8") as file:
                    for line in file:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        if line.startswith("export "):
                            line = line[len("export "):]
                        key, value = line.split("=", 1)
                        value = value.strip()
                        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                            value = value[1:-1]
                        values.setdefault(key.strip(), value)
            except (OSError, UnicodeDecodeError) as exc:
                logger.debug("Cannot read %s: %s", expanded, exc)
                continue
            logger.debug("Variables loaded from %s", expanded)
        return values

    def _get_credentials_from_env_vars(self, username, password, domain):
        """
        Complète les identifiants depuis l'environnement puis le fichier .env.

        Returns:
            tuple: (username, password, domain)
        """
        dotenv = self._load_dotenv()
        found = {"username": username, "password": password, "domain": domain}
        for field, name in CREDENTIAL_ENV_VARS.items():
            if found[field]:
                continue
            value = os.environ.get(name) or dotenv.get(name)
            if value:
                found[field] = value
                logger.debug("Proxy %s read from %s", field, name)
        return found["username"], found["password"], found["domain"]

    @staticmethod
    def _keyring_service(service_name, env_type, auth_type):
        return f"{service_name}_{env_type}-{auth_type}"

    def _get_credentials_from_keyring(self, username, password, domain, keyring_service):
        """
        Complète les identifiants depuis le trousseau système.

        Returns:
            tuple: (username, password, domain)
        """
        try:
            if not username:
                username = keyring.get_password(keyring_service, USERNAME_KEY)
            if username and not password:
                password = keyring.get_password(keyring_service, username)
            if not domain:
                domain = keyring.get_password(keyring_service, DOMAIN_KEY)
        except Exception as exc:
            logger.debug("Keyring unavailable: %s", exc)
        return username, password, domain

    def _get_current_session_info(self):
        """
        Utilisateur et domaine de la session courante.

        Returns:
            tuple: (username, domain)
        """
        try:
            # getpass lit déjà LOGNAME, USER, LNAME et USERNAME
            username = getpass.getuser()
        except Exception:
            username = None

        domain = None
        if platform.system() == "Windows":
            if username and "\\" in username:
                domain, username = username.split("\\", 1)
            else:
                domain = os.environ.get("USERDOMAIN")
                computer = os.environ.get("COMPUTERNAME")
                # Un « domaine » égal au nom du poste est un groupe de travail
                if domain and computer and domain.upper() == computer.upper():
                    domain = None
        else:
            try:
                fqdn = socket.getfqdn()
                if "." in fqdn:
                    domain = fqdn.split(".", 1)[1]
            except OSError:
                pass

        logger.debug("Session info - user: %s, domain: %s", username, domain)
        return username, domain

    def _get_credentials_from_session(self, username, password, domain, keyring_service, auth_type):
        """
        Complète l'utilisateur (et le domaine pour NTLM) depuis la session,
        puis cherche le mot de passe correspondant dans le trousseau.

        Returns:
            tuple: (username, password, domain)
        """
        ntlm = (auth_type or "").lower() == "ntlm"
        if not username or (ntlm and not domain):
            session_user, session_domain = self._get_current_session_info()
            username = username or session_user
            if ntlm and not domain:
                domain = session_domain

        if username and not password:
            try:
                password = keyring.get_password(keyring_service, username)
            except Exception as exc:
                logger.debug("Keyring unavailable: %s", exc)
        return username, password, domain

    def _get_credentials_interactively(self, username, password, domain, keyring_service,
                                       auth_type="basic"):
        """
        Demande les identifiants (fenêtre graphique ou console) et les
        enregistre dans le trousseau.

        Returns:
            tuple: (username, password, domain)
        """
        try:
            result = self.password_manager.get_credentials_interactive(
                existing_username=username,
                existing_domain=domain,
                auth_type=auth_type,
                title="IziProxy - Proxy authentication",
            )
        except Exception as exc:
            logger.warning("Interactive credential prompt failed: %s", exc)
            return username, password, domain

        if not result or not result[0] or not result[1]:
            logger.info("Credential prompt cancelled")
            return username, password, domain

        username, password, domain = result
        self._store_credentials_in_keyring(username, password, domain, keyring_service)
        return username, password, domain

    def _store_credentials_in_keyring(self, username, password, domain, keyring_service):
        """Enregistre les identifiants dans le trousseau système."""
        if not username or not password:
            return
        try:
            keyring.set_password(keyring_service, username, password)
            keyring.set_password(keyring_service, USERNAME_KEY, username)
            if domain:
                keyring.set_password(keyring_service, DOMAIN_KEY, domain)
            logger.debug("Credentials stored in keyring for %s", username)
        except Exception as exc:
            logger.debug("Cannot store credentials in keyring: %s", exc)

    def delete_credentials(self, env_type, auth_type=None, service_name="iziproxy"):
        """
        Supprime les identifiants enregistrés pour un environnement.

        Args:
            env_type (str): Environnement
            auth_type (str): Type d'authentification (celui de la configuration par défaut)
        """
        auth_type = (auth_type or self.get_environment_config(env_type).get("auth_type") or "basic").lower()
        service = self._keyring_service(service_name, env_type, auth_type)
        try:
            username = keyring.get_password(service, USERNAME_KEY)
            for key in filter(None, (username, USERNAME_KEY, DOMAIN_KEY)):
                try:
                    keyring.delete_password(service, key)
                except keyring.errors.PasswordDeleteError:
                    pass
            logger.info("Stored credentials removed for %s", service)
        except Exception as exc:
            logger.debug("Cannot remove credentials from keyring: %s", exc)

    # ------------------------------------------------------------------ #
    # Point d'entrée
    # ------------------------------------------------------------------ #
    def get_credentials(self, env_type, service_name="iziproxy", auth_required=None,
                        auth_type=None, prompt=True):
        """
        Recherche les identifiants du proxy.

        Ordre : variables d'environnement / .env, trousseau, session
        courante, puis saisie interactive (si prompt).

        Args:
            env_type (str): Environnement
            service_name (str): Préfixe des entrées du trousseau
            auth_required (bool): Forcer la recherche (None : valeur de requires_auth)
            auth_type (str): 'basic' ou 'ntlm' (None : valeur de la configuration)
            prompt (bool): Autoriser la saisie interactive

        Returns:
            tuple: (username, SecurePassword|None, domain)
        """
        env_config = self.get_environment_config(env_type)
        if auth_required is None:
            auth_required = bool(env_config.get("requires_auth"))
        if not auth_required:
            return None, None, None

        auth_type = (auth_type or env_config.get("auth_type") or "basic").lower()
        service = self._keyring_service(service_name, env_type, auth_type)

        def result(user, pwd, dom):
            return user, (SecurePassword(pwd) if pwd else None), dom

        username, password, domain = self._get_credentials_from_env_vars(None, None, None)
        if username and password:
            return result(username, password, domain)

        username, password, domain = self._get_credentials_from_keyring(
            username, password, domain, service)
        if username and password:
            return result(username, password, domain)

        username, password, domain = self._get_credentials_from_session(
            username, password, domain, service, auth_type)
        if username and password:
            return result(username, password, domain)

        if prompt:
            username, password, domain = self._get_credentials_interactively(
                username, password, domain, service, auth_type)

        return result(username, password, domain)
