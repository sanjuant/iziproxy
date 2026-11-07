"""
Point d'entrée d'IziProxy : détection de l'environnement, choix du proxy,
authentification et intégration avec requests.
"""

import os
import threading
from urllib.parse import urlsplit

import requests

from .adapters import IziProxyAdapter
from .config_manager import ConfigManager
from .env_detector import EnvironmentDetector, normalize_environment
from .local_proxy import LocalProxy
from .logger import enable_debug_logging, disable_debug_logging, get_logger
from .proxy_detector import ProxyDetector
from .proxy_utils import (
    build_ssl_context,
    extract_credentials,
    has_credentials,
    inject_credentials,
    is_https_proxy,
    no_proxy_for_env,
    normalize_proxy_url,
    parse_no_proxy,
    probe_proxy_auth,
    should_bypass,
    strip_credentials,
)
from .secure_config import SecurePassword, SecureProxyConfig
from .ntlm_auth import NtlmProxyAdapter, can_use_current_user, is_ntlm_auth_available

logger = get_logger("iziproxy")

NTLM_SUPPORT = is_ntlm_auth_available()

# URL utilisée quand aucune cible n'est précisée (évaluation PAC, sonde)
DEFAULT_TARGET_URL = "https://www.example.com/"

_PROXY_ENV_VARS = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")

# Patch de requests actif (un seul à la fois pour tout le processus)
_PATCH_LOCK = threading.Lock()
_ACTIVE_PATCH = {"owner": None, "original_init": None}


class IziProxy:
    """
    Gestion intelligente des proxys d'entreprise.

    - Détecte l'environnement d'exécution (local, dev, prod)
    - Trouve le proxy : paramètre explicite, configuration, variables
      d'environnement, paramètres système ou fichier PAC
    - Respecte les exclusions (no_proxy, ProxyOverride Windows...)
    - Détecte si le proxy exige une authentification (Basic ou NTLM)
    - S'intègre à requests (session, dictionnaire, variables d'environnement,
      patch global)

    Exemple :
        >>> proxy = IziProxy()
        >>> session = proxy.create_session()
        >>> session.get("https://example.com")
    """

    def __init__(self, config_path=None, proxy_url=None, pac_url=None, environment=None,
                 username=None, password=None, domain=None, auth_type=None,
                 no_proxy=None, interactive=None, verify=None, debug=False):
        """
        Args:
            config_path (str): Fichier de configuration YAML
            proxy_url (str): Proxy à utiliser (prioritaire sur toute détection)
            pac_url (str): Fichier PAC à utiliser (URL ou chemin)
            environment (str): Forcer l'environnement ('local', 'dev', 'prod' ou
                un alias reconnu : 'production', 'staging'...)
            username (str): Nom d'utilisateur du proxy
            password (str): Mot de passe du proxy
            domain (str): Domaine NTLM
            auth_type (str): 'basic' ou 'ntlm' (détecté automatiquement sinon)
            no_proxy (str|list): Hôtes supplémentaires à contacter sans proxy
            interactive (bool): Autoriser la saisie des identifiants manquants
                (None : valeur de la configuration, vrai par défaut)
            verify (bool|str): Vérification des certificats du proxy https:// et
                du fichier PAC : True (autorités du système, défaut), False ou
                chemin vers un fichier / répertoire d'autorités (None : clé
                ``verify`` de la configuration). Les certificats des sites
                restent vérifiés par chaque client (``verify`` de requests...).
            debug (bool): Afficher les journaux détaillés
        """
        if debug:
            enable_debug_logging()

        self.proxy_url_override = normalize_proxy_url(proxy_url)
        self.pac_url_override = pac_url
        self.env_override = None
        if environment:
            self.env_override = normalize_environment(environment)
            if self.env_override is None:
                raise ValueError(f"Unknown environment {environment!r}: expected local, dev or prod")
        self.username_override = username
        self.password_override = password
        self.domain_override = domain
        self.auth_type_override = auth_type.lower() if auth_type else None
        self.no_proxy_override = no_proxy
        self.interactive = interactive

        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()
        self.verify = self._resolve_verify(verify)
        self.env_detector = EnvironmentDetector(self.config)
        self.proxy_detector = ProxyDetector(self.config.get("system_proxy", {}), verify=self.verify)

        self.current_env = self.env_override or self.env_detector.detect_environment()

        self._lock = threading.RLock()
        self._settings = None
        self._auth = None
        self._credentials = None
        self._pac_results = {}
        self._saved_env = None
        self._env_local_proxy = None
        self._shared_local_proxy = None
        self._local_proxies = []
        self._warned = set()

        logger.debug("IziProxy initialized (environment: %s)", self.current_env)

    def __repr__(self):
        return f"IziProxy(environment={self.current_env!r}, proxy={self.get_proxy_url()!r})"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.unpatch_requests()
        self.clear_environment_variables()
        self.stop_local_proxies()
        return False

    # ------------------------------------------------------------------ #
    # Résolution du proxy
    # ------------------------------------------------------------------ #
    def _resolve_verify(self, verify):
        """Valide l'option verify (paramètre, sinon configuration, sinon True)."""
        value = self.config.get("verify", True) if verify is None else verify
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip():
            return os.path.expanduser(value.strip())
        raise ValueError(f"Invalid verify value {value!r}: expected True, False or a CA bundle path")

    def _proxy_ssl_context(self):
        """Contexte TLS vers un proxy https:// (selon verify)."""
        return build_ssl_context(self.verify)

    def _env_config(self):
        return self.config_manager.get_environment_config(self.current_env) or {}

    def _warn_once(self, key, message, *args):
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    def _proxy_settings(self):
        """
        Détermine (une seule fois) la source du proxy.

        Returns:
            dict: source ('explicit', 'pac', 'system', 'direct'), http, https,
                  pac_url, no_proxy (liste)
        """
        with self._lock:
            if self._settings is not None:
                return self._settings

            env_config = self._env_config()
            no_proxy = parse_no_proxy(self.no_proxy_override)
            no_proxy += parse_no_proxy(env_config.get("no_proxy"))
            no_proxy += parse_no_proxy(self.config.get("no_proxy"))

            explicit = self.proxy_url_override or normalize_proxy_url(env_config.get("proxy_url"))
            pac_url = self.pac_url_override or env_config.get("pac_url")

            if explicit:
                settings = {"source": "explicit", "http": explicit, "https": explicit}
            elif pac_url:
                settings = {"source": "pac", "pac_url": pac_url}
            else:
                system = self.proxy_detector.detect_system_proxy()
                no_proxy += parse_no_proxy(system.get("no_proxy"))
                if system.get("http") or system.get("https"):
                    settings = {
                        "source": "system",
                        "http": system.get("http") or system.get("https"),
                        "https": system.get("https") or system.get("http"),
                    }
                elif system.get("pac_url"):
                    settings = {"source": "pac", "pac_url": system["pac_url"]}
                else:
                    settings = {"source": "direct"}

            # Supprimer les doublons en gardant l'ordre
            settings["no_proxy"] = list(dict.fromkeys(no_proxy))
            self._settings = settings
            logger.debug("Proxy source: %s", SecureProxyConfig._mask_passwords(
                {k: v for k, v in settings.items() if isinstance(v, str)}))
            return settings

    def _raw_proxies(self, url=None):
        """
        Proxys à utiliser pour une URL, sans identifiants ajoutés.

        Returns:
            dict: {'http': ..., 'https': ...} ou {} pour une connexion directe
        """
        settings = self._proxy_settings()
        if url and should_bypass(url, settings["no_proxy"]):
            return {}

        source = settings["source"]
        if source == "direct":
            return {}
        if source == "pac":
            proxy = self._pac_proxy(url or DEFAULT_TARGET_URL, settings["pac_url"])
            return {"http": proxy, "https": proxy} if proxy else {}
        return {"http": settings["http"], "https": settings["https"]}

    def _pac_proxy(self, url, pac_url):
        """Évalue le PAC pour une URL (cache par schéma + hôte + port)."""
        parts = urlsplit(url)
        key = (parts.scheme, parts.hostname, parts.port)
        with self._lock:
            if key not in self._pac_results:
                self._pac_results[key] = self.proxy_detector.find_proxy_for_url(url, pac_url)
            return self._pac_results[key]

    # ------------------------------------------------------------------ #
    # Authentification
    # ------------------------------------------------------------------ #
    def _auth_settings(self):
        """
        Détermine (une seule fois) si une authentification est nécessaire et
        laquelle.

        Ordre : paramètres du constructeur, configuration de l'environnement,
        puis sondage du proxy (réponse 407 et en-têtes Proxy-Authenticate).

        Returns:
            dict: {'required': bool, 'type': 'basic'|'ntlm'}
        """
        with self._lock:
            if self._auth is not None:
                return self._auth

            env_config = self._env_config()
            required = env_config.get("requires_auth")
            auth_type = self.auth_type_override or (env_config.get("auth_type") or "").lower() or None

            if required is None and (self.username_override or self.password_override):
                required = True

            proxies = self._raw_proxies()
            proxy = proxies.get("https") or proxies.get("http")

            if proxy and has_credentials(proxy):
                # Identifiants déjà présents dans l'URL du proxy
                required = True if required is None else required
                auth_type = auth_type or "basic"
            elif proxy and (required is None or (required and auth_type is None)):
                status, schemes = probe_proxy_auth(
                    proxy, ssl_context=self._proxy_ssl_context() if is_https_proxy(proxy) else None)
                logger.debug("Proxy probe %s -> status=%s schemes=%s",
                             strip_credentials(proxy), status, list(schemes))
                if required is None:
                    required = status == 407
                if required and auth_type is None:
                    auth_type = self._pick_auth_type(schemes)

            # Sans proxy, aucune authentification n'a de sens
            self._auth = {"required": bool(required) and bool(proxy), "type": auth_type or "basic"}
            logger.debug("Authentication settings: %s", self._auth)
            return self._auth

    @staticmethod
    def _pick_auth_type(schemes):
        """Choisit le type d'authentification parmi les schémas proposés."""
        windows_auth = "ntlm" in schemes or "negotiate" in schemes
        if windows_auth and (NTLM_SUPPORT or "basic" not in schemes):
            return "ntlm"
        return "basic"

    def _uses_ntlm(self):
        """Indique si l'adaptateur NTLM doit être utilisé."""
        auth = self._auth_settings()
        if not (auth["required"] and auth["type"] == "ntlm"):
            return False
        if not NTLM_SUPPORT:
            self._warn_once("ntlm", "The proxy requires NTLM but pyspnego is not installed: "
                                    "pip install iziproxy[ntlm]. Falling back to Basic authentication.")
            return False
        return True

    def _get_credentials(self):
        """
        Identifiants du proxy (mis en cache après la première recherche).

        Returns:
            tuple: (username, SecurePassword|None, domain)
        """
        with self._lock:
            if self._credentials is not None:
                return self._credentials

            proxies = self._raw_proxies()
            proxy = proxies.get("https") or proxies.get("http")
            auth_type = self._auth_settings()["type"]

            if self.username_override or self.password_override:
                username = self.username_override
                password = self.password_override
                domain = self.domain_override
            elif proxy and has_credentials(proxy):
                username, password = extract_credentials(proxy)
                domain = self.domain_override
            else:
                # Sous Windows, NTLM peut utiliser la session courante : ne pas demander
                sspi = auth_type == "ntlm" and NTLM_SUPPORT and can_use_current_user()
                prompt = self.interactive
                if prompt is None:
                    prompt = self.config.get("credentials", {}).get("prompt", True)
                username, password, domain = self.config_manager.get_credentials(
                    self.current_env,
                    auth_required=True,
                    auth_type=auth_type,
                    prompt=bool(prompt) and not sspi,
                )
                if sspi and not password:
                    logger.debug("No stored password: using the current Windows session for NTLM")
                    username, password = None, None
                domain = self.domain_override or domain

            if password is not None and not isinstance(password, SecurePassword):
                password = SecurePassword(password) if password != "" else None
            self._credentials = (username or None, password, domain or None)
            return self._credentials

    def _create_ntlm_adapter(self, **kwargs):
        """Crée l'adaptateur NTLM avec les identifiants courants."""
        username, password, domain = self._get_credentials()
        return NtlmProxyAdapter(resolver=self._raw_proxies, username=username,
                                password=password, domain=domain, proxy_verify=self.verify, **kwargs)

    def _resolve(self, url=None):
        """
        Proxys à utiliser pour une URL, identifiants Basic inclus.

        Returns:
            dict: {'http': ..., 'https': ...} ou {}
        """
        proxies = self._raw_proxies(url)
        if not proxies:
            return {}
        auth = self._auth_settings()
        if not auth["required"] or self._uses_ntlm():
            return proxies

        username, password, _ = self._get_credentials()
        if not username:
            self._warn_once("nocreds", "The proxy requires authentication but no credentials were found")
            return proxies
        secret = password.get_password() if password else None
        return {
            scheme: value if has_credentials(value) else inject_credentials(value, username, secret)
            for scheme, value in proxies.items()
        }

    # ------------------------------------------------------------------ #
    # API publique : informations
    # ------------------------------------------------------------------ #
    @property
    def environment(self):
        """Environnement courant ('local', 'dev', 'prod')."""
        return self.current_env

    def get_proxy_url(self, url=None):
        """
        URL du proxy (sans identifiants) utilisée pour une URL cible.

        Args:
            url (str): URL cible (https://www.example.com par défaut)

        Returns:
            str|None: URL du proxy, None pour une connexion directe
        """
        target = url or DEFAULT_TARGET_URL
        proxies = self._raw_proxies(target)
        scheme = urlsplit(target).scheme or "https"
        return strip_credentials(proxies.get(scheme) or proxies.get("https") or proxies.get("http"))

    def get_proxy_host(self, url=None):
        """Nom d'hôte du proxy, ou None."""
        proxy = self.get_proxy_url(url)
        return urlsplit(proxy).hostname if proxy else None

    def get_proxy_port(self, url=None):
        """Port du proxy (port par défaut du schéma si absent), ou None."""
        proxy = self.get_proxy_url(url)
        if not proxy:
            return None
        parts = urlsplit(proxy)
        return parts.port or (443 if parts.scheme == "https" else 80)

    def get_proxy_dict(self, url=None):
        """
        Dictionnaire de proxys utilisable avec requests (paramètre proxies=).

        Les identifiants Basic sont inclus dans les URLs. Un proxy NTLM ne
        peut pas être décrit par un dictionnaire : utilisez create_session().

        Args:
            url (str): URL cible (prise en compte des exclusions et du PAC)

        Returns:
            dict: {'http': ..., 'https': ..., 'no_proxy': ...} ou {}
        """
        proxies = self._resolve(url)
        no_proxy = self._proxy_settings()["no_proxy"]
        if proxies and no_proxy:
            proxies = dict(proxies, no_proxy=",".join(no_proxy))
        return proxies

    def get_proxy_config(self, url=None):
        """
        Version sécurisée de get_proxy_dict() (mots de passe masqués à l'affichage).

        Returns:
            SecureProxyConfig: Configuration ; get_real_config() donne les URLs réelles
        """
        return SecureProxyConfig(self.get_proxy_dict(url))

    @property
    def requires_auth(self):
        """True si le proxy exige une authentification."""
        return self._auth_settings()["required"]

    @property
    def auth_type(self):
        """Type d'authentification utilisé ('basic' ou 'ntlm')."""
        return self._auth_settings()["type"]

    def get_credentials(self):
        """
        Identifiants utilisés pour le proxy.

        Returns:
            tuple: (username, SecurePassword|None, domain) ; (None, None, None)
                   si aucune authentification n'est nécessaire
        """
        if not self._auth_settings()["required"]:
            return None, None, None
        return self._get_credentials()

    # ------------------------------------------------------------------ #
    # API publique : intégration
    # ------------------------------------------------------------------ #
    def configure_session(self, session):
        """
        Configure une session requests existante.

        Le proxy est choisi à chaque requête (exclusions, PAC) par un
        adaptateur dédié ; les réglages de nouvelles tentatives existants
        sont conservés.

        Args:
            session (requests.Session): Session à configurer

        Returns:
            requests.Session: La même session
        """
        current = session.get_adapter("https://")
        max_retries = getattr(current, "max_retries", 0)
        adapter = IziProxyAdapter(self, max_retries=max_retries)

        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.iziproxy = self
        return session

    def create_session(self):
        """
        Crée une session requests configurée.

        Returns:
            requests.Session: Nouvelle session
        """
        return self.configure_session(requests.Session())

    def start_local_proxy(self, port=0, timeout=30.0):
        """
        Démarre un proxy local (façon cntlm / px) sur 127.0.0.1.

        Les outils qui ne lisent que HTTP(S)_PROXY (pip, git, curl, conda...)
        peuvent alors traverser un proxy NTLM / Negotiate ou Basic sans
        connaître d'identifiants : le proxy local choisit la route de chaque
        URL comme create_session() (no_proxy, PAC, connexion directe) et
        s'authentifie à leur place.

        La détection de l'authentification et la recherche des identifiants
        (éventuelle saisie interactive) ont lieu ici, dans le thread appelant.

        Args:
            port (int): Port d'écoute (0 : port libre choisi par le système)
            timeout (float): Délai de connexion / lecture vers l'amont (secondes)

        Returns:
            LocalProxy: Proxy démarré (url, port, stop(), gestionnaire de contexte)
        """
        if self._raw_proxies() and self._auth_settings()["required"]:
            self._get_credentials()
        local = LocalProxy(self, port=port, timeout=timeout).start()
        with self._lock:
            self._local_proxies = [p for p in self._local_proxies if p.running]
            self._local_proxies.append(local)
        return local

    def stop_local_proxies(self):
        """Arrête tous les proxys locaux démarrés par cette instance."""
        with self._lock:
            proxies, self._local_proxies = self._local_proxies, []
            self._env_local_proxy = None
            self._shared_local_proxy = None
        for local in proxies:
            local.stop()

    # ------------------------------------------------------------------ #
    # API publique : autres clients HTTP
    # ------------------------------------------------------------------ #
    def local_proxy_url(self):
        """
        URL d'un proxy local partagé (démarré à la première demande, arrêté
        par stop_local_proxies() ou en sortie de bloc ``with``).

        Il sert aux clients qui ne savent pas parler NTLM ou évaluer un PAC :
        navigateurs, aiohttp, gRPC...

        Returns:
            str: URL du type http://127.0.0.1:port
        """
        with self._lock:
            local = self._shared_local_proxy
            if local is None or not local.running:
                local = self._shared_local_proxy = self.start_local_proxy()
            return local.url

    def proxy_for(self, url):
        """
        URL de proxy à donner à un client HTTP quelconque pour une URL cible.

        - connexion directe (exclusion, PAC « DIRECT », pas de proxy) : None
        - proxy sans authentification ou Basic : URL du proxy, identifiants
          inclus et encodés
        - proxy NTLM / Negotiate : URL du proxy local partagé, qui
          s'authentifie à la place du client

        Les schémas ws:// et wss:// sont traités comme http:// et https://.

        Args:
            url (str): URL cible

        Returns:
            str|None: URL du proxy
        """
        scheme, sep, rest = url.partition("://")
        scheme = {"ws": "http", "wss": "https"}.get(scheme.lower(), scheme.lower())
        target = f"{scheme}{sep}{rest}"
        if not self._raw_proxies(target):
            return None
        if self._uses_ntlm():
            return self.local_proxy_url()
        resolved = self._resolve(target)
        return resolved.get(scheme) or resolved.get("https") or resolved.get("http")

    def httpx_client(self, **kwargs):
        """
        Client httpx synchrone dont le transport choisit le proxy à chaque
        requête (voir iziproxy.integrations.httpx_transport).

        Les options de transport (verify, cert, http1, http2, limits,
        retries, local_address, socket_options) sont transmises au
        transport ; les autres au client httpx.

        Returns:
            httpx.Client: Client configuré
        """
        from .integrations.httpx_transport import build_client

        return build_client(self, asynchronous=False, **kwargs)

    def httpx_async_client(self, **kwargs):
        """
        Client httpx asynchrone (voir httpx_client()).

        Returns:
            httpx.AsyncClient: Client configuré
        """
        from .integrations.httpx_transport import build_client

        return build_client(self, asynchronous=True, **kwargs)

    def aiohttp_session(self, **kwargs):
        """
        Session aiohttp configurée (à créer dans une coroutine).

        aiohttp n'offre pas de point d'extension public pour choisir le proxy
        requête par requête : la session passe donc par le proxy local
        partagé, qui applique PAC, exclusions et authentification. Sans
        proxy, la session est directe.

        Returns:
            aiohttp.ClientSession: Session configurée
        """
        from .integrations.aiohttp_session import build_session

        return build_session(self, **kwargs)

    def urllib3_pool_manager(self, **kwargs):
        """
        PoolManager urllib3 qui choisit le proxy à chaque requête.

        Returns:
            iziproxy.integrations.urllib3_pool.IziPoolManager: Gestionnaire configuré
        """
        from .integrations.urllib3_pool import IziPoolManager

        return IziPoolManager(self, **kwargs)

    def urllib_opener(self, *handlers):
        """
        OpenerDirector urllib.request qui choisit le proxy à chaque requête.

        Args:
            *handlers: Handlers urllib supplémentaires (cookies, auth...)

        Returns:
            urllib.request.OpenerDirector: Opener configuré
        """
        from .integrations.urllib_handler import build_opener

        return build_opener(self, *handlers)

    def install_urllib_opener(self, *handlers):
        """
        Installe urllib_opener() comme opener global : urllib.request.urlopen()
        (y compris dans les bibliothèques tierces) passe alors par IziProxy.

        Returns:
            IziProxy: L'instance (chaînage)
        """
        import urllib.request

        urllib.request.install_opener(self.urllib_opener(*handlers))
        return self

    def http_connection(self, url, timeout=None, context=None):
        """
        Connexion http.client prête à l'emploi pour l'hôte d'une URL.

        Via un proxy, la connexion ouvre un tunnel CONNECT : les requêtes
        s'écrivent comme en direct (chemin relatif).

        Args:
            url (str): URL (ou origine) cible, ex. https://api.example.com
            timeout (float): Délai en secondes
            context (ssl.SSLContext): Contexte TLS pour une cible HTTPS

        Returns:
            http.client.HTTPConnection: Connexion (HTTPSConnection pour https)
        """
        from .integrations.http_client import connection_for

        return connection_for(self, url, timeout=timeout, context=context)

    def websocket_proxy(self, uri):
        """
        Valeur du paramètre ``proxy`` de websockets.connect() pour une URI
        ws:// ou wss:// (None : connexion directe).

        websockets ne décode pas les identifiants de l'URL du proxy (un mot
        de passe encodé serait envoyé tel quel) et ne reçoit pas l'option
        verify : avec un proxy authentifié ou https://, la connexion passe
        par le proxy local partagé.
        """
        proxy = self.proxy_for(uri)
        if proxy and (has_credentials(proxy) or is_https_proxy(proxy)):
            return self.local_proxy_url()
        return proxy

    def grpc_channel_options(self, target, secure=True):
        """
        Options de canal gRPC pour une cible « hôte:port ».

        Args:
            target (str): Cible gRPC (hôte:port, éventuellement dns:///hôte:port)
            secure (bool): Canal TLS (https) ou non (http)

        Returns:
            list: Options à passer à grpc.secure_channel() / insecure_channel()
        """
        from .integrations.tools import grpc_options

        return grpc_options(self, target, secure)

    def selenium_proxy(self):
        """
        Objet selenium.webdriver.common.proxy.Proxy pointant vers le proxy
        local partagé (ou connexion directe sans proxy).
        """
        from .integrations.tools import selenium_proxy

        return selenium_proxy(self)

    def playwright_proxy(self):
        """
        Paramètre ``proxy`` de Playwright (launch() ou new_context()), ou
        None sans proxy.
        """
        from .integrations.tools import playwright_proxy

        return playwright_proxy(self)

    def set_environment_variables(self, local_proxy=False):
        """
        Définit HTTP(S)_PROXY et NO_PROXY pour les outils qui les lisent
        (pip, git, curl, urllib...). Les valeurs précédentes sont mémorisées
        et restaurées par clear_environment_variables().

        Args:
            local_proxy (bool): Faire pointer les variables vers un proxy
                local (voir start_local_proxy()) qui gère NTLM, le PAC et les
                exclusions ; il est arrêté par clear_environment_variables()

        Returns:
            dict: Variables définies
        """
        if local_proxy:
            values = self._local_proxy_env()
        else:
            # Un proxy local démarré par un appel précédent n'a plus d'usage
            local, self._env_local_proxy = self._env_local_proxy, None
            if local is not None:
                local.stop()
            values = self._direct_env()

        if self._saved_env is None:
            self._saved_env = {name: os.environ.get(name) for name in _PROXY_ENV_VARS}
            self.proxy_detector.env_overrides = dict(self._saved_env)
        os.environ.update(values)
        logger.debug("Proxy environment variables set: %s", sorted(values))
        return values

    def _local_proxy_env(self):
        """Variables pointant vers le proxy local (démarré si nécessaire)."""
        local = self._env_local_proxy
        if local is None or not local.running:
            local = self._env_local_proxy = self.start_local_proxy()
        no_proxy = no_proxy_for_env(self._proxy_settings()["no_proxy"])
        return {
            "HTTP_PROXY": local.url, "http_proxy": local.url,
            "HTTPS_PROXY": local.url, "https_proxy": local.url,
            "NO_PROXY": no_proxy, "no_proxy": no_proxy,
        }

    def _direct_env(self):
        """Variables pointant directement vers le proxy d'entreprise."""
        if self._uses_ntlm():
            self._warn_once("ntlm-env", "Environment variables cannot carry NTLM authentication; "
                                        "use set_environment_variables(local_proxy=True)")
        if self._proxy_settings()["source"] == "pac":
            logger.debug("PAC configuration: environment variables use the proxy for %s", DEFAULT_TARGET_URL)

        proxies = self._resolve()
        values = {}
        if proxies.get("http"):
            values["HTTP_PROXY"] = values["http_proxy"] = proxies["http"]
        if proxies.get("https"):
            values["HTTPS_PROXY"] = values["https_proxy"] = proxies["https"]
        if proxies:
            values["NO_PROXY"] = values["no_proxy"] = no_proxy_for_env(self._proxy_settings()["no_proxy"])
        return values

    def clear_environment_variables(self):
        """
        Restaure les variables d'environnement d'avant set_environment_variables()
        et arrête le proxy local qu'elle avait démarré.
        """
        local, self._env_local_proxy = self._env_local_proxy, None
        if local is not None:
            local.stop()
        if self._saved_env is None:
            return
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._saved_env = None
        self.proxy_detector.env_overrides = {}
        logger.debug("Proxy environment variables restored")

    def patch_requests(self):
        """
        Configure automatiquement toutes les sessions requests créées ensuite,
        y compris celles de requests.get() et des bibliothèques tierces.

        Returns:
            IziProxy: L'instance (chaînage)
        """
        with _PATCH_LOCK:
            if _ACTIVE_PATCH["owner"] is self:
                return self
            if _ACTIVE_PATCH["owner"] is not None:
                _ACTIVE_PATCH["owner"].unpatch_requests()

            original_init = requests.Session.__init__
            izi = self
            state = threading.local()

            def patched_init(session, *args, **kwargs):
                original_init(session, *args, **kwargs)
                if getattr(state, "busy", False):
                    return
                state.busy = True
                try:
                    izi.configure_session(session)
                finally:
                    state.busy = False

            patched_init.__wrapped__ = original_init
            requests.Session.__init__ = patched_init
            _ACTIVE_PATCH.update(owner=self, original_init=original_init)
        logger.info("requests patched with the IziProxy configuration")
        return self

    def unpatch_requests(self):
        """
        Annule patch_requests().

        Returns:
            IziProxy: L'instance (chaînage)
        """
        with _PATCH_LOCK:
            if _ACTIVE_PATCH["owner"] is not self:
                return self
            requests.Session.__init__ = _ACTIVE_PATCH["original_init"]
            _ACTIVE_PATCH.update(owner=None, original_init=None)
        logger.info("requests restored")
        return self

    # ------------------------------------------------------------------ #
    # API publique : maintenance
    # ------------------------------------------------------------------ #
    def clear_auth_cache(self):
        """Oublie le type d'authentification détecté et les identifiants."""
        with self._lock:
            self._auth = None
            self._credentials = None

    def reset_credentials(self):
        """
        Supprime les identifiants enregistrés dans le trousseau pour
        l'environnement courant (utile après un changement de mot de passe).

        Returns:
            IziProxy: L'instance (chaînage)
        """
        self.config_manager.delete_credentials(self.current_env, auth_type=self.auth_type)
        self.clear_auth_cache()
        return self

    def refresh(self):
        """
        Relance toutes les détections (environnement, proxy, authentification).

        Returns:
            IziProxy: L'instance (chaînage)
        """
        with self._lock:
            if not self.env_override:
                self.current_env = self.env_detector.detect_environment(force_refresh=True)
            self.proxy_detector.clear_cache()
            self._settings = None
            self._pac_results.clear()
            self.clear_auth_cache()
        logger.debug("IziProxy refreshed")
        return self

    def set_debug(self, enabled=True):
        """
        Active ou désactive les journaux détaillés.

        Returns:
            IziProxy: L'instance (chaînage)
        """
        if enabled:
            enable_debug_logging()
        else:
            disable_debug_logging()
        return self
