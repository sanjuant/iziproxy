"""
Détection des proxys configurés sur le système et évaluation des fichiers PAC.
"""

import logging
import os
import platform
import re
import ssl
import subprocess
import urllib.request
from urllib.parse import urlsplit

from .proxy_utils import normalize_proxy_url, parse_no_proxy

logger = logging.getLogger("iziproxy")


def parse_pac_result(value):
    """
    Convertit le résultat de FindProxyForURL en URL de proxy.

    Exemples : "PROXY p:8080; DIRECT" -> "http://p:8080",
    "HTTPS p:443" -> "https://p:443", "SOCKS5 p:1080" -> "socks5h://p:1080",
    "DIRECT" -> None.

    Args:
        value (str): Résultat brut du PAC

    Returns:
        str|None: URL du premier proxy utilisable, None pour une connexion directe
    """
    if not value:
        return None
    schemes = {
        "proxy": "http",
        "http": "http",
        "https": "https",
        "socks": "socks4",
        "socks4": "socks4",
        "socks5": "socks5h",
    }
    for directive in str(value).split(";"):
        parts = directive.strip().split()
        if not parts:
            continue
        kind = parts[0].lower()
        if kind == "direct":
            return None
        if kind in schemes and len(parts) > 1:
            return f"{schemes[kind]}://{parts[1]}"
    return None


def _run(command):
    """Exécute une commande système et retourne sa sortie (ou None)."""
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None


class ProxyDetector:
    """
    Détecte les paramètres de proxy du système.

    Sources, par ordre de priorité :
    1. Variables d'environnement (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY)
    2. Paramètres du système (registre Windows, scutil macOS, GNOME/KDE)
    3. Fichier PAC déclaré par le système (évalué pour chaque URL)
    """

    def __init__(self, config=None):
        """
        Args:
            config (dict, optional): Section « system_proxy » de la configuration
                - use_system_proxy (bool): active la détection (défaut True)
                - detect_env_vars (bool): lit les variables d'environnement (défaut True)
                - detect_pac (bool): utilise les fichiers PAC (défaut True)
        """
        self.config = config or {}
        self.use_system_proxy = self.config.get("use_system_proxy", True)
        self.detect_env_vars = self.config.get("detect_env_vars", True)
        self.detect_pac = self.config.get("detect_pac", True)
        self._settings = None
        self._pac_cache = {}
        self._pac_warning_shown = False

    # ------------------------------------------------------------------ #
    # Paramètres statiques
    # ------------------------------------------------------------------ #
    def detect_system_proxy(self, force_refresh=False):
        """
        Retourne les paramètres de proxy du système.

        Returns:
            dict: Clés possibles 'http', 'https', 'no_proxy', 'pac_url'
        """
        if self._settings is not None and not force_refresh:
            return dict(self._settings)

        settings = {}
        if self.use_system_proxy:
            sources = []
            if self.detect_env_vars:
                sources.append(("environment", self._detect_env_vars))
            sources.append(("system", self._detect_system_settings))

            for name, method in sources:
                try:
                    found = method() or {}
                except Exception as exc:  # une source défaillante ne doit rien bloquer
                    logger.debug("Proxy detection via %s failed: %s", name, exc)
                    continue
                if found.get("http") or found.get("https"):
                    logger.debug("Proxy found via %s", name)
                    settings = found
                    break
                # Garder une URL PAC trouvée même sans proxy manuel
                if found.get("pac_url") and not settings.get("pac_url"):
                    settings["pac_url"] = found["pac_url"]
                if found.get("no_proxy") and not settings.get("no_proxy"):
                    settings["no_proxy"] = found["no_proxy"]

            if not self.detect_pac:
                settings.pop("pac_url", None)

        self._settings = settings
        logger.debug("System proxy settings: %s", settings or "none")
        return dict(settings)

    def _detect_env_vars(self):
        """Lit les variables d'environnement standard (minuscules prioritaires)."""
        def read(name):
            return os.environ.get(name.lower()) or os.environ.get(name.upper())

        result = {}
        all_proxy = read("all_proxy")
        http = read("http_proxy") or all_proxy
        https = read("https_proxy") or all_proxy or http
        if http:
            result["http"] = normalize_proxy_url(http)
        if https:
            result["https"] = normalize_proxy_url(https)
        no_proxy = read("no_proxy")
        if no_proxy:
            result["no_proxy"] = no_proxy
        return result

    def _detect_system_settings(self):
        """Lit la configuration propre au système d'exploitation."""
        os_name = platform.system().lower()
        if os_name == "windows":
            return self._detect_windows_proxy()
        if os_name == "darwin":
            return self._detect_macos_proxy()
        if os_name.startswith("linux"):
            return self._detect_linux_proxy()
        return {}

    @staticmethod
    def parse_windows_proxy_server(value):
        """
        Analyse la valeur ProxyServer du registre Windows.

        Formats : "proxy:8080", "http://proxy:8080",
        "http=proxy:80;https=proxy:443;ftp=...".

        Returns:
            dict: {'http': ..., 'https': ...}
        """
        result = {}
        if not value:
            return result
        value = value.strip()
        if "=" not in value:
            url = normalize_proxy_url(value.split(";")[0])
            return {"http": url, "https": url}

        for entry in value.split(";"):
            if "=" not in entry:
                continue
            protocol, address = (part.strip() for part in entry.split("=", 1))
            protocol = protocol.lower()
            if protocol in ("http", "https") and address:
                result[protocol] = normalize_proxy_url(address)
            elif protocol == "socks" and address:
                result.setdefault("socks", normalize_proxy_url(address, "socks4"))
        if "https" not in result and "http" in result:
            result["https"] = result["http"]
        if "http" not in result and "socks" in result:
            result["http"] = result["https"] = result["socks"]
        result.pop("socks", None)
        return result

    def _detect_windows_proxy(self):
        """Lit les paramètres Internet de l'utilisateur dans le registre."""
        import winreg

        result = {}
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            def query(name):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return None

            pac_url = query("AutoConfigURL")
            if pac_url:
                result["pac_url"] = pac_url

            if query("ProxyEnable"):
                result.update(self.parse_windows_proxy_server(query("ProxyServer")))
                overrides = query("ProxyOverride")
                if overrides:
                    result["no_proxy"] = ",".join(parse_no_proxy(overrides))
        return result

    def _detect_macos_proxy(self):
        """Lit les paramètres réseau via « scutil --proxy »."""
        output = _run(["scutil", "--proxy"])
        if not output:
            return {}

        values = {}
        exceptions = []
        in_exceptions = False
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("ExceptionsList"):
                in_exceptions = True
                continue
            if in_exceptions:
                if line.startswith("}"):
                    in_exceptions = False
                    continue
                match = re.match(r"\d+\s*:\s*(.+)", line)
                if match:
                    exceptions.append(match.group(1).strip())
                continue
            match = re.match(r"(\w+)\s*:\s*(.+)", line)
            if match:
                values[match.group(1)] = match.group(2).strip()

        result = {}
        for scheme, prefix in (("http", "HTTP"), ("https", "HTTPS")):
            if values.get(f"{prefix}Enable") == "1" and values.get(f"{prefix}Proxy"):
                port = values.get(f"{prefix}Port", "80")
                result[scheme] = f"http://{values[prefix + 'Proxy']}:{port}"
        if values.get("ProxyAutoConfigEnable") == "1" and values.get("ProxyAutoConfigURLString"):
            result["pac_url"] = values["ProxyAutoConfigURLString"]
        if exceptions:
            result["no_proxy"] = ",".join(exceptions)
        return result

    def _detect_linux_proxy(self):
        """Lit la configuration GNOME (gsettings) puis KDE (kreadconfig)."""
        return self._detect_gnome_proxy() or self._detect_kde_proxy()

    @staticmethod
    def _detect_gnome_proxy():
        def get(schema, key):
            output = _run(["gsettings", "get", schema, key])
            return output.strip().strip("'") if output else ""

        mode = get("org.gnome.system.proxy", "mode")
        result = {}
        if mode == "manual":
            for scheme in ("http", "https"):
                host = get(f"org.gnome.system.proxy.{scheme}", "host")
                port = get(f"org.gnome.system.proxy.{scheme}", "port")
                if host and port and port != "0":
                    result[scheme] = normalize_proxy_url(f"{host}:{port}")
            if "http" in result and "https" not in result:
                result["https"] = result["http"]
            ignore = _run(["gsettings", "get", "org.gnome.system.proxy", "ignore-hosts"]) or ""
            hosts = re.findall(r"'([^']+)'", ignore)
            if hosts:
                result["no_proxy"] = ",".join(hosts)
        elif mode == "auto":
            pac_url = get("org.gnome.system.proxy", "autoconfig-url")
            if pac_url:
                result["pac_url"] = pac_url
        return result

    @staticmethod
    def _detect_kde_proxy():
        def read(key):
            for tool in ("kreadconfig6", "kreadconfig5"):
                output = _run([tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key])
                if output is not None:
                    return output.strip()
            return ""

        proxy_type = read("ProxyType")
        result = {}
        if proxy_type == "1":
            for scheme, key in (("http", "httpProxy"), ("https", "httpsProxy")):
                value = read(key)
                if value:
                    # KDE stocke "http://hote 8080" (port séparé par un espace)
                    value = re.sub(r"\s+(\d+)$", r":\1", value)
                    result[scheme] = normalize_proxy_url(value)
            no_proxy = read("NoProxyFor")
            if no_proxy:
                result["no_proxy"] = no_proxy
        elif proxy_type == "2":
            pac_url = read("Proxy Config Script")
            if pac_url:
                result["pac_url"] = pac_url
        return result

    # ------------------------------------------------------------------ #
    # Fichiers PAC
    # ------------------------------------------------------------------ #
    def find_proxy_for_url(self, url, pac_url):
        """
        Évalue un fichier PAC pour une URL.

        Args:
            url (str): URL cible
            pac_url (str): URL (http, https, file) ou chemin du fichier PAC

        Returns:
            str|None: URL du proxy, None pour une connexion directe ou en cas d'échec
        """
        pac = self._load_pac(pac_url)
        if pac is None:
            return None
        host = urlsplit(url).hostname or ""
        try:
            return parse_pac_result(pac.find_proxy_for_url(url, host))
        except Exception as exc:
            logger.warning("PAC evaluation failed for %s: %s", host, exc)
            return None

    def _load_pac(self, pac_url):
        """Télécharge et compile un fichier PAC (avec cache)."""
        if pac_url in self._pac_cache:
            return self._pac_cache[pac_url]

        pac = None
        try:
            from pypac.parser import PACFile
        except ImportError:
            if not self._pac_warning_shown:
                logger.warning("PAC file found but pypac is not installed: pip install iziproxy[pac]")
                self._pac_warning_shown = True
            return None

        text = self.fetch_pac(pac_url)
        if text:
            try:
                pac = PACFile(text)
            except Exception as exc:
                logger.warning("Invalid PAC file %s: %s", pac_url, exc)
        self._pac_cache[pac_url] = pac
        return pac

    @staticmethod
    def fetch_pac(pac_url):
        """
        Télécharge le contenu d'un fichier PAC, sans passer par un proxy.

        Returns:
            str|None: Contenu JavaScript du PAC
        """
        if os.path.exists(pac_url):
            with open(pac_url, "r", encoding="utf-8", errors="replace") as file:
                return file.read()

        def open_url(context):
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context),
            )
            with opener.open(pac_url, timeout=5) as response:
                status = getattr(response, "status", None)
                if status not in (None, 200):
                    return None
                return response.read().decode("utf-8", errors="replace")

        try:
            return open_url(ssl.create_default_context())
        except Exception as exc:
            # urllib enveloppe les erreurs TLS dans URLError.reason
            if not isinstance(getattr(exc, "reason", exc), ssl.SSLError):
                logger.warning("Cannot download PAC file %s: %s", pac_url, exc)
                return None

        # Les PAC internes sont souvent servis avec une CA d'entreprise inconnue
        logger.warning("PAC certificate for %s could not be verified, retrying without verification", pac_url)
        unverified = ssl.create_default_context()
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        try:
            return open_url(unverified)
        except Exception as exc:
            logger.warning("Cannot download PAC file %s: %s", pac_url, exc)
        return None

    def clear_cache(self):
        """Vide les caches de détection et de PAC."""
        self._settings = None
        self._pac_cache.clear()
