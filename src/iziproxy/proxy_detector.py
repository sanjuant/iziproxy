"""
Module de détection automatique des proxys système et des fichiers PAC
"""

import logging
import os
import platform
import re
import socket
import ssl
import urllib.request
from urllib.parse import urlparse

# Configuration du logger
logger = logging.getLogger("iziproxy")


class ProxyDetector:
    """
    Détecte les proxys disponibles sur le système
    
    Cette classe permet de:
    - Détecter les proxys configurés au niveau du système
    - Récupérer les paramètres depuis les variables d'environnement
    - Analyser les fichiers PAC (Proxy Auto-Configuration)
    """

    ENV_PROXY_VARS = [
        "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
        "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"
    ]

    def __init__(self, config=None):
        """
        Initialise le détecteur de proxy
        
        Args:
            config (dict, optional): Configuration spécifique
        """
        self.config = config or {}
        self.use_system_proxy = self.config.get("use_system_proxy", True)
        self.detect_pac = self.config.get("detect_pac", True)
        self._detection_cache = {}
        self._pac_url = None
        self._system_info = self._get_system_info()

    def _get_system_info(self):
        """
        Collecte les informations système pour faciliter la détection
        
        Returns:
            dict: Informations système
        """
        return {
            "os": platform.system().lower(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "hostname": socket.gethostname().lower(),
        }

    def detect_system_proxy(self, url=None, force_refresh=False):
        """
        Détecte le proxy configuré sur le système
        
        Args:
            url (str, optional): URL cible pour laquelle trouver le proxy (utile pour PAC)
            force_refresh (bool, optional): Force la détection même si en cache
            
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        # Vérifier si la détection est activée
        if not self.use_system_proxy:
            logger.debug("Détection de proxy système désactivée")
            return {}

        # Cache key (None ou URL spécifique)
        cache_key = url or "_default_"

        # Vérifier si déjà en cache et pas de rafraîchissement forcé
        if cache_key in self._detection_cache and not force_refresh:
            logger.debug(f"Utilisation du cache pour {cache_key}")
            return self._detection_cache[cache_key]

        result = {}

        # Ordre de priorité de détection
        methods = [
            self._detect_env_vars,
            self._detect_system_settings
        ]

        # Ajouter la détection PAC si activée
        if self.detect_pac:
            methods.append(self._detect_pac_file)

        # On a besoin de savoir si on a trouvé un proxy HTTP/HTTPS pour éviter
        # de continuer inutilement
        found_proxy = False

        # Essayer chaque méthode
        for method in methods:
            try:
                method_name = getattr(method, '__name__', str(method))
                proxy_config = method(url)

                if proxy_config:
                    result.update(proxy_config)
                    logger.debug(f"Proxy détecté via {method_name}: {proxy_config}")

                    # Vérifier si on a trouvé un proxy HTTP/HTTPS
                    if 'http' in proxy_config or 'https' in proxy_config:
                        found_proxy = True
                        break
            except Exception as e:
                method_name = getattr(method, '__name__', str(method))
                logger.debug(f"Erreur lors de la détection via {method_name}: {e}")

        # Si on n'a pas trouvé de proxy mais qu'on a une URL PAC, essayer de la traiter
        if not found_proxy and not result.get('http') and not result.get('https') and result.get('pac_url'):
            try:
                pac_result = self._detect_pac_file(url)
                if pac_result:
                    result.update(pac_result)
                    logger.debug(f"Proxy détecté via PAC: {pac_result}")
            except Exception as e:
                logger.debug(f"Erreur lors de la détection via PAC: {e}")

        # Mettre en cache
        self._detection_cache[cache_key] = result

        # Journaliser le résultat
        if result:
            logger.info(f"Proxy système détecté: {result}")
        else:
            logger.info("Aucun proxy système détecté")

        return result

    def _detect_env_vars(self, url=None):
        """
        Détecte les proxys configurés via variables d'environnement
        
        Args:
            url (str, optional): URL cible (non utilisé pour cette méthode)
            
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        result = {}

        # Vérifier les variables d'environnement standard
        for var in self.ENV_PROXY_VARS:
            if var in os.environ and os.environ[var]:
                var_lower = var.lower()
                if var_lower.startswith('http_'):
                    result['http'] = os.environ[var]
                elif var_lower.startswith('https_'):
                    result['https'] = os.environ[var]
                elif var_lower.startswith('all_'):
                    # ALL_PROXY est utilisé pour HTTP et HTTPS
                    if 'http' not in result:
                        result['http'] = os.environ[var]
                    if 'https' not in result:
                        result['https'] = os.environ[var]
                elif var_lower.startswith('no_proxy'):
                    result['no_proxy'] = os.environ[var]

        # Si seul HTTP est défini, l'utiliser aussi pour HTTPS sauf indication contraire
        if 'http' in result and 'https' not in result:
            result['https'] = result['http']

        return result

    def _detect_system_settings(self, url=None):
        """
        Détecte les proxys configurés dans les paramètres système
        
        Args:
            url (str, optional): URL cible (non utilisé pour cette méthode)
            
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        result = {}

        # Vérifier en fonction du système d'exploitation
        os_name = self._system_info["os"]
        
        if os_name == 'windows':
            result = self._detect_windows_proxy()
        elif os_name == 'darwin':
            result = self._detect_macos_proxy()
        elif os_name.startswith('linux'):
            result = self._detect_linux_proxy()

        return result

    def _detect_windows_proxy(self):
        """
        Détecte les proxys configurés sur Windows (Registre)
        
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...', 'pac_url': '...'}
        """
        result = {}

        try:
            import winreg

            # Accéder aux clés de Registre pour les paramètres Internet
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')

            # Vérifier s'il y a un fichier PAC configuré (indépendamment de proxy_enable)
            try:
                pac_url, _ = winreg.QueryValueEx(key, 'AutoConfigURL')
                if pac_url:
                    # Stocker pour une analyse ultérieure
                    result['pac_url'] = pac_url
                    self._pac_url = pac_url
                    logger.debug(f"Fichier PAC détecté: {pac_url}")
            except (FileNotFoundError, WindowsError):
                pass

            # Vérifier si un proxy manuel est activé
            try:
                proxy_enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')

                if proxy_enable:
                    # Récupérer l'adresse du proxy
                    proxy_server, _ = winreg.QueryValueEx(key, 'ProxyServer')

                    # Vérifier si le proxy est unique ou par protocole
                    if ';' in proxy_server:
                        # Format "protocole=adresse:port;protocole2=adresse2:port2"
                        entries = proxy_server.split(';')
                        for entry in entries:
                            if '=' in entry:
                                protocol, address = entry.split('=', 1)
                                if protocol.lower() == 'http':
                                    result['http'] = f'http://{address}'
                                elif protocol.lower() == 'https':
                                    result['https'] = f'http://{address}'
                    else:
                        # Unique pour tous les protocoles
                        result['http'] = f'http://{proxy_server}'
                        result['https'] = f'http://{proxy_server}'

                    # Vérifier les exceptions (pour NO_PROXY)
                    try:
                        exceptions, _ = winreg.QueryValueEx(key, 'ProxyOverride')
                        if exceptions:
                            result['no_proxy'] = exceptions.replace(';', ',')
                    except:
                        pass
            except (FileNotFoundError, WindowsError):
                pass

        except Exception as e:
            logger.debug(f"Erreur lors de la détection du proxy Windows: {e}")

        return result

    def _detect_macos_proxy(self):
        """
        Détecte les proxys configurés sur macOS
        
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        result = {}

        try:
            # Utiliser networksetup pour obtenir les paramètres de proxy
            import subprocess

            # Obtenir la liste des services réseau
            services_output = subprocess.check_output(
                ['networksetup', '-listallnetworkservices'],
                universal_newlines=True
            )

            # Ignorer la première ligne qui est un message d'information
            services = services_output.strip().split('\n')[1:]

            # Pour chaque service, vérifier les paramètres de proxy
            for service in services:
                # Vérifier si le service est actif (pas d'astérisque devant le nom)
                if service.startswith('*'):
                    continue

                # Vérifier le proxy HTTP
                try:
                    http_output = subprocess.check_output(
                        ['networksetup', '-getwebproxy', service],
                        universal_newlines=True
                    )

                    # Analyser la sortie pour vérifier si le proxy est activé
                    if 'Enabled: Yes' in http_output:
                        server = None
                        port = None

                        for line in http_output.split('\n'):
                            if 'Server:' in line:
                                server = line.split(':', 1)[1].strip()
                            elif 'Port:' in line:
                                port = line.split(':', 1)[1].strip()

                        if server and port:
                            result['http'] = f'http://{server}:{port}'
                except:
                    pass

                # Vérifier le proxy HTTPS
                try:
                    https_output = subprocess.check_output(
                        ['networksetup', '-getsecurewebproxy', service],
                        universal_newlines=True
                    )

                    # Analyser la sortie pour vérifier si le proxy est activé
                    if 'Enabled: Yes' in https_output:
                        server = None
                        port = None

                        for line in https_output.split('\n'):
                            if 'Server:' in line:
                                server = line.split(':', 1)[1].strip()
                            elif 'Port:' in line:
                                port = line.split(':', 1)[1].strip()

                        if server and port:
                            result['https'] = f'http://{server}:{port}'
                except:
                    pass

                # Vérifier le PAC
                try:
                    pac_output = subprocess.check_output(
                        ['networksetup', '-getautoproxyurl', service],
                        universal_newlines=True
                    )

                    # Analyser la sortie pour vérifier si le PAC est activé
                    if 'Enabled: Yes' in pac_output:
                        for line in pac_output.split('\n'):
                            if 'URL:' in line:
                                pac_url = line.split(':', 1)[1].strip()
                                if pac_url:
                                    # Stocker pour une analyse ultérieure si nécessaire
                                    result['pac_url'] = pac_url
                                    self._pac_url = pac_url
                                break
                except:
                    pass

                # Si on a trouvé un proxy, on peut s'arrêter
                if result:
                    break
        except Exception as e:
            logger.debug(f"Erreur lors de la détection du proxy macOS: {e}")

        return result

    def _detect_linux_proxy(self):
        """
        Détecte les proxys configurés sur Linux (GNOME/KDE)
        
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        result = {}

        # Essayer avec gsettings (GNOME)
        try:
            import subprocess

            # Vérifier si le proxy est activé dans GNOME
            mode_output = subprocess.check_output(
                ['gsettings', 'get', 'org.gnome.system.proxy', 'mode'],
                universal_newlines=True
            ).strip()

            # Si le mode est 'manual', le proxy est configuré manuellement
            if 'manual' in mode_output:
                # HTTP Proxy
                try:
                    host = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy.http', 'host'],
                        universal_newlines=True
                    ).strip().strip("'")

                    port = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy.http', 'port'],
                        universal_newlines=True
                    ).strip()

                    if host and port:
                        result['http'] = f'http://{host}:{port}'
                except:
                    pass

                # HTTPS Proxy
                try:
                    host = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy.https', 'host'],
                        universal_newlines=True
                    ).strip().strip("'")

                    port = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy.https', 'port'],
                        universal_newlines=True
                    ).strip()

                    if host and port:
                        result['https'] = f'http://{host}:{port}'
                except:
                    pass

                # No Proxy
                try:
                    ignore_hosts = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy', 'ignore-hosts'],
                        universal_newlines=True
                    )

                    if ignore_hosts and 'nothing' not in ignore_hosts:
                        # Convertir le format GNOME en format NO_PROXY
                        hosts = re.findall(r"'([^']+)'", ignore_hosts)
                        if hosts:
                            result['no_proxy'] = ','.join(hosts)
                except:
                    pass

            # Si le mode est 'auto', un fichier PAC est utilisé
            elif 'auto' in mode_output:
                try:
                    pac_url = subprocess.check_output(
                        ['gsettings', 'get', 'org.gnome.system.proxy', 'autoconfig-url'],
                        universal_newlines=True
                    ).strip().strip("'")

                    if pac_url:
                        result['pac_url'] = pac_url
                        self._pac_url = pac_url
                except:
                    pass
        except Exception as e:
            logger.debug(f"Erreur lors de la détection du proxy GNOME: {e}")

        # Si GNOME n'a pas donné de résultat, essayer avec KDE
        if not result:
            try:
                # Vérifier la configuration KDE via kreadconfig5
                proxy_type = subprocess.check_output(
                    ['kreadconfig5', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'ProxyType'],
                    universal_newlines=True
                ).strip()

                # Si le type est 1, le proxy est configuré manuellement
                if proxy_type == '1':
                    # HTTP Proxy
                    http_proxy = subprocess.check_output(
                        ['kreadconfig5', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpProxy'],
                        universal_newlines=True
                    ).strip()

                    if http_proxy:
                        if not http_proxy.startswith('http://'):
                            http_proxy = 'http://' + http_proxy
                        result['http'] = http_proxy

                    # HTTPS Proxy
                    https_proxy = subprocess.check_output(
                        ['kreadconfig5', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'httpsProxy'],
                        universal_newlines=True
                    ).strip()

                    if https_proxy:
                        if not https_proxy.startswith('http://'):
                            https_proxy = 'http://' + https_proxy
                        result['https'] = https_proxy

                    # No Proxy
                    no_proxy = subprocess.check_output(
                        ['kreadconfig5', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'NoProxyFor'],
                        universal_newlines=True
                    ).strip()

                    if no_proxy:
                        result['no_proxy'] = no_proxy.replace(',', ';')

                # Si le type est 2, un fichier PAC est utilisé
                elif proxy_type == '2':
                    pac_url = subprocess.check_output(
                        ['kreadconfig5', '--file', 'kioslaverc', '--group', 'Proxy Settings', '--key', 'Proxy Config Script'],
                        universal_newlines=True
                    ).strip()

                    if pac_url:
                        result['pac_url'] = pac_url
                        self._pac_url = pac_url
            except Exception as e:
                logger.debug(f"Erreur lors de la détection du proxy KDE: {e}")

        return result

    def _detect_pac_file(self, url=None):
        """
        Détecte et utilise le fichier PAC pour obtenir le proxy
        
        Args:
            url (str, optional): URL cible pour laquelle trouver le proxy
            
        Returns:
            dict: Configuration de proxy {'http': '...', 'https': '...'}
        """
        result = {}

        # URL cible par défaut si non spécifiée
        if not url:
            url = "https://www.google.com"

        # Vérifier si on a déjà une URL PAC
        pac_url = self._pac_url

        if not pac_url:
            # Essayer de détecter l'URL PAC depuis les méthodes précédentes
            from_env = self._detect_env_vars()
            from_system = self._detect_system_settings()

            if 'pac_url' in from_env:
                pac_url = from_env['pac_url']
            elif 'pac_url' in from_system:
                pac_url = from_system['pac_url']

            # Stocker pour les prochains appels
            self._pac_url = pac_url

        if not pac_url:
            return {}

        logger.debug(f"Utilisation du fichier PAC: {pac_url}")

        # Essayer d'utiliser pypac si disponible
        try:
            from pypac import parser, resolver

            # Télécharger et parser le PAC
            pac_text = self._fetch_pac(pac_url)
            if not pac_text:
                return {}

            pac = parser.PACFile(pac_text)

            # Obtenir la configuration pour l'URL cible
            parsed_url = urlparse(url)
            proxy_str = pac.find_proxy_for_url(url, parsed_url.netloc)

            # Convertir en format de proxy requests
            if proxy_str:
                # Format typique: "PROXY proxy.example.com:8080; DIRECT"
                parts = proxy_str.split(';')
                for part in parts:
                    part = part.strip().lower()
                    if part.startswith('proxy '):
                        proxy_address = part[6:]  # Supprimer "PROXY "
                        result['http'] = f"http://{proxy_address}"
                        result['https'] = f"http://{proxy_address}"
                        logger.debug(f"Proxy trouvé via PAC: {proxy_address}")
                        break
                    elif part == 'direct':
                        # Pas de proxy pour cette URL
                        logger.debug("Le PAC indique une connexion directe")
                        return {}
        except ImportError:
            logger.debug("Module pypac non disponible, utilisation d'une méthode alternative")
            # Méthode alternative si pypac n'est pas installé
            # Simplement suggérer l'installation de pypac
            logger.warning("Pour une meilleure prise en charge des fichiers PAC, installez: pip install pypac")
            return {}
        except Exception as e:
            logger.debug(f"Erreur lors de l'analyse du fichier PAC: {e}")
            return {}

        return result

    def _fetch_pac(self, pac_url):
        """
        Télécharge le contenu d'un fichier PAC
        
        Args:
            pac_url (str): URL du fichier PAC
            
        Returns:
            str: Contenu du fichier PAC ou None en cas d'échec
        """
        try:
            # Créer un contexte SSL non vérifié pour les fichiers PAC internes
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Faire la requête
            response = urllib.request.urlopen(pac_url, timeout=5, context=ctx)

            if response.status == 200:
                return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Erreur lors du téléchargement du fichier PAC: {e}")

        return None

    def clear_cache(self):
        """
        Vide le cache de détection de proxy
        """
        self._detection_cache.clear()
        logger.debug("Cache de détection de proxy vidé")
