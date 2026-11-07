"""
Fonctions utilitaires partagées : règles de contournement (no_proxy),
manipulation des URLs de proxy et construction des contextes TLS.
"""

import fnmatch
import ipaddress
import ssl
from urllib.parse import quote, unquote, urlsplit

# Hôtes toujours joignables sans proxy (boucle locale)
LOOPBACK_BYPASS = ("localhost", "127.0.0.0/8", "::1")


def parse_no_proxy(value):
    """
    Normalise une liste d'exclusions de proxy.

    Accepte une chaîne séparée par des virgules, points-virgules ou espaces
    (formats NO_PROXY, registre Windows, GNOME, KDE) ou une liste.

    Args:
        value (str|list|None): Exclusions brutes

    Returns:
        list: Entrées nettoyées, sans doublons, ordre conservé
    """
    if not value:
        return []
    if isinstance(value, str):
        for sep in (";", " ", "\t", "\n"):
            value = value.replace(sep, ",")
        items = value.split(",")
    else:
        items = list(value)

    result = []
    for item in items:
        item = str(item).strip().lower()
        if item and item not in result:
            result.append(item)
    return result


def _split_host_port(entry):
    """Sépare 'hote:port' (et '[ipv6]:port') en (hote, port|None)."""
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
        return host, port
    if entry.count(":") == 1:
        host, port = entry.split(":")
        if port.isdigit():
            return host, port
    return entry, None


def _match_entry(entry, host, port):
    """Vérifie si un hôte correspond à une entrée d'exclusion."""
    if entry == "*":
        return True

    # Entrée spéciale Windows : noms d'hôte sans point (intranet)
    if entry == "<local>":
        return "." not in host and ":" not in host

    # Supprimer un éventuel schéma ("http://intranet")
    if "://" in entry:
        entry = entry.split("://", 1)[1]
    entry = entry.rstrip("/")

    entry_host, entry_port = _split_host_port(entry)
    if entry_port and port and entry_port != str(port):
        return False

    # Réseau CIDR ou adresse IP
    try:
        network = ipaddress.ip_network(entry_host, strict=False)
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    except ValueError:
        pass

    # Joker ("*.corp.com", "10.*", "intra*")
    if any(c in entry_host for c in "*?["):
        if fnmatch.fnmatchcase(host, entry_host):
            return True
        # "*.corp.com" doit aussi couvrir "corp.com"
        if entry_host.startswith("*.") and host == entry_host[2:]:
            return True
        return False

    # Suffixe de domaine (".corp.com" ou "corp.com")
    suffix = entry_host.lstrip(".")
    return host == suffix or host.endswith("." + suffix)


def should_bypass(url, no_proxy, include_loopback=True):
    """
    Indique si une URL doit être contactée directement, sans proxy.

    Args:
        url (str): URL cible
        no_proxy (str|list): Règles d'exclusion
        include_loopback (bool): Toujours exclure localhost / 127.0.0.0/8 / ::1

    Returns:
        bool: True si le proxy doit être contourné
    """
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return False
    if not host:
        return False

    entries = parse_no_proxy(no_proxy)
    if include_loopback:
        entries = list(LOOPBACK_BYPASS) + entries

    return any(_match_entry(entry, host, port) for entry in entries)


def no_proxy_for_env(no_proxy):
    """
    Convertit des règles d'exclusion au format de la variable NO_PROXY
    (compris par curl, pip, git, requests...).

    Args:
        no_proxy (str|list): Règles d'exclusion

    Returns:
        str: Liste séparée par des virgules
    """
    result = []
    for entry in parse_no_proxy(no_proxy):
        if entry == "<local>":
            continue
        if entry.startswith("*."):
            entry = entry[1:]
        if entry not in result:
            result.append(entry)
    for entry in ("localhost", "127.0.0.1", "::1"):
        if entry not in result:
            result.append(entry)
    return ",".join(result)


def normalize_proxy_url(value, default_scheme="http"):
    """
    Ajoute un schéma à une adresse de proxy si nécessaire.

    Args:
        value (str): "proxy:8080" ou "http://proxy:8080"

    Returns:
        str|None: URL complète
    """
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    return value


def strip_credentials(proxy_url):
    """Retire les identifiants d'une URL de proxy."""
    if not proxy_url or "@" not in proxy_url:
        return proxy_url
    scheme, sep, rest = proxy_url.partition("://")
    if not sep:
        return proxy_url
    return f"{scheme}://{rest.rsplit('@', 1)[1]}"


def has_credentials(proxy_url):
    """Indique si une URL de proxy contient déjà des identifiants."""
    if not proxy_url or "://" not in proxy_url:
        return False
    netloc = proxy_url.split("://", 1)[1].split("/", 1)[0]
    return "@" in netloc


def inject_credentials(proxy_url, username, password):
    """
    Insère des identifiants (encodés pour l'URL) dans une URL de proxy.

    Les caractères spéciaux (@, :, %, /, \\) sont encodés afin que requests
    et urllib3 les décodent correctement.

    Args:
        proxy_url (str): URL du proxy sans identifiants
        username (str): Nom d'utilisateur
        password (str): Mot de passe

    Returns:
        str: URL avec identifiants
    """
    if not proxy_url or not username:
        return proxy_url
    proxy_url = strip_credentials(normalize_proxy_url(proxy_url))
    scheme, rest = proxy_url.split("://", 1)
    auth = quote(str(username), safe="")
    if password:
        auth += ":" + quote(str(password), safe="")
    return f"{scheme}://{auth}@{rest}"


def extract_credentials(proxy_url):
    """
    Extrait (username, password) d'une URL de proxy.

    Returns:
        tuple: (username|None, password|None) décodés
    """
    if not has_credentials(proxy_url):
        return None, None
    auth = proxy_url.split("://", 1)[1].rsplit("@", 1)[0]
    username, _, password = auth.partition(":")
    return unquote(username) or None, unquote(password) or None


def proxy_host_port(proxy_url):
    """
    Retourne (hôte, port) d'une URL de proxy, avec le port par défaut du schéma.

    Returns:
        tuple: (host, port) ou (None, None)
    """
    if not proxy_url:
        return None, None
    try:
        parts = urlsplit(normalize_proxy_url(proxy_url))
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None, None
    if not host:
        return None, None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return host, port


def split_timeout(timeout):
    """
    Convertit un timeout requests (nombre, tuple ou urllib3.Timeout)
    en (connect, read).
    """
    if timeout is None:
        return None, None
    if isinstance(timeout, tuple):
        connect, read = timeout
        return connect, read
    connect = getattr(timeout, "connect_timeout", None)
    read = getattr(timeout, "read_timeout", None)
    if connect is not None or read is not None or hasattr(timeout, "connect_timeout"):
        # urllib3 utilise un sentinel pour "valeur par défaut"
        connect = connect if isinstance(connect, (int, float)) else None
        read = read if isinstance(read, (int, float)) else None
        return connect, read
    return timeout, timeout


def build_ssl_context(verify=True, cert=None):
    """
    Construit un contexte TLS équivalent à celui de requests.

    Lorsque verify vaut True, le magasin système ET le bundle certifi de
    requests sont chargés : les proxys d'entreprise à inspection TLS
    installent souvent leur CA dans le magasin système.

    Args:
        verify (bool|str): True, False ou chemin vers un bundle/répertoire CA
        cert (str|tuple): Certificat client (fichier ou (cert, clé))

    Returns:
        ssl.SSLContext: Contexte prêt à l'emploi
    """
    import os

    ctx = ssl.create_default_context()
    if verify is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        if os.path.isdir(verify):
            ctx.load_verify_locations(capath=verify)
        else:
            ctx.load_verify_locations(cafile=verify)
    else:
        try:
            from requests.utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths

            ctx.load_verify_locations(cafile=extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH))
        except Exception:
            pass

    if cert:
        if isinstance(cert, (tuple, list)):
            ctx.load_cert_chain(cert[0], cert[1])
        else:
            ctx.load_cert_chain(cert)
    return ctx


def parse_proxy_authenticate(headers):
    """
    Extrait les schémas et jetons des en-têtes Proxy-Authenticate.

    Args:
        headers (list): Liste de tuples (nom, valeur)

    Returns:
        dict: {schéma_minuscule: jeton_ou_chaîne_vide}
    """
    result = {}
    for name, value in headers:
        if name.lower() != "proxy-authenticate":
            continue
        # Un même en-tête peut contenir plusieurs schémas séparés par des virgules
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            scheme, _, token = part.partition(" ")
            scheme = scheme.lower()
            # Les paramètres (realm="...") ne sont pas des schémas
            if "=" in scheme:
                continue
            token = token.strip()
            if token or scheme not in result:
                result[scheme] = token
    return result


def probe_proxy_auth(proxy_url, timeout=3.0):
    """
    Interroge un proxy sans identifiants pour savoir s'il exige une
    authentification et avec quels schémas.

    Seul le proxy est contacté : la requête vise un domaine réservé
    (example.com) et le proxy répond 407 avant tout accès externe.

    Args:
        proxy_url (str): URL du proxy
        timeout (float): Délai maximal en secondes

    Returns:
        tuple: (statut HTTP ou None si injoignable, {schéma: jeton})
    """
    import http.client
    import socket

    host, port = proxy_host_port(proxy_url)
    if not host:
        return None, {}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None, {}
    try:
        if normalize_proxy_url(proxy_url).startswith("https://"):
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(
            b"HEAD http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Proxy-Connection: close\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = http.client.HTTPResponse(sock, method="HEAD")
        response.begin()
        return response.status, parse_proxy_authenticate(response.getheaders())
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None, {}
    finally:
        sock.close()
