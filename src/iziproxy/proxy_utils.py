"""
Fonctions utilitaires partagées : règles de contournement (no_proxy),
manipulation des URLs de proxy et construction des contextes TLS.
"""

import fnmatch
import http.client
import io
import ipaddress
import logging
import ssl
from urllib.parse import quote, unquote, urlsplit

logger = logging.getLogger("iziproxy")

# Hôtes toujours joignables sans proxy (boucle locale)
LOOPBACK_BYPASS = ("localhost", "127.0.0.0/8", "::1")

# Ports par défaut des schémas d'URL cibles
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Taille maximale de l'en-tête d'une réponse à un CONNECT (lu octet par octet)
MAX_TUNNEL_HEAD = 65536


def _netloc_bounds(url):
    """
    Retourne (schéma, autorité, reste) d'une URL, ou None sans « :// ».

    L'autorité s'arrête au premier « / », « ? » ou « # » : un « @ » dans le
    chemin n'est donc jamais pris pour un séparateur d'identifiants.
    """
    scheme, sep, rest = (url or "").partition("://")
    if not sep:
        return None
    end = len(rest)
    for char in "/?#":
        index = rest.find(char)
        if index != -1:
            end = min(end, index)
    return scheme, rest[:end], rest[end:]


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
    # port est toujours renseigné (port par défaut du schéma) : « hote:8080 »
    # ne couvre donc pas http://hote/
    if entry_port and entry_port != str(port):
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
        port = parts.port or DEFAULT_PORTS.get(parts.scheme.lower())
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
    bounds = _netloc_bounds(proxy_url)
    if bounds is None or "@" not in bounds[1]:
        return proxy_url
    scheme, netloc, rest = bounds
    return f"{scheme}://{netloc.rsplit('@', 1)[1]}{rest}"


def has_credentials(proxy_url):
    """Indique si une URL de proxy contient déjà des identifiants."""
    bounds = _netloc_bounds(proxy_url)
    return bounds is not None and "@" in bounds[1]


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
    auth = _netloc_bounds(proxy_url)[1].rsplit("@", 1)[0]
    username, _, password = auth.partition(":")
    return unquote(username) or None, unquote(password) or None


def is_https_proxy(proxy_url):
    """Indique si l'on parle TLS au proxy lui-même (URL en https://)."""
    return bool(proxy_url) and normalize_proxy_url(proxy_url).lower().startswith("https://")


def wrap_tls(sock, context, server_hostname):
    """
    Chiffre une connexion, y compris un tunnel qui passe déjà par une
    connexion TLS vers un proxy https:// (TLS dans TLS).

    ssl.SSLContext.wrap_socket() ne sait pas empiler deux couches TLS : la
    seconde utiliserait directement le descripteur réseau. urllib3 fournit
    SSLTransport, qui chiffre en mémoire au-dessus d'une socket TLS.

    Args:
        sock (socket.socket): Connexion ouverte (éventuellement déjà TLS)
        context (ssl.SSLContext): Contexte TLS
        server_hostname (str): Nom vérifié dans le certificat

    Returns:
        ssl.SSLSocket|urllib3.util.ssltransport.SSLTransport: Connexion chiffrée
    """
    if isinstance(sock, ssl.SSLSocket):
        from urllib3.util.ssltransport import SSLTransport

        return SSLTransport(sock, context, server_hostname=server_hostname)
    return context.wrap_socket(sock, server_hostname=server_hostname)


class _ReplayReader(io.RawIOBase):
    """Flux brut qui rend d'abord des octets déjà lus, puis lit le socket."""

    def __init__(self, head, sock):
        super().__init__()
        self._head = head
        self._sock = sock

    def readable(self):
        return True

    def readinto(self, buffer):
        if self._head:
            size = min(len(buffer), len(self._head))
            buffer[:size] = self._head[:size]
            self._head = self._head[size:]
            return size
        return self._sock.recv_into(buffer)


class _ReplaySocket:
    """Pseudo-socket donné à http.client (seul makefile() est utilisé)."""

    def __init__(self, head, sock):
        self._raw = _ReplayReader(head, sock)

    def makefile(self, *args, **kwargs):
        return io.BufferedReader(self._raw)


def read_tunnel_response(sock, method="CONNECT"):
    """
    Lit la réponse d'un proxy à un CONNECT sans consommer les octets qui
    suivent son en-tête.

    http.client lit le socket par blocs : les premiers octets d'un serveur
    qui parle en premier (bannière SSH, SMTP...), arrivés avec la réponse
    200, resteraient dans son tampon et seraient perdus pour le tunnel.
    L'en-tête est donc lu octet par octet ; le corps d'un refus (407...)
    reste lu normalement par http.client.

    Args:
        sock (socket.socket): Connexion au proxy (éventuellement TLS)
        method (str): Méthode de la requête envoyée

    Returns:
        http.client.HTTPResponse: Réponse dont l'en-tête est lu
    """
    head = bytearray()
    while not (head.endswith(b"\n\n") or head.endswith(b"\n\r\n")):
        if len(head) >= MAX_TUNNEL_HEAD:
            raise http.client.LineTooLong("proxy response header")
        byte = sock.recv(1)
        if not byte:
            # Connexion fermée : http.client signale l'en-tête incomplet
            break
        head += byte
    response = http.client.HTTPResponse(_ReplaySocket(bytes(head), sock), method=method)
    response.begin()
    return response


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


def _trusted_context():
    """
    Contexte qui fait confiance aux autorités du système.

    Avec truststore (pip install iziproxy[truststore]), la vérification est
    confiée au système lui-même (Windows, macOS, Linux) : autorités
    d'entreprise déployées par stratégie, trousseau macOS, récupération des
    certificats intermédiaires manquants. Sinon : magasin lu par OpenSSL
    (magasin Windows inclus) complété par certifi.
    """
    try:
        import truststore
    except ImportError:
        truststore = None
    if truststore is not None:
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ctx = ssl.create_default_context()
    try:
        from requests.utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths

        ctx.load_verify_locations(cafile=extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH))
    except Exception:
        pass
    return ctx


def build_ssl_context(verify=True, cert=None):
    """
    Construit un contexte TLS.

    Args:
        verify (bool|str): True (autorités du système, voir _trusted_context),
            False (aucune vérification) ou chemin vers un fichier / répertoire
            d'autorités (seules celles-ci sont acceptées, comme dans requests)
        cert (str|tuple): Certificat client (fichier ou (cert, clé))

    Returns:
        ssl.SSLContext: Contexte prêt à l'emploi
    """
    import os

    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx = ssl.create_default_context(
            capath=verify if os.path.isdir(verify) else None,
            cafile=None if os.path.isdir(verify) else verify,
        )
    else:
        ctx = _trusted_context()

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


def probe_proxy_auth(proxy_url, timeout=3.0, ssl_context=None):
    """
    Interroge un proxy sans identifiants pour savoir s'il exige une
    authentification et avec quels schémas.

    Seul le proxy est contacté : la requête vise un domaine réservé
    (example.com) et le proxy répond 407 avant tout accès externe.

    Args:
        proxy_url (str): URL du proxy
        timeout (float): Délai maximal en secondes
        ssl_context (ssl.SSLContext): Contexte TLS vers un proxy https://
            (par défaut : autorités du système)

    Returns:
        tuple: (statut HTTP ou None si injoignable, {schéma: jeton})
    """
    import socket

    host, port = proxy_host_port(proxy_url)
    if not host:
        return None, {}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None, {}
    try:
        if is_https_proxy(proxy_url):
            sock = (ssl_context or build_ssl_context()).wrap_socket(sock, server_hostname=host)
        sock.sendall(
            b"HEAD http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Proxy-Connection: close\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = http.client.HTTPResponse(sock, method="HEAD")
        response.begin()
        return response.status, parse_proxy_authenticate(response.getheaders())
    except ssl.SSLError as exc:
        logger.warning("TLS handshake with proxy %s failed: %s", strip_credentials(proxy_url), exc)
        return None, {}
    except (OSError, http.client.HTTPException):
        return None, {}
    finally:
        sock.close()


def basic_proxy_authorization(proxy_url):
    """
    En-tête Proxy-Authorization Basic (UTF-8, RFC 7617) pour les
    identifiants présents dans une URL de proxy.

    Returns:
        str|None: Valeur de l'en-tête, None sans identifiants
    """
    import base64

    username, password = extract_credentials(proxy_url)
    if not username:
        return None
    token = f"{username}:{password or ''}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")
