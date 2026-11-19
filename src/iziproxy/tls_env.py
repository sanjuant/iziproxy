"""
Variables TLS des sous-processus : autorités de confiance et révocation.

Derrière un proxy d'entreprise qui inspecte le TLS, les sites présentent des
certificats signés par une autorité interne, installée dans le magasin du
système. Les outils lancés en sous-processus ne le lisent pas tous :

- pip, requests, curl, Node.js utilisent leur propre liste d'autorités
  (certifi, fichier de l'OpenSSL embarqué...) : ils reçoivent un fichier PEM
  exporté du magasin du système (REQUESTS_CA_BUNDLE, PIP_CERT, SSL_CERT_FILE,
  CURL_CA_BUNDLE, NODE_EXTRA_CA_CERTS) ;
- git sous Windows (moteur schannel) vérifie la révocation et échoue si la
  liste de révocation de l'autorité interne est injoignable : il reçoit
  ``http.schannelCheckRevoke=best-effort`` par GIT_CONFIG_COUNT /
  GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n, sans toucher à sa configuration.

Une variable déjà définie par l'utilisateur n'est jamais remplacée.
"""

import logging
import os
import ssl
import subprocess
import sys
import tempfile
import time

logger = logging.getLogger("iziproxy")

BUNDLE_NAME = "ca-bundle.pem"

# Âge maximal de l'export avant de le refaire (secondes)
MAX_AGE = 24 * 3600

# Usage « authentification de serveur TLS » (extended key usage)
SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"

# Variables qui reçoivent un fichier d'autorités
CA_FILE_VARS = ("REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")
# Variables qui acceptent un répertoire d'autorités (verify="/chemin/dossier")
CA_DIR_VARS = ("REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_DIR")
# Toutes les variables d'autorités qu'IziProxy peut définir
CA_VARS = tuple(dict.fromkeys(CA_FILE_VARS + CA_DIR_VARS))

GIT_REVOKE_KEY = "http.schannelCheckRevoke"
GIT_REVOKE_VALUE = "best-effort"

# Fichiers d'autorités des distributions Linux et BSD (le premier trouvé gagne)
SYSTEM_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL 7+
    "/etc/ssl/cert.pem",  # Alpine, BSD, macOS
)

# Trousseaux macOS : autorités publiques et autorités ajoutées (entreprise)
MACOS_KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)


def cache_dir():
    """
    Répertoire de cache de l'utilisateur pour IziProxy.

    Returns:
        str: ``%LOCALAPPDATA%\\iziproxy`` (Windows),
             ``~/Library/Caches/iziproxy`` (macOS),
             ``$XDG_CACHE_HOME/iziproxy`` ou ``~/.cache/iziproxy`` (ailleurs)
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "iziproxy")


def _certifi_pems():
    """Autorités de certifi (liste de Mozilla), ou chaîne vide."""
    try:
        import certifi
    except ImportError:
        return ""
    with open(certifi.where(), encoding="ascii", errors="ignore") as handle:
        return handle.read()


def _split_pems(text):
    """Découpe un texte PEM en certificats (blocs BEGIN/END CERTIFICATE)."""
    pems = []
    end = "-----END CERTIFICATE-----"
    for chunk in text.split(end)[:-1]:
        start = chunk.find("-----BEGIN CERTIFICATE-----")
        if start != -1:
            pems.append(chunk[start:].strip() + "\n" + end + "\n")
    return pems


def _enum_certificates(store):
    """Certificats d'un magasin Windows (ssl.enum_certificates)."""
    return ssl.enum_certificates(store)


def _windows_pems():
    """Autorités des magasins Windows ROOT et CA valables pour un serveur TLS."""
    pems = []
    for store in ("ROOT", "CA"):
        for cert, encoding, trust in _enum_certificates(store):
            if encoding != "x509_asn":
                continue
            # trust : True (tous usages) ou ensemble d'OID d'usages autorisés
            if trust is not True and SERVER_AUTH_OID not in trust:
                continue
            pems.append(ssl.DER_cert_to_PEM_cert(cert))
    return pems


def _macos_pems():
    """Autorités des trousseaux système de macOS."""
    pems = []
    for keychain in MACOS_KEYCHAINS:
        if not os.path.exists(keychain):
            continue
        result = subprocess.run(["security", "find-certificate", "-a", "-p", keychain],
                                capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            pems.extend(_split_pems(result.stdout))
    return pems


def _export(pems, path):
    """Écrit les certificats (sans doublon) dans path, de façon atomique."""
    unique = list(dict.fromkeys(pem.strip() + "\n" for pem in pems))
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ca-bundle-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as handle:
            handle.write("".join(unique))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    logger.debug("System CA bundle exported to %s (%d certificates)", path, len(unique))


def system_ca_bundle(max_age=MAX_AGE):
    """
    Fichier PEM des autorités de confiance du système.

    Windows et macOS : export du magasin du système (plus les autorités de
    certifi, pour qu'un site public reste accepté si le système n'a pas
    encore téléchargé sa racine) dans le cache de l'utilisateur, refait
    quand il a plus de ``max_age`` secondes. Linux : fichier de la
    distribution, sinon celui de certifi.

    Args:
        max_age (float): Âge maximal de l'export (secondes)

    Returns:
        str|None: Chemin du fichier, ou None si l'export a échoué (un
                  avertissement est journalisé)
    """
    try:
        if sys.platform not in ("win32", "darwin"):
            for candidate in (ssl.get_default_verify_paths().cafile,) + SYSTEM_BUNDLES:
                if candidate and os.path.isfile(candidate):
                    return candidate
            import certifi

            return certifi.where()

        path = os.path.join(cache_dir(), BUNDLE_NAME)
        try:
            if time.time() - os.path.getmtime(path) < max_age and os.path.getsize(path) > 0:
                return path
        except OSError:
            pass
        system = _windows_pems() if sys.platform == "win32" else _macos_pems()
        if not system:
            raise OSError("no certificate found in the system trust store")
        _export(system + _split_pems(_certifi_pems()), path)
        return path
    except Exception as exc:
        logger.warning("Could not export the system CA bundle, CA variables not set: %s", exc)
        return None


def _git_revoke_env(original):
    """
    Variables GIT_CONFIG_* qui ajoutent http.schannelCheckRevoke=best-effort
    à la suite de celles déjà définies ({} si l'utilisateur l'a déjà réglé
    ainsi ou si GIT_CONFIG_COUNT est invalide).
    """
    raw = original.get("GIT_CONFIG_COUNT")
    try:
        count = int(raw) if raw else 0
    except ValueError:
        count = -1
    if count < 0:
        logger.warning("Invalid GIT_CONFIG_COUNT %r: git revocation setting not added", raw)
        return {}
    for index in range(count):
        if (original.get(f"GIT_CONFIG_KEY_{index}") or "").lower() == GIT_REVOKE_KEY.lower():
            return {}
    return {
        "GIT_CONFIG_COUNT": str(count + 1),
        f"GIT_CONFIG_KEY_{count}": GIT_REVOKE_KEY,
        f"GIT_CONFIG_VALUE_{count}": GIT_REVOKE_VALUE,
    }


def tls_environment(verify=True, original=None):
    """
    Variables TLS à définir pour les sous-processus.

    Args:
        verify (bool|str): Option verify d'IziProxy. False : aucune variable
            d'autorités ; chemin : ce fichier (ou répertoire) plutôt que
            l'export du système
        original (Mapping): Valeurs des variables avant IziProxy (défaut :
            os.environ) ; une variable déjà définie n'est jamais remplacée

    Returns:
        dict: {nom: valeur} des variables à définir
    """
    original = os.environ if original is None else original
    values = {}
    if verify is not False:
        if isinstance(verify, str):
            names = CA_DIR_VARS if os.path.isdir(verify) else CA_FILE_VARS
        else:
            names = CA_FILE_VARS
        missing = [name for name in names if not original.get(name)]
        if missing:
            path = verify if isinstance(verify, str) else system_ca_bundle()
            if path:
                values.update(dict.fromkeys(missing, path))
    if sys.platform == "win32":
        values.update(_git_revoke_env(original))
    return values
