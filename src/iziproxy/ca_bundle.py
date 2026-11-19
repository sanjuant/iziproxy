"""
Export des autorités de confiance du système dans un fichier PEM.

Derrière un proxy d'entreprise qui inspecte le TLS, les sites présentent des
certificats signés par une autorité interne installée dans le magasin du
système. pip (option ``cert``) ne lit qu'un fichier PEM : ce module en écrit
un qui réunit les autorités de certifi (liste de Mozilla) et celles du
système (magasins Windows ROOT et CA, trousseaux macOS, fichier de la
distribution sous Linux).
"""

import os
import ssl
import subprocess
import sys
import tempfile

# Usage « authentification de serveur TLS » (extended key usage)
SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"

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

_BEGIN = "-----BEGIN CERTIFICATE-----"
_END = "-----END CERTIFICATE-----"


def split_pems(text):
    """Découpe un texte PEM en certificats (blocs BEGIN/END CERTIFICATE)."""
    pems = []
    for chunk in text.split(_END)[:-1]:
        start = chunk.find(_BEGIN)
        if start != -1:
            pems.append(chunk[start:].strip() + "\n" + _END + "\n")
    return pems


def _read(path):
    with open(path, encoding="ascii", errors="ignore") as handle:
        return handle.read()


def _certifi_pems():
    """Autorités de certifi (dépendance de requests), ou liste vide."""
    try:
        import certifi
    except ImportError:  # pragma: no cover - requests dépend de certifi
        return []
    return split_pems(_read(certifi.where()))


def _windows_pems():
    """Autorités des magasins Windows ROOT et CA valables pour un serveur TLS."""
    pems = []
    for store in ("ROOT", "CA"):
        for cert, encoding, trust in ssl.enum_certificates(store):
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
            pems.extend(split_pems(result.stdout))
    return pems


def _unix_pems():
    """Autorités du premier fichier de distribution trouvé."""
    for path in SYSTEM_BUNDLES:
        if os.path.isfile(path):
            return split_pems(_read(path))
    return []


def system_pems():
    """
    Autorités du magasin du système, au format PEM.

    Returns:
        list[str]: Un certificat PEM par élément (vide si rien n'est lisible)
    """
    if sys.platform == "win32":
        return _windows_pems()
    if sys.platform == "darwin":
        return _macos_pems()
    return _unix_pems()


def export_ca_bundle(path):
    """
    Écrit dans path les autorités de certifi et du système, sans doublon.

    L'écriture est atomique (fichier temporaire puis remplacement).

    Args:
        path (str): Fichier PEM à écrire (son répertoire est créé au besoin)

    Returns:
        int: Nombre de certificats écrits
    """
    unique = list(dict.fromkeys(pem.strip() + "\n" for pem in _certifi_pems() + system_pems()))
    directory = os.path.dirname(os.path.abspath(path))
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
    return len(unique)
