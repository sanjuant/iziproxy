"""
Configuration unique de git, curl et pip pour le proxy local (``iziproxy setup``).

IziProxy ne peut pas modifier l'environnement d'un terminal déjà ouvert : pour
que git, curl et pip passent par le proxy local lancé avec ``iziproxy serve``,
leur configuration utilisateur reçoit une fois pour toutes l'URL du proxy
local, jeton compris :

- git : ``http.proxy`` / ``https.proxy`` en configuration globale (et, sous
  Windows, ``http.schannelCheckRevoke=best-effort``) ;
- curl : ``proxy`` (et ``ssl-revoke-best-effort`` sous Windows) dans
  ``%APPDATA%\\_curlrc`` ou ``~/.curlrc`` ;
- pip : ``proxy`` et ``cert`` (export PEM du magasin du système) dans
  ``%APPDATA%\\pip\\pip.ini`` ou ``~/.config/pip/pip.conf``.

Seul le jeton du proxy local est écrit, jamais un mot de passe. Chaque valeur
ou fichier modifié est sauvegardé avant l'écriture (``setup-backup.json``
dans le répertoire de configuration d'IziProxy) : ``undo()`` les restaure.
"""

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

from .ca_bundle import export_ca_bundle
from .local_proxy import _TOKEN_RE, DEFAULT_PORT, LISTEN_HOST, TOKEN_USERNAME

TOOLS = ("git", "curl", "pip")

TOKEN_FILE = "local-proxy-token"
BACKUP_FILE = "setup-backup.json"
CA_FILE = "ca-bundle.pem"
# Suffixe de la copie d'un fichier modifié à la main après setup, faite par undo()
UNDO_COPY_SUFFIX = ".iziproxy-undo.bak"

GIT_PROXY_KEYS = ("http.proxy", "https.proxy")
GIT_REVOKE_KEY = "http.schannelCheckRevoke"
GIT_REVOKE_VALUE = "best-effort"

_MARKER = "# Added by 'iziproxy setup' (undo: iziproxy setup --undo)"
# Clés curl remplacées par setup (« x » : option courte -x de --proxy)
_CURL_PROXY_KEYS = {"proxy", "x"}
_CURL_REVOKE_KEY = "ssl-revoke-best-effort"
_INI_SECTION_RE = re.compile(r"^\s*\[([^\]]*)\]\s*$")


class SetupError(Exception):
    """Configuration impossible (git absent, fichier illisible...)."""


def _is_windows(windows):
    return sys.platform == "win32" if windows is None else windows


def _appdata():
    return os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")


def config_dir(windows=None):
    """
    Répertoire de configuration de l'utilisateur pour IziProxy.

    Returns:
        str: ``%APPDATA%\\iziproxy`` (Windows),
             ``~/Library/Application Support/iziproxy`` (macOS),
             ``$XDG_CONFIG_HOME/iziproxy`` ou ``~/.config/iziproxy`` (ailleurs)
    """
    if _is_windows(windows):
        base = _appdata()
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "iziproxy")


def curlrc_path(windows=None):
    """Fichier de configuration de curl : ``%APPDATA%\\_curlrc`` ou ``~/.curlrc``."""
    if _is_windows(windows):
        return os.path.join(_appdata(), "_curlrc")
    return os.path.join(os.path.expanduser("~"), ".curlrc")


def pip_config_path(windows=None):
    """Fichier de configuration de pip : ``%APPDATA%\\pip\\pip.ini`` ou ``~/.config/pip/pip.conf``."""
    if _is_windows(windows):
        return os.path.join(_appdata(), "pip", "pip.ini")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "pip", "pip.conf")


# ---------------------------------------------------------------------- #
# Fichiers
# ---------------------------------------------------------------------- #
def _read_text(path):
    """Contenu exact du fichier (fins de ligne comprises), None s'il n'existe pas."""
    try:
        with open(path, encoding="utf-8", newline="") as handle:
            return handle.read()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise SetupError(f"Cannot read {path}: {exc}") from exc


def _write_private(path, text):
    """
    Écrit text dans path de façon atomique.

    Sous Linux et macOS, le fichier n'est lisible que par l'utilisateur
    (mkstemp crée en 0600) ; sous Windows, le profil de l'utilisateur
    (%APPDATA%) est déjà réservé à son propriétaire.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iziproxy-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _newline(text):
    return "\r\n" if text and "\r\n" in text else "\n"


def _lines_with_end(text):
    """Lignes de text, la dernière terminée par un saut de ligne."""
    lines = (text or "").splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += _newline(text)
    return lines


# ---------------------------------------------------------------------- #
# Jeton du proxy local
# ---------------------------------------------------------------------- #
def token_path(windows=None):
    """Fichier du jeton fixe du proxy local."""
    return os.path.join(config_dir(windows), TOKEN_FILE)


def load_token(windows=None):
    """
    Jeton fixe du proxy local, généré au premier appel.

    Le fichier est créé lisible par l'utilisateur seul (0600 sous Linux et
    macOS ; profil réservé sous Windows). Les droits trop larges d'un fichier
    existant sont resserrés.

    Returns:
        str: Jeton (16 caractères ou plus parmi lettres, chiffres et ``._~-``)

    Raises:
        SetupError: Fichier de jeton illisible ou invalide
    """
    path = token_path(windows)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    token = secrets.token_urlsafe(24)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Déjà généré (éventuellement à l'instant par un autre processus)
        token = (_read_text(path) or "").strip()
        if not _TOKEN_RE.fullmatch(token):
            raise SetupError(f"Invalid local proxy token in {path}: delete the file to generate a new one")
        if os.name == "posix" and os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o600)
        return token
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(token + "\n")
    return token


def local_proxy_url(token, port=DEFAULT_PORT):
    """URL du proxy local, jeton compris."""
    return f"http://{TOKEN_USERNAME}:{token}@{LISTEN_HOST}:{port}"


# ---------------------------------------------------------------------- #
# git
# ---------------------------------------------------------------------- #
def _git_available():
    return shutil.which("git") is not None


def _git(*args):
    try:
        return subprocess.run(["git", "config", "--global", *args],
                              capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError as exc:
        raise SetupError("git is not installed or not in PATH") from exc


def _git_get(key):
    """Valeur globale de key, None si elle n'est pas définie."""
    result = _git("--get", key)
    if result.returncode == 0:
        return result.stdout.rstrip("\r\n")
    if result.returncode == 1:
        return None
    raise SetupError(f"git config --global --get {key} failed: {result.stderr.strip()}")


def _git_set(key, value):
    result = _git(key, value)
    if result.returncode != 0:
        raise SetupError(f"git config --global {key} failed: {result.stderr.strip()}")


def _git_unset(key):
    result = _git("--unset-all", key)
    # 5 : la clé n'existe pas (déjà retirée)
    if result.returncode not in (0, 5):
        raise SetupError(f"git config --global --unset-all {key} failed: {result.stderr.strip()}")


# ---------------------------------------------------------------------- #
# Édition des fichiers de configuration
# ---------------------------------------------------------------------- #
def _curl_key(line):
    """Nom de l'option d'une ligne de .curlrc (sans tirets), None pour un commentaire."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    return re.split(r"[\s=:]", stripped.lstrip("-"), maxsplit=1)[0].lower()


def update_curlrc(text, proxy_url, revoke_best_effort):
    """
    Contenu de .curlrc avec le proxy local.

    Les options ``proxy`` / ``-x`` existantes (et ``ssl-revoke-best-effort``
    si on l'ajoute) sont retirées, le reste est conservé tel quel.
    """
    replaced = set(_CURL_PROXY_KEYS)
    settings = [f'proxy = "{proxy_url}"']
    if revoke_best_effort:
        replaced.add(_CURL_REVOKE_KEY)
        settings.append(_CURL_REVOKE_KEY)
    newline = _newline(text)
    lines = [line for line in _lines_with_end(text)
             if _curl_key(line) not in replaced and line.strip() != _MARKER]
    if lines and lines[-1].strip():
        lines.append(newline)
    lines += [line + newline for line in [_MARKER] + settings]
    return "".join(lines)


def update_ini(text, section, values):
    """
    Contenu d'un fichier INI dont la section reçoit values.

    Les clés de values déjà présentes dans la section sont remplacées ; les
    autres lignes (commentaires compris) sont conservées.
    """
    newline = _newline(text)
    lines = _lines_with_end(text)
    keys = {key.lower() for key in values}
    settings = [f"{key} = {value}{newline}" for key, value in values.items()]
    start = next((i for i, line in enumerate(lines)
                  if (m := _INI_SECTION_RE.match(line)) and m.group(1).strip() == section), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append(newline)
        return "".join(lines + [f"[{section}]{newline}"] + settings)
    end = next((i for i in range(start + 1, len(lines)) if _INI_SECTION_RE.match(lines[i])), len(lines))
    body = [line for line in lines[start + 1:end]
            if re.split(r"[=:]", line, maxsplit=1)[0].strip().lower() not in keys]
    return "".join(lines[:start + 1] + settings + body + lines[end:])


# ---------------------------------------------------------------------- #
# Plan, application, restauration
# ---------------------------------------------------------------------- #
class Change:
    """
    Modification prévue par setup.

    Attributs : ``tool`` (git, curl, pip), ``kind`` (``git`` : clé de la
    configuration globale ; ``file`` : fichier entier ; ``ca`` : export PEM),
    ``target`` (clé ou chemin), ``value`` (nouvelle valeur ou contenu),
    ``summary`` (lignes à afficher, jeton masqué).
    """

    def __init__(self, tool, kind, target, value, summary):
        self.tool = tool
        self.kind = kind
        self.target = target
        self.value = value
        self.summary = summary

    def __repr__(self):
        return f"Change({self.tool!r}, {self.kind!r}, {self.target!r})"


def plan(port=DEFAULT_PORT, tools=TOOLS, token=None, windows=None):
    """
    Modifications que setup ferait, sans rien écrire.

    Args:
        port (int): Port du proxy local (celui de ``iziproxy serve``)
        tools (iterable): Outils à configurer parmi git, curl, pip
        token (str): Jeton du proxy local (None : load_token(), créé au besoin)
        windows (bool): Forcer les réglages Windows (None : système courant)

    Returns:
        tuple[list[Change], list[str]]: Modifications et outils ignorés (avec la raison)
    """
    windows = _is_windows(windows)
    unknown = set(tools) - set(TOOLS)
    if unknown:
        raise ValueError(f"Unknown tool(s): {', '.join(sorted(unknown))} (choose among {', '.join(TOOLS)})")
    token = token or load_token(windows)
    url = local_proxy_url(token, port)
    shown = url.replace(token, "***")
    changes, skipped = [], []

    if "git" in tools:
        if not _git_available():
            skipped.append("git: not found in PATH")
        else:
            for key in GIT_PROXY_KEYS:
                changes.append(Change("git", "git", key, url, [f"{key} = {shown}"]))
            if windows:
                changes.append(Change("git", "git", GIT_REVOKE_KEY, GIT_REVOKE_VALUE,
                                      [f"{GIT_REVOKE_KEY} = {GIT_REVOKE_VALUE}"]))

    if "curl" in tools:
        path = curlrc_path(windows)
        content = update_curlrc(_read_text(path), url, windows)
        summary = [f'proxy = "{shown}"'] + ([_CURL_REVOKE_KEY] if windows else [])
        changes.append(Change("curl", "file", path, content, summary))

    if "pip" in tools:
        ca_path = os.path.join(config_dir(windows), CA_FILE)
        changes.append(Change("pip", "ca", ca_path, None, ["export of the system certificate store (PEM)"]))
        path = pip_config_path(windows)
        content = update_ini(_read_text(path), "global", {"proxy": url, "cert": ca_path})
        summary = [f"[global] proxy = {shown}", f"[global] cert = {ca_path}"]
        changes.append(Change("pip", "file", path, content, summary))

    return changes, skipped


def backup_path(windows=None):
    """Fichier de sauvegarde des valeurs d'origine."""
    return os.path.join(config_dir(windows), BACKUP_FILE)


def _load_backup(windows=None):
    text = _read_text(backup_path(windows))
    if text is None:
        return []
    try:
        entries = json.loads(text)["entries"]
    except (ValueError, KeyError, TypeError) as exc:
        raise SetupError(f"Corrupted backup file {backup_path(windows)}: {exc}") from exc
    return entries


def _save_backup(entries, windows=None):
    path = backup_path(windows)
    if not entries:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return
    # Peut contenir l'ancien contenu des fichiers (identifiants éventuels) : 0600
    _write_private(path, json.dumps({"version": 1, "entries": entries}, indent=2))


def apply(changes, windows=None):
    """
    Applique les modifications après avoir sauvegardé chaque valeur d'origine.

    La sauvegarde garde la valeur d'avant le PREMIER setup : relancer setup
    (autre port, autre outil) ne l'écrase pas, undo revient bien à l'état
    initial.

    Args:
        changes (list[Change]): Résultat de plan()
        windows (bool): Comme pour plan()
    """
    entries = _load_backup(windows)
    for change in changes:
        entry = next((e for e in entries if e["kind"] == change.kind and e["target"] == change.target), None)
        if entry is None:
            original = _git_get(change.target) if change.kind == "git" else _read_text(change.target)
            entry = {"tool": change.tool, "kind": change.kind, "target": change.target, "original": original}
            entries.append(entry)
        # Sauvegarde AVANT l'écriture : un échec en cours de route reste annulable
        _save_backup(entries, windows)
        if change.kind == "git":
            _git_set(change.target, change.value)
        elif change.kind == "ca":
            export_ca_bundle(change.target)
        else:
            _write_private(change.target, change.value)
            entry["written"] = change.value
    _save_backup(entries, windows)


def has_backup(windows=None):
    """True si un setup peut être annulé."""
    return bool(_load_backup(windows))


def undo(tools=TOOLS, windows=None):
    """
    Restaure les valeurs et fichiers d'avant setup.

    Un fichier modifié à la main depuis setup est d'abord copié à côté
    (suffixe ``.iziproxy-undo.bak``) avant d'être restauré.

    Args:
        tools (iterable): Outils à restaurer parmi git, curl, pip
        windows (bool): Comme pour plan()

    Returns:
        list[str]: Ce qui a été restauré (une ligne par valeur ou fichier)
    """
    entries = _load_backup(windows)
    done = []
    for entry in reversed(list(entries)):
        if entry["tool"] not in tools:
            continue
        kind, target, original = entry["kind"], entry["target"], entry["original"]
        if kind == "git":
            if original is None:
                _git_unset(target)
            else:
                _git_set(target, original)
            done.append(f"git {target}: " + ("removed" if original is None else "restored"))
        else:
            current = _read_text(target)
            if kind == "file" and current is not None and current != entry.get("written"):
                shutil.copyfile(target, target + UNDO_COPY_SUFFIX)
                done.append(f"{target}: edited since setup, copy kept in {target + UNDO_COPY_SUFFIX}")
            if original is None:
                if current is not None:
                    os.remove(target)
                done.append(f"{target}: removed")
            else:
                _write_private(target, original)
                done.append(f"{target}: restored")
        entries.remove(entry)
        _save_backup(entries, windows)
    return done
