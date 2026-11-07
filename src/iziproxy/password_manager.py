"""
Saisie interactive des identifiants du proxy : fenêtre Windows native,
fenêtre tkinter ou console selon le contexte d'exécution.
"""

import getpass
import logging
import os
import platform
import sys
from typing import Optional, Tuple

Credentials = Tuple[Optional[str], Optional[str], Optional[str]]

# Valeur renvoyée par un dialogue lorsque l'utilisateur annule (≠ dialogue indisponible)
CANCELLED = object()

# Indicateurs de CredUIPromptForCredentialsW
CREDUI_FLAGS_DO_NOT_PERSIST = 0x00002
CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x00080
CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000
ERROR_CANCELLED = 1223


class PasswordManager:
    """Choisit et affiche le moyen de saisie adapté (GUI ou console)."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("iziproxy")
        self.is_gui_available = self._detect_gui_environment()
        self.logger.debug("Credential prompt mode: %s", "GUI" if self.is_gui_available else "CLI")

    def _detect_gui_environment(self) -> bool:
        """Détecte si l'application tourne sans console (GUI)."""
        # Application empaquetée (PyInstaller) : généralement sans console
        if getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"):
            return True

        # Session Python interactive ou terminal : rester en console
        if hasattr(sys, "ps1"):
            return False
        stdin = sys.stdin
        try:
            if stdin is not None and stdin.isatty():
                return False
        except (AttributeError, ValueError):
            pass

        # pythonw.exe : pas de flux standard
        if stdin is None or sys.stdout is None:
            return True

        if platform.system() in ("Linux", "Darwin"):
            return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) \
                or platform.system() == "Darwin"
        return platform.system() == "Windows"

    def get_credentials_interactive(self, existing_username: str = None,
                                    existing_domain: str = None,
                                    auth_type: str = "basic",
                                    title: str = "IziProxy - Proxy authentication") -> Credentials:
        """
        Demande les identifiants à l'utilisateur.

        Returns:
            tuple: (username, password, domain) ; (None, None, None) si annulé
        """
        auth_type = (auth_type or "basic").lower()
        if self.is_gui_available:
            return self._get_credentials_gui(title, existing_domain, existing_username, auth_type)
        return self._get_credentials_cli(existing_domain, existing_username, auth_type)

    def _get_credentials_gui(self, title, existing_domain=None, existing_username=None,
                             auth_type="basic") -> Credentials:
        """Essaie la fenêtre Windows, puis tkinter, puis la console."""
        dialogs = []
        if platform.system() == "Windows":
            dialogs.append(self._get_credentials_windows_complete)
        dialogs.append(self._get_credentials_tkinter_dialog)

        for dialog in dialogs:
            creds = dialog(title, existing_domain, existing_username, auth_type)
            if creds is CANCELLED:
                return None, None, None
            if creds is not None:
                return creds

        self.logger.warning("No graphical prompt available, falling back to the console")
        return self._get_credentials_cli(existing_domain, existing_username, auth_type)

    def _get_credentials_cli(self, existing_domain=None, existing_username=None,
                             auth_type="basic") -> Credentials:
        """Saisie en console (valeurs existantes proposées par défaut)."""
        try:
            print("=== IziProxy - proxy authentication ===", file=sys.stderr)

            if existing_username:
                username = input(f"Username [{existing_username}]: ").strip() or existing_username
            else:
                username = input("Proxy username: ").strip()
            if not username:
                print("A username is required", file=sys.stderr)
                return None, None, None

            domain = None
            if auth_type == "ntlm":
                if existing_domain:
                    domain = input(f"Domain [{existing_domain}]: ").strip() or existing_domain
                else:
                    domain = input("NTLM domain (empty if none): ").strip() or None

            password = getpass.getpass(f"Password for {username}: ")
            if not password:
                print("A password is required", file=sys.stderr)
                return None, None, None
            return username, password, domain
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled", file=sys.stderr)
            return None, None, None

    @staticmethod
    def _split_domain(full_username, auth_type):
        """Sépare DOMAINE\\utilisateur ou utilisateur@domaine pour NTLM."""
        if auth_type == "ntlm":
            if "\\" in full_username:
                domain, username = full_username.split("\\", 1)
                return username, domain
            if "@" in full_username:
                username, domain = full_username.split("@", 1)
                return username, domain
        return full_username, None

    def _get_credentials_windows_complete(self, title, existing_domain=None,
                                          existing_username=None, auth_type="basic"):
        """
        Fenêtre d'identification native de Windows (CredUI).

        Returns:
            tuple|CANCELLED|None: identifiants, annulation, ou None si indisponible
        """
        if platform.system() != "Windows":
            return None
        try:
            import ctypes
            from ctypes import wintypes

            class CREDUI_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("hwndParent", wintypes.HWND),
                    ("pszMessageText", wintypes.LPCWSTR),
                    ("pszCaptionText", wintypes.LPCWSTR),
                    ("hbmBanner", wintypes.HBITMAP),
                ]

            prompt = ctypes.windll.credui.CredUIPromptForCredentialsW
            prompt.argtypes = [
                ctypes.POINTER(CREDUI_INFO), wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD,
                wintypes.LPWSTR, wintypes.ULONG, wintypes.LPWSTR, wintypes.ULONG,
                ctypes.POINTER(wintypes.BOOL), wintypes.DWORD,
            ]
            prompt.restype = wintypes.DWORD

            username_buffer = ctypes.create_unicode_buffer(514)
            password_buffer = ctypes.create_unicode_buffer(257)
            if existing_username:
                if existing_domain and auth_type == "ntlm":
                    username_buffer.value = f"{existing_domain}\\{existing_username}"
                else:
                    username_buffer.value = existing_username

            info = CREDUI_INFO()
            info.cbSize = ctypes.sizeof(CREDUI_INFO)
            info.hwndParent = None
            info.pszMessageText = ("Enter your proxy credentials (DOMAIN\\user)"
                                   if auth_type == "ntlm" else "Enter your proxy credentials")
            info.pszCaptionText = title
            info.hbmBanner = None

            save = wintypes.BOOL(False)
            flags = (CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI
                     | CREDUI_FLAGS_DO_NOT_PERSIST)
            result = prompt(ctypes.byref(info), "IziProxy", None, 0,
                            username_buffer, 513, password_buffer, 256, ctypes.byref(save), flags)

            if result == ERROR_CANCELLED:
                return CANCELLED
            if result != 0:
                self.logger.debug("CredUIPromptForCredentialsW failed with code %s", result)
                return None

            username, domain = self._split_domain(username_buffer.value, auth_type)
            password = password_buffer.value
            # Effacer le mot de passe du tampon natif
            ctypes.memset(password_buffer, 0, ctypes.sizeof(password_buffer))
            return username, password, domain
        except (ImportError, OSError, AttributeError) as exc:
            self.logger.debug("Windows credential prompt unavailable: %s", exc)
            return None

    def _get_credentials_tkinter_dialog(self, title, existing_domain=None,
                                        existing_username=None, auth_type="basic"):
        """
        Fenêtre tkinter.

        Returns:
            tuple|CANCELLED|None: identifiants, annulation, ou None si indisponible
        """
        try:
            import tkinter as tk
            from tkinter import messagebox, ttk
        except ImportError:
            return None

        try:
            root = tk.Tk()
        except Exception as exc:  # pas d'affichage disponible
            self.logger.debug("tkinter unavailable: %s", exc)
            return None

        result = {"value": CANCELLED}
        try:
            root.title(title)
            root.resizable(False, False)
            root.attributes("-topmost", True)

            frame = ttk.Frame(root, padding=20)
            frame.grid(row=0, column=0, sticky="nsew")
            ttk.Label(frame, text=f"Proxy credentials ({auth_type.upper()})",
                      font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 15))

            row = 1
            domain_var = tk.StringVar(value=existing_domain or "")
            domain_entry = None
            if auth_type == "ntlm":
                ttk.Label(frame, text="Domain:").grid(row=row, column=0, sticky="w", pady=5)
                domain_entry = ttk.Entry(frame, textvariable=domain_var, width=35)
                domain_entry.grid(row=row, column=1, pady=5, padx=(10, 0))
                row += 1

            ttk.Label(frame, text="Username:").grid(row=row, column=0, sticky="w", pady=5)
            username_var = tk.StringVar(value=existing_username or "")
            username_entry = ttk.Entry(frame, textvariable=username_var, width=35)
            username_entry.grid(row=row, column=1, pady=5, padx=(10, 0))
            row += 1

            ttk.Label(frame, text="Password:").grid(row=row, column=0, sticky="w", pady=5)
            password_var = tk.StringVar()
            password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=35)
            password_entry.grid(row=row, column=1, pady=5, padx=(10, 0))
            row += 1

            def submit(_event=None):
                username = username_var.get().strip()
                password = password_var.get()
                if not username:
                    messagebox.showerror("Error", "A username is required", parent=root)
                    username_entry.focus_set()
                    return
                if not password:
                    messagebox.showerror("Error", "A password is required", parent=root)
                    password_entry.focus_set()
                    return
                domain = domain_var.get().strip() or None if auth_type == "ntlm" else None
                result["value"] = (username, password, domain)
                root.destroy()

            def cancel(_event=None):
                result["value"] = CANCELLED
                root.destroy()

            buttons = ttk.Frame(frame)
            buttons.grid(row=row, column=0, columnspan=2, pady=(15, 0))
            ttk.Button(buttons, text="OK", command=submit, width=12).pack(side="left", padx=5)
            ttk.Button(buttons, text="Cancel", command=cancel, width=12).pack(side="left", padx=5)

            root.bind("<Return>", submit)
            root.bind("<Escape>", cancel)
            root.protocol("WM_DELETE_WINDOW", cancel)

            # Placer le curseur sur le premier champ vide
            if domain_entry is not None and not existing_domain:
                domain_entry.focus_set()
            elif not existing_username:
                username_entry.focus_set()
            else:
                password_entry.focus_set()

            root.update_idletasks()
            x = (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2
            y = (root.winfo_screenheight() - root.winfo_reqheight()) // 2
            root.geometry(f"+{x}+{y}")
            root.mainloop()
        except Exception as exc:
            self.logger.debug("tkinter prompt failed: %s", exc)
            try:
                root.destroy()
            except Exception:
                pass
            return None
        return result["value"]
