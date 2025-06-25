import getpass
import logging
import os
import platform
import sys
from typing import Optional, Tuple


class PasswordManager:
    """Gestionnaire de saisie de mot de passe adaptatif GUI/CLI intégré dans ConfigManager"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.is_gui_available = self._detect_gui_environment()

        if self.is_gui_available:
            self.logger.debug("Environnement GUI détecté")
        else:
            self.logger.debug("Environnement CLI détecté")

    def _detect_gui_environment(self) -> bool:
        """Détecte si on est dans un environnement GUI ou CLI"""

        # 1. Vérification PyInstaller (le plus fiable pour les apps empaquetées)
        if hasattr(sys, '_MEIPASS') or os.environ.get('_MEIPASS'):
            self.logger.debug("Application PyInstaller détectée")
            return True

        # 2. Vérification si on est en mode interactif Python
        if hasattr(sys, 'ps1'):  # Mode interactif Python
            self.logger.debug("Mode interactif Python détecté")
            return False

        # 3. Vérification si stdin est un TTY (terminal)
        if sys.stdin.isatty():
            self.logger.debug("Terminal TTY détecté")
            return False

        # 4. Vérification si on a un DISPLAY (Linux/macOS)
        if platform.system() in ['Linux', 'Darwin']:
            has_display = bool(os.environ.get('DISPLAY'))
            self.logger.debug(f"DISPLAY présent: {has_display}")
            return has_display

        # Par défaut, supposer environnement CLI
        return False

    def get_credentials_interactive(self, existing_username: str = None,
                                    existing_domain: str = None,
                                    auth_type: str = "basic",
                                    title: str = "IziProxy - Authentification Proxy") -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Récupère les credentials de manière interactive avec GUI/CLI adaptatif

        Args:
            existing_username: Nom d'utilisateur existant à préremplir
            existing_domain: Domaine existant à préremplir
            auth_type: Type d'authentification (basic, ntlm)
            title: Titre de la boîte de dialogue

        Returns:
            Tuple (username, password, domain)
        """
        self.logger.info("Demande interactive de credentials")

        if self.is_gui_available:
            return self._get_credentials_gui(title, existing_domain, existing_username, auth_type)
        else:
            return self._get_credentials_cli(existing_domain, existing_username, auth_type)

    def _get_credentials_gui(self, title: str,
                             existing_domain: str = None,
                             existing_username: str = None,
                             auth_type: str = "basic") -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Saisie complète des credentials en GUI avec préremplissage"""

        # 1. Essayer une boîte de dialogue complète Windows avec préremplissage
        if platform.system() == 'Windows':
            self.logger.debug("Tentative Windows Credential Manager")
            creds = self._get_credentials_windows_complete(title, existing_domain, existing_username, auth_type)
            if creds is not None:
                self.logger.info("Credentials saisies via Windows Credential Manager")
                return creds

        # 2. Essayer tkinter avec dialogue personnalisé prérempli
        self.logger.debug("Tentative tkinter")
        creds = self._get_credentials_tkinter_dialog(title, existing_domain, existing_username, auth_type)
        if creds is not None:
            self.logger.info("Credentials saisies via tkinter")
            return creds

        # 3. Fallback vers CLI avec préremplissage
        self.logger.warning("GUI non disponible, fallback vers CLI")
        print("Interface graphique non disponible, utilisation du mode console...")
        return self._get_credentials_cli(existing_domain, existing_username, auth_type)

    def _get_credentials_cli(self, existing_domain: str = None,
                             existing_username: str = None,
                             auth_type: str = "basic") -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Saisie complète des credentials en CLI avec préremplissage"""
        try:
            print("=== Configuration Proxy IziProxy ===")

            # Username avec valeur existante
            if existing_username:
                username_prompt = f"Nom d'utilisateur [{existing_username}]: "
                username_input = input(username_prompt).strip()
                username = username_input if username_input else existing_username
            else:
                username = input("Nom d'utilisateur pour le proxy: ").strip()
                if not username:
                    print("Le nom d'utilisateur est requis")
                    return None, None, None

            # Domaine avec valeur existante (seulement si NTLM)
            domain = None
            if auth_type.lower() == "ntlm":
                if existing_domain:
                    domain_prompt = f"Domaine [{existing_domain}]: "
                    domain_input = input(domain_prompt).strip()
                    domain = domain_input if domain_input else existing_domain
                else:
                    domain = input("Domaine pour l'authentification NTLM (vide si aucun): ").strip() or None

            # Password - toujours demandé pour sécurité
            password = getpass.getpass(f"Mot de passe pour {username}: ")
            if not password:
                print("Le mot de passe est requis")
                return None, None, None

            return username, password, domain

        except (KeyboardInterrupt, EOFError):
            print("\nOpération annulée")
            return None, None, None

    def _get_credentials_windows_complete(self, title: str,
                                          existing_domain: str = None,
                                          existing_username: str = None,
                                          auth_type: str = "basic") -> Optional[Tuple[str, str, str]]:
        """Utilise la boîte de dialogue Windows complète avec préremplissage"""
        if platform.system() != 'Windows':
            return None

        try:
            import ctypes
            from ctypes import wintypes

            class CREDUI_INFO(ctypes.Structure):
                _fields_ = [
                    ('cbSize', wintypes.DWORD),
                    ('hwndParent', wintypes.HWND),
                    ('pszMessageText', wintypes.LPCWSTR),
                    ('pszCaptionText', wintypes.LPCWSTR),
                    ('hbmBanner', wintypes.HBITMAP)
                ]

            credui = ctypes.windll.credui

            # Buffers avec préremplissage
            username_buffer = ctypes.create_unicode_buffer(512)
            password_buffer = ctypes.create_unicode_buffer(256)

            # Préremplir le nom d'utilisateur avec domaine si disponible et NTLM
            if existing_username:
                if existing_domain and auth_type.lower() == "ntlm":
                    prefilled_username = f"{existing_domain}\\{existing_username}"
                else:
                    prefilled_username = existing_username
                username_buffer.value = prefilled_username

            ui_info = CREDUI_INFO()
            ui_info.cbSize = ctypes.sizeof(CREDUI_INFO)
            ui_info.hwndParent = None

            if auth_type.lower() == "ntlm":
                ui_info.pszMessageText = "Entrez vos identifiants proxy (format: domaine\\utilisateur pour NTLM)"
            else:
                ui_info.pszMessageText = "Entrez vos identifiants proxy"

            ui_info.pszCaptionText = title
            ui_info.hbmBanner = None

            result = credui.CredUIPromptForCredentialsW(
                ctypes.byref(ui_info),
                None,
                None,
                0,
                username_buffer,
                512,
                password_buffer,
                256,
                None,
                0x20001  # CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX
            )

            if result == 0:
                full_username = username_buffer.value
                password = password_buffer.value

                # Parser domaine\utilisateur
                domain = None
                username = full_username

                if auth_type.lower() == "ntlm":
                    if '\\' in full_username:
                        domain, username = full_username.split('\\', 1)
                    elif '@' in full_username:
                        username, domain = full_username.split('@', 1)

                return username, password, domain
            else:
                return None

        except (ImportError, OSError, AttributeError) as e:
            self.logger.debug(f"Erreur Windows Credential Manager: {e}")
            return None

    def _get_credentials_tkinter_dialog(self, title: str,
                                        existing_domain: str = None,
                                        existing_username: str = None,
                                        auth_type: str = "basic") -> Optional[Tuple[str, str, str]]:
        """Dialogue tkinter personnalisé pour saisie complète avec préremplissage"""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox

            class CredentialsDialog:
                def __init__(self, parent, title, domain=None, username=None, auth_type="basic"):
                    self.result = None
                    self.auth_type = auth_type.lower()

                    self.dialog = tk.Toplevel(parent)
                    self.dialog.title(title)

                    # Ajuster la taille selon le type d'auth
                    if self.auth_type == "ntlm":
                        self.dialog.geometry("400x300")
                    else:
                        self.dialog.geometry("400x250")

                    self.dialog.resizable(False, False)
                    self.dialog.grab_set()

                    # Centrer la fenêtre
                    self.dialog.update_idletasks()
                    x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
                    y = ((self.dialog.winfo_screenheight() // 2) - (300 if self.auth_type == "ntlm" else 250) // 2)
                    self.dialog.geometry(f"400x{300 if self.auth_type == 'ntlm' else 250}+{x}+{y}")

                    # Valeurs initiales
                    self.initial_domain = domain or ""
                    self.initial_username = username or ""

                    self.create_widgets()

                def create_widgets(self):
                    # Frame principal
                    main_frame = ttk.Frame(self.dialog, padding="20")
                    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

                    # Titre de section
                    title_text = f"Configuration des identifiants proxy ({self.auth_type.upper()})"
                    title_label = ttk.Label(main_frame, text=title_text,
                                            font=('TkDefaultFont', 10, 'bold'))
                    title_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))

                    current_row = 1

                    # Domaine (seulement pour NTLM)
                    if self.auth_type == "ntlm":
                        ttk.Label(main_frame, text="Domaine:").grid(row=current_row, column=0, sticky=tk.W, pady=5)
                        self.domain_var = tk.StringVar(value=self.initial_domain)
                        self.domain_entry = ttk.Entry(main_frame, textvariable=self.domain_var, width=35)
                        self.domain_entry.grid(row=current_row, column=1, pady=5, padx=(10, 0), sticky=tk.W)
                        current_row += 1
                    else:
                        self.domain_var = tk.StringVar(value="")

                    # Username
                    ttk.Label(main_frame, text="Nom d'utilisateur:").grid(row=current_row, column=0, sticky=tk.W, pady=5)
                    self.username_var = tk.StringVar(value=self.initial_username)
                    self.username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=35)
                    self.username_entry.grid(row=current_row, column=1, pady=5, padx=(10, 0), sticky=tk.W)
                    current_row += 1

                    # Password
                    ttk.Label(main_frame, text="Mot de passe:").grid(row=current_row, column=0, sticky=tk.W, pady=5)
                    self.password_var = tk.StringVar()
                    self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=35)
                    self.password_entry.grid(row=current_row, column=1, pady=5, padx=(10, 0), sticky=tk.W)
                    current_row += 1

                    # Note d'aide
                    if self.auth_type == "ntlm":
                        help_text = "Authentification NTLM: le domaine est requis.\nLes champs sont préremplis avec les valeurs existantes."
                    else:
                        help_text = "Authentification basique.\nLes champs sont préremplis avec les valeurs existantes."

                    help_label = ttk.Label(main_frame, text=help_text,
                                           font=('TkDefaultFont', 8), foreground='gray')
                    help_label.grid(row=current_row, column=0, columnspan=2, pady=(10, 15))
                    current_row += 1

                    # Boutons
                    button_frame = ttk.Frame(main_frame)
                    button_frame.grid(row=current_row, column=0, columnspan=2, pady=10)

                    ttk.Button(button_frame, text="Valider", command=self.ok_clicked, width=12).pack(side=tk.LEFT, padx=5)
                    ttk.Button(button_frame, text="Annuler", command=self.cancel_clicked, width=12).pack(side=tk.LEFT, padx=5)

                    # Focus sur le premier champ vide
                    if self.auth_type == "ntlm" and not self.initial_domain:
                        self.domain_entry.focus()
                    elif not self.initial_username:
                        self.username_entry.focus()
                    else:
                        self.password_entry.focus()

                    # Bind Enter et Escape
                    self.dialog.bind('<Return>', lambda e: self.ok_clicked())
                    self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())

                def ok_clicked(self):
                    username = self.username_var.get().strip()
                    if not username:
                        messagebox.showerror("Erreur", "Le nom d'utilisateur est requis")
                        self.username_entry.focus()
                        return

                    password = self.password_var.get()
                    if not password:
                        messagebox.showerror("Erreur", "Le mot de passe est requis")
                        self.password_entry.focus()
                        return

                    domain = None
                    if self.auth_type == "ntlm":
                        domain = self.domain_var.get().strip() or None

                    self.result = (username, password, domain)
                    self.dialog.destroy()

                def cancel_clicked(self):
                    self.result = None
                    self.dialog.destroy()

            root = tk.Tk()
            root.withdraw()

            try:
                dialog = CredentialsDialog(root, title, existing_domain, existing_username, auth_type)
                root.wait_window(dialog.dialog)
                return dialog.result
            finally:
                root.destroy()

        except (ImportError, Exception) as e:
            self.logger.debug(f"Erreur tkinter: {e}")
            return None


