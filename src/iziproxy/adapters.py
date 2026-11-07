"""
Adaptateur requests qui choisit le proxy requête par requête.

requests applique le même dictionnaire de proxys à toutes les requêtes d'une
session et n'utilise la clé « no_proxy » que pour les variables
d'environnement. Cet adaptateur interroge IziProxy pour chaque URL, ce qui
permet de respecter les exclusions et les fichiers PAC.

Le type d'authentification n'est déterminé qu'à la première requête qui
passe réellement par le proxy : créer une session ne coûte rien.
"""

import base64
import threading

from requests.adapters import HTTPAdapter

from .proxy_utils import extract_credentials


class IziProxyAdapter(HTTPAdapter):
    """
    Adaptateur HTTP piloté par une instance IziProxy.

    - Hôte exclu ou pas de proxy : connexion directe
    - Proxy sans authentification ou Basic : l'authentification est portée
      par l'URL du proxy ; urllib3 n'envoie alors Proxy-Authorization qu'au
      proxy (dans la requête CONNECT pour HTTPS), jamais au site cible
    - Proxy NTLM / Negotiate : délégation à NtlmProxyAdapter
    """

    def __init__(self, izi, **kwargs):
        """
        Args:
            izi (IziProxy): Instance qui fournit la configuration
        """
        self._adapter_kwargs = dict(kwargs)
        super().__init__(**kwargs)
        self.izi = izi
        self._ntlm_adapter = None
        self._lock = threading.Lock()

    def _ntlm(self):
        """Crée à la demande l'adaptateur NTLM partagé par la session."""
        with self._lock:
            if self._ntlm_adapter is None:
                self._ntlm_adapter = self.izi._create_ntlm_adapter(**self._adapter_kwargs)
            return self._ntlm_adapter

    def proxy_headers(self, proxy):
        """
        En-têtes envoyés au proxy. requests encode les identifiants Basic en
        latin-1 ; on utilise UTF-8 (RFC 7617, navigateurs modernes) afin que
        les mots de passe accentués fonctionnent.
        """
        headers = {}
        username, password = extract_credentials(proxy)
        if username:
            token = f"{username}:{password or ''}".encode("utf-8")
            headers["Proxy-Authorization"] = "Basic " + base64.b64encode(token).decode("ascii")
        return headers

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Envoie la requête avec le proxy déterminé pour son URL."""
        raw = self.izi._raw_proxies(request.url)
        if raw and self.izi._uses_ntlm():
            return self._ntlm().send(request, stream=stream, timeout=timeout,
                                     verify=verify, cert=cert)
        resolved = self.izi._resolve(request.url) if raw else {}
        return super().send(request, stream=stream, timeout=timeout,
                            verify=verify, cert=cert, proxies=resolved)

    def close(self):
        super().close()
        if self._ntlm_adapter is not None:
            self._ntlm_adapter.close()
