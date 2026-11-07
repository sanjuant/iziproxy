"""
Adaptateur requests qui choisit le proxy requête par requête.

requests applique le même dictionnaire de proxys à toutes les requêtes d'une
session et n'utilise la clé « no_proxy » que pour les variables
d'environnement. Cet adaptateur interroge IziProxy pour chaque URL, ce qui
permet de respecter les exclusions et les fichiers PAC.

Le type d'authentification n'est déterminé qu'à la première requête qui
passe réellement par le proxy : créer une session ne coûte rien.
"""

import threading

from requests.adapters import HTTPAdapter

from .proxy_utils import basic_proxy_authorization, is_https_proxy


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
        self._ntlm_generation = None
        self._lock = threading.Lock()

    def _ntlm(self):
        """
        Crée à la demande l'adaptateur NTLM partagé par la session (recréé
        après clear_auth_cache(), reset_credentials() ou refresh()).
        """
        with self._lock:
            generation = self.izi._auth_generation
            if self._ntlm_adapter is None or self._ntlm_generation != generation:
                if self._ntlm_adapter is not None:
                    self._ntlm_adapter.close()
                self._ntlm_adapter = self.izi._create_ntlm_adapter(**self._adapter_kwargs)
                self._ntlm_generation = generation
            return self._ntlm_adapter

    def proxy_headers(self, proxy):
        """
        En-têtes envoyés au proxy. requests encode les identifiants Basic en
        latin-1 ; on utilise UTF-8 (RFC 7617, navigateurs modernes) afin que
        les mots de passe accentués fonctionnent.
        """
        auth = basic_proxy_authorization(proxy)
        return {"Proxy-Authorization": auth} if auth else {}

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """
        Gestionnaire urllib3 du proxy. Pour un proxy https://, le certificat
        du proxy est vérifié selon ``verify`` d'IziProxy (autorités du
        système par défaut) et non selon le bundle certifi de requests.
        """
        if is_https_proxy(proxy) and "proxy_ssl_context" not in proxy_kwargs:
            proxy_kwargs["proxy_ssl_context"] = self.izi._proxy_ssl_context()
        return super().proxy_manager_for(proxy, **proxy_kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Envoie la requête avec le proxy déterminé pour son URL."""
        proxy, mode = self.izi._route(request.url)
        if mode == "ntlm":
            return self._ntlm().send(request, stream=stream, timeout=timeout,
                                     verify=verify, cert=cert)
        resolved = self.izi._resolve(request.url) if proxy else {}
        return super().send(request, stream=stream, timeout=timeout,
                            verify=verify, cert=cert, proxies=resolved)

    def close(self):
        super().close()
        if self._ntlm_adapter is not None:
            self._ntlm_adapter.close()
