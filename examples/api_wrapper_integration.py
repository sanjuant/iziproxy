"""
Exemple d'intégration d'IziProxy avec un wrapper d'API qui utilise requests

Ce script montre comment utiliser IziProxy avec une API tierce
qui utilise requests en interne, sans avoir besoin de modifier son code source.
"""

import json
import requests
from iziproxy import IziProxy

# Simulation d'une API tierce qui utilise requests en interne
class MockThirdPartyAPI:
    """Simulation d'une API tierce qui utilise requests"""
    
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
    
    def find_resources(self, query_params):
        """Cette méthode utilise requests.get en interne"""
        url = f"{self.base_url}/resources"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        # Cette ligne va utiliser requests.get, qui sera patché
        response = requests.get(url, params=query_params, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Erreur: {response.status_code}")
            return None

# Notre wrapper client qui intègre IziProxy
class APIClient:
    """Client pour interagir avec l'API tierce via proxy"""
    
    def __init__(self):
        # Configuration
        self.api_key = "your-api-key"
        self.api_url = "https://httpbin.org"  # Pour test
        
        # Obtention d'une session préconfigurée avec IziProxy
        self.proxy = IziProxy(debug=True)
        self.session = self.proxy.create_session()

        # Monkey patch requests methods avec notre session
        self._patch_requests()

        # Important: l'API est initialisée APRÈS le monkey patching
        self.api = None
        self._initialize_api()
    
    def _initialize_api(self):
        """Initialise l'API tierce"""
        self.api = MockThirdPartyAPI(
            self.api_url,
            self.api_key
        )

    def _patch_requests(self):
        """Remplace les méthodes du module requests par celles de notre session"""
        # Conserver les références aux méthodes originales
        self.original_get = requests.get
        self.original_post = requests.post
        
        # Remplacer les méthodes par celles de notre session préconfigurée
        requests.get = self.session.get
        requests.post = self.session.post
        requests.put = self.session.put
        requests.patch = self.session.patch
        requests.delete = self.session.delete
        
        print("Module requests patché avec notre session IziProxy")
    
    def restore_requests(self):
        """Restaure les méthodes originales du module requests"""
        # Cette fonction est optionnelle, mais recommandée pour le nettoyage
        requests.get = self.original_get
        requests.post = self.original_post
        print("Module requests restauré à son état original")
    
    def find_resources(self, query_params):
        """Recherche des ressources via l'API"""
        # Cette méthode appelle l'API tierce, qui utilisera requests patché
        return self.api.find_resources(query_params)

def main():
    """Fonction principale de démonstration"""
    print("DÉMONSTRATION D'INTÉGRATION AVEC UN WRAPPER D'API")
    print("================================================")
    
    # Créer notre client API qui intègre IziProxy
    client = APIClient()
    
    # Effectuer une requête via l'API
    print("\nRecherche de ressources via l'API tierce...")
    result = client.find_resources({"param1": "value1", "param2": "value2"})
    
    if result:
        print("\nRésultat de la requête:")
        print(json.dumps(result, indent=2))
        
        # Vérifier si les headers contiennent des informations sur le proxy utilisé
        if 'headers' in result:
            proxy_headers = [h for h in result['headers'] if 'proxy' in h.lower()]
            if proxy_headers:
                print("\nEn-têtes liés au proxy détectés:")
                for header in proxy_headers:
                    print(f"  - {header}: {result['headers'][header]}")
            else:
                print("\nAucun en-tête lié au proxy détecté, mais la requête a bien été " + 
                      "routée via notre session IziProxy configurée")
    
    # Restaurer les méthodes originales pour nettoyer
    client.restore_requests()
    
    print("\nCOMMENT ÇA FONCTIONNE ?")
    print("======================")
    print("1. Nous créons une session préconfigurée avec IziProxy")
    print("2. Nous remplaçons les méthodes de requests par celles de notre session")
    print("3. L'API tierce utilise requests.get(), qui est maintenant notre session.get()")
    print("4. Résultat: l'API tierce utilise notre configuration de proxy sans le savoir!")

if __name__ == "__main__":
    main()
