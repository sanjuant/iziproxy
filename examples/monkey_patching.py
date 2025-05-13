"""
Exemple d'utilisation du monkey patching d'IziProxy
"""

import requests
import os
from iziproxy import IziProxy

def show_request_info(description):
    """Affiche des informations sur une requête pour démonstration"""
    print(f"\n--- {description} ---")
    try:
        # Cette requête utilisera le proxy configuré ou non selon le contexte
        response = requests.get("https://httpbin.org/ip", timeout=5)
        print(f"Statut: {response.status_code}")
        print(f"IP vue par le serveur: {response.json().get('origin', 'inconnu')}")
        print(f"Headers utilisés: {response.request.headers.get('User-Agent', 'standard')}")
        
        # Vérifier si un proxy est utilisé en recherchant des en-têtes spécifiques
        proxy_headers = [h for h in response.headers.keys() if 'proxy' in h.lower()]
        if proxy_headers:
            print(f"En-têtes liés au proxy: {proxy_headers}")
        else:
            print("Aucun en-tête lié au proxy détecté")
    except Exception as e:
        print(f"Erreur lors de la requête: {e}")

def main():
    """Fonction principale pour la démonstration"""
    print("DÉMONSTRATION DU MONKEY PATCHING")
    print("================================")
    print("Cette technique permet de remplacer les méthodes du module requests")
    print("pour qu'elles utilisent automatiquement la configuration proxy.")
    
    # Effectuer une requête standard pour référence
    show_request_info("Sans IziProxy")
    
    # Créer une instance IziProxy
    print("\nCréation d'une instance IziProxy...")
    proxy = IziProxy(debug=True)
    
    # Montrer qu'à ce stade, requests standard n'est pas affecté
    show_request_info("Avec IziProxy créé mais sans patch")
    
    # Appliquer le monkey patching
    print("\nApplication du monkey patching...")
    proxy.patch_requests()
    
    # Montrer que maintenant, requests utilise le proxy
    show_request_info("Après monkey patching")
    
    # Restaurer requests à son état original
    print("\nRestauration de requests à son état original...")
    proxy.unpatch_requests()
    
    # Vérifier que requests est revenu à son comportement normal
    show_request_info("Après restauration")
    
    print("\n=== Avantages du monkey patching ===")
    print("1. Permet d'utiliser IziProxy avec des bibliothèques tierces")
    print("2. Simplifie l'intégration dans du code existant")
    print("3. Une seule ligne de code suffit pour configurer tout un projet")
    
    print("\n=== Utilisation typique ===")
    print("# Au début de votre programme:")
    print("from iziproxy import IziProxy")
    print("IziProxy().patch_requests()")
    print("# À partir de ce point, toutes les requêtes utilisent le proxy automatiquement")

if __name__ == "__main__":
    main()
