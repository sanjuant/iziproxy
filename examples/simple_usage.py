"""
Exemple d'utilisation basique d'IziProxy
"""

from iziproxy import IziProxy
import requests

def main():
    """
    Démonstration des fonctionnalités de base d'IziProxy
    """
    print("Création d'une instance IziProxy avec détection automatique...")
    proxy = IziProxy(debug=True)
    
    print(f"\nEnvironnement détecté : {proxy.get_current_environment()}")
    
    # Méthode 1 : Utiliser une session requests préconfigurée
    print("\n--- Méthode 1 : Utiliser une session préconfigurée ---")
    session = proxy.create_session()
    try:
        response = session.get("https://httpbin.org/ip", timeout=5)
        print(f"Statut de la requête : {response.status_code}")
        print(f"Réponse : {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête : {e}")
    
    # Méthode 2 : Utiliser le dictionnaire de proxy
    print("\n--- Méthode 2 : Utiliser le dictionnaire de proxy ---")
    proxy_dict = proxy.get_proxy_dict()
    print(f"Dictionnaire de proxy : {proxy_dict}")
    
    try:
        response = requests.get("https://httpbin.org/headers", proxies=proxy_dict, timeout=5)
        print(f"Statut de la requête : {response.status_code}")
        print(f"En-têtes utilisés : {response.json().get('headers', {}).get('Via', 'Non détecté')}")
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête : {e}")
    
    # Méthode 3 : Utiliser les variables d'environnement
    print("\n--- Méthode 3 : Utiliser les variables d'environnement ---")
    proxy.set_environment_variables()
    
    try:
        # requests respecte les variables d'environnement par défaut
        response = requests.get("https://httpbin.org/get", timeout=5)
        print(f"Statut de la requête : {response.status_code}")
        print(f"Réponse reçue via proxy : {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête : {e}")
    finally:
        # Nettoyer les variables d'environnement
        proxy.clear_environment_variables()

if __name__ == "__main__":
    main()
