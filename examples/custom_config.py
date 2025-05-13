"""
Exemple d'utilisation d'IziProxy avec une configuration personnalisée
"""

from iziproxy import IziProxy
import os
import sys

# Ajouter le répertoire parent au PATH pour pouvoir exécuter depuis le répertoire examples
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def example_1_config_file():
    """Exemple d'utilisation avec un fichier de configuration"""
    print("\n=== Exemple 1: Utilisation avec un fichier de configuration ===")
    
    # Chemin vers le fichier de configuration
    config_path = os.path.join(os.path.dirname(__file__), "config_example.yml")
    
    # Créer une instance avec un fichier de configuration
    proxy = IziProxy(config_path=config_path, debug=True)
    
    print(f"Environnement détecté : {proxy.get_current_environment()}")
    print(f"Configuration proxy : {proxy.get_proxy_dict()}")
    
    # Créer une session et faire une requête
    session = proxy.create_session()
    
    print("Exécution d'une requête...")
    try:
        response = session.get("https://httpbin.org/ip", timeout=5)
        print(f"Statut : {response.status_code}")
        print(f"Réponse : {response.json()}")
    except Exception as e:
        print(f"Erreur : {e}")


def example_2_explicit_config():
    """Exemple d'utilisation avec une configuration explicite"""
    print("\n=== Exemple 2: Configuration explicite ===")
    
    # Créer une instance avec des paramètres explicites
    proxy = IziProxy(
        proxy_url="http://proxy.example.com:8080",
        username="user",
        password="pass",
        environment="prod",
        debug=True
    )
    
    print(f"Environnement forcé : {proxy.get_current_environment()}")
    print(f"Configuration proxy : {proxy.get_proxy_dict()}")
    
    # En environnement réel, la requête échouerait avec ce proxy fictif
    print("Notez que cette configuration utilise un proxy fictif pour l'exemple.")


def example_3_environment_override():
    """Exemple d'utilisation avec forçage d'environnement"""
    print("\n=== Exemple 3: Forçage d'environnement ===")
    
    # Définir une variable d'environnement pour tester
    os.environ["IZIPROXY_ENV"] = "dev"
    
    # Créer une instance IziProxy sans configuration
    proxy = IziProxy(debug=True)
    
    print(f"Environnement détecté (devrait être dev) : {proxy.get_current_environment()}")
    
    # Changer l'environnement manuellement
    os.environ["IZIPROXY_ENV"] = "prod"
    
    # Rafraîchir la détection
    proxy.refresh()
    
    print(f"Environnement après refresh : {proxy.get_current_environment()}")
    
    # Nettoyer
    if "IZIPROXY_ENV" in os.environ:
        del os.environ["IZIPROXY_ENV"]


def main():
    """Exécute tous les exemples"""
    print("Démonstration des différentes méthodes de configuration d'IziProxy")
    
    try:
        example_1_config_file()
    except Exception as e:
        print(f"Erreur dans l'exemple 1 : {e}")
    
    try:
        example_2_explicit_config()
    except Exception as e:
        print(f"Erreur dans l'exemple 2 : {e}")
    
    try:
        example_3_environment_override()
    except Exception as e:
        print(f"Erreur dans l'exemple 3 : {e}")


if __name__ == "__main__":
    main()
