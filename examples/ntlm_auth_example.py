"""
Exemple d'utilisation d'IziProxy avec authentification NTLM
"""

from iziproxy import IziProxy
import os
import requests
import sys

# Ajouter le répertoire parent au PATH pour pouvoir exécuter depuis le répertoire examples
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def check_ntlm_support():
    """Vérifie si le support NTLM est disponible"""
    try:
        # Essayer d'importer ntlm_auth
        import ntlm_auth
        
        # Vérifier aussi pour pycryptodomex
        try:
            from Cryptodome.Hash import MD4, MD5
            print("Support complet NTLM disponible (ntlm_auth et pycryptodomex installés).")
            return True
        except ImportError:
            print("Support partiel NTLM disponible (ntlm_auth installé, mais pycryptodomex manquant).")
            print("Pour un support complet, installer: pip install pycryptodomex")
            return True
    except ImportError:
        print("Support NTLM non disponible. Pour activer le support NTLM:")
        print("  pip install iziproxy[ntlm]")
        print("  ou")
        print("  pip install ntlm-auth pycryptodomex")
        return False


def ntlm_example():
    """Exemple d'utilisation avec authentification NTLM"""
    print("\n=== Exemple d'authentification NTLM ===")
    
    # Vérifier si le support NTLM est disponible
    if not check_ntlm_support():
        return
    
    # Paramètres de proxy NTLM (à adapter à votre environnement)
    proxy_url = os.environ.get("NTLM_PROXY_URL", "http://proxy.example.com:8080")
    username = os.environ.get("NTLM_USERNAME", "domain\\user")
    password = os.environ.get("NTLM_PASSWORD", "password")
    domain = os.environ.get("NTLM_DOMAIN", "DOMAIN")
    
    print(f"Création d'une configuration proxy avec NTLM pour: {proxy_url}")
    print(f"Identifiants: {username} (domaine: {domain})")
    
    # Créer la configuration pour utiliser NTLM
    config = {
        "environments": {
            "prod": {
                "proxy_url": proxy_url,
                "requires_auth": True,
                "auth_type": "ntlm"
            }
        },
        "credentials": {
            "username": username,
            "password": password,
            "domain": domain
        }
    }
    
    # Créer un fichier de configuration temporaire
    import tempfile
    import yaml
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as temp:
        yaml.dump(config, temp)
        temp_config_path = temp.name
    
    try:
        # Créer une instance IziProxy avec la configuration NTLM
        print("Création de l'instance IziProxy avec authentification NTLM...")
        proxy = IziProxy(
            config_path=temp_config_path,
            environment="prod",
            debug=True
        )
        
        # Créer une session configurée pour NTLM
        session = proxy.create_session()
        
        print("\nTentative de requête avec authentification NTLM...")
        print("(Cette requête échouera probablement avec les identifiants d'exemple.)")
        print("(Modifiez les variables d'environnement pour tester avec vos identifiants réels.)")
        
        try:
            response = session.get("https://httpbin.org/ip", timeout=10)
            print(f"Statut: {response.status_code}")
            print(f"Réponse: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête: {e}")
    
    finally:
        # Supprimer le fichier temporaire
        if os.path.exists(temp_config_path):
            os.unlink(temp_config_path)


def main():
    """Fonction principale"""
    print("Démonstration de l'authentification NTLM avec IziProxy")
    ntlm_example()


if __name__ == "__main__":
    main()
