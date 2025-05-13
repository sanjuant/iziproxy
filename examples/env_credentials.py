"""
Exemple d'utilisation d'IziProxy avec variables d'environnement ou fichier .env
"""

import os
from iziproxy import IziProxy
import requests

def demonstrate_env_vars():
    """
    Démonstration de l'utilisation avec variables d'environnement
    """
    print("\n=== Utilisation avec variables d'environnement ===")
    
    # Définir les variables d'environnement (dans votre application réelle,
    # vous les définiriez au niveau du système ou via les scripts de lancement)
    os.environ["IZI_USERNAME"] = "mon_utilisateur"
    os.environ["IZI_PASSWORD"] = "mon_mot_de_passe"
    os.environ["IZI_DOMAIN"] = "mon_domaine"  # Optionnel, pour NTLM
    
    # Créer l'instance IziProxy qui utilisera ces variables
    proxy = IziProxy(debug=True)
    
    # Obtenir une session configurée
    session = proxy.create_session()
    print(f"Proxy configuré: {proxy.get_proxy_dict()}")
    
    # Nettoyer les variables d'environnement
    del os.environ["IZI_USERNAME"]
    del os.environ["IZI_PASSWORD"]
    del os.environ["IZI_DOMAIN"]
    
    print("Variables d'environnement supprimées")
    
    # Les identifiants devraient être sauvegardés dans keyring si store_method="keyring"
    print("Note: Les identifiants sont conservés dans keyring pour les utilisations futures")

def demonstrate_dot_env_file():
    """
    Démonstration de l'utilisation avec fichier .env
    """
    print("\n=== Utilisation avec fichier .env ===")
    
    # Créer un fichier .env temporaire pour la démonstration
    # Dans une application réelle, ce fichier serait créé manuellement
    with open(".env", "w") as f:
        f.write("# Configuration IziProxy\n")
        f.write("IZI_USERNAME=utilisateur_env_file\n")
        f.write("IZI_PASSWORD=mot_de_passe_env_file\n")
        f.write("IZI_DOMAIN=domaine_env_file\n")
    
    print("Fichier .env créé temporairement")
    
    # Créer l'instance IziProxy qui utilisera ce fichier
    proxy = IziProxy(debug=True)
    
    # Obtenir une session configurée
    session = proxy.create_session()
    print(f"Proxy configuré avec .env: {proxy.get_proxy_dict()}")
    
    # Supprimer le fichier .env temporaire
    import os
    os.remove(".env")
    print("Fichier .env temporaire supprimé")

def main():
    """
    Fonction principale
    """
    print("DÉMONSTRATION DE CONFIGURATION DES IDENTIFIANTS")
    print("================================================")
    print("Ce script montre comment IziProxy peut être configuré via:")
    print("1. Variables d'environnement")
    print("2. Fichier .env")
    
    demonstrate_env_vars()
    demonstrate_dot_env_file()
    
    print("\n=== Comment utiliser cette approche dans votre application ===")
    print("1. Créez un fichier .env avec vos identifiants et ajoutez-le à .gitignore")
    print("2. Ou définissez les variables d'environnement dans votre système")
    print("3. Pour Windows: setx IZI_USERNAME \"mon_utilisateur\"")
    print("4. Pour Linux/Mac: export IZI_USERNAME=\"mon_utilisateur\"")
    print("5. Ou définissez-les dans les scripts de lancement de votre application")

if __name__ == "__main__":
    main()
