# Guide de contribution

Merci de votre intérêt pour IziProxy ! Voici comment vous pouvez contribuer au projet.

## Configuration de l'environnement de développement

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/sanjuant/iziproxy.git
   cd iziproxy
   ```

2. Créez et activez un environnement virtuel :
   ```bash
   python -m venv venv
   source venv/bin/activate  # Sur Windows : venv\Scripts\activate
   ```

3. Installez les dépendances de développement :
   ```bash
   pip install -e ".[dev]"
   ```

## Tests

Exécutez les tests avec pytest :

```bash
pytest
```

Pour vérifier la couverture de code :

```bash
pytest --cov=iziproxy
```

## Formatage du code

Flake8 vérifie le code (configuration dans `.flake8` : lignes de 120
caractères au plus) :

```bash
flake8 src tests
```

## Guide de soumission des Pull Requests

1. Créez une branche dédiée à votre contribution
2. Faites vos modifications en suivant les conventions de codage
3. Ajoutez des tests pour vos nouvelles fonctionnalités
4. Assurez-vous que tous les tests passent
5. Mettez à jour la documentation si nécessaire
6. Soumettez votre Pull Request avec une description claire

## Conventions de codage

- Code (noms, messages de journal et d'erreur) en anglais ; commentaires et
  docstrings (format Google) en français
- Suivez la norme PEP 8 (vérifiée par flake8)
- Les tests ne doivent dépendre ni du réseau externe ni de la configuration
  de la machine : préférez les vrais serveurs de `tests/servers.py` aux mocks
- Toute fonctionnalité nouvelle s'accompagne de tests et d'une mise à jour
  de la documentation (`README.md`, `docs/source/`)
- Un changement qui touche aux identifiants ou au proxy local doit respecter
  les garanties décrites dans `docs/source/security.rst`

Merci pour votre contribution !
