# Guide de contribution

Merci de votre intérêt pour IziProxy ! Voici comment vous pouvez contribuer au projet.

## Configuration de l'environnement de développement

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/votrenom/iziproxy.git
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

Nous utilisons Black pour le formatage du code :

```bash
black src tests
```

Et Flake8 pour la vérification de la qualité du code :

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

- Suivez la norme PEP 8
- Utilisez des docstrings au format Google pour documenter les classes et fonctions
- Ajoutez des commentaires lorsque le code n'est pas évident
- Écrivez des tests unitaires pour chaque nouvelle fonctionnalité

Merci pour votre contribution !
