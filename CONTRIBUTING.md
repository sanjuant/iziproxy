# Guide de contribution

Merci de votre intérêt pour IziProxy ! Voici comment vous pouvez contribuer au projet.

## Configuration de l'environnement de développement

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/sanjuant/iziproxy.git
   cd iziproxy
   ```

2. Créez et activez un environnement virtuel (Python 3.11 ou plus récent) :
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

Les versions minimales déclarées dans `pyproject.toml` (plus anciennes
versions sans faille connue) se vérifient dans un environnement installé
« au plus bas », avec Python 3.11 :

```bash
uv venv --python 3.11 .venv-min
uv pip install --python .venv-min --resolution lowest-direct -e ".[dev]"
.venv-min/Scripts/python -m pytest   # Linux, macOS : .venv-min/bin/python
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

## Intégration continue

GitHub Actions (`.github/workflows/ci.yml`) lance à chaque push sur
`master`, à chaque Pull Request et chaque lundi :

- les tests sous Linux et Windows, Python 3.11 à 3.14, avec les dernières
  versions des dépendances, plus Python 3.11 avec les versions minimales ;
- flake8 ;
- la documentation Sphinx en mode strict (`-W`).

## Publier une version

1. Changez `version` dans `pyproject.toml`. C'est le seul endroit à modifier :
   `iziproxy.__version__` et la documentation lisent la version du paquet.
2. Décrivez les changements visibles dans `docs/source/migration.rst`.
3. Commitez sur `master`, puis créez et poussez le tag :
   ```bash
   git tag -a v0.8.0 -m "iziproxy 0.8.0"
   git push origin master v0.8.0
   ```

Le tag déclenche `.github/workflows/release.yml` :
1. le workflow vérifie que le tag correspond à la version ;
2. il relance tous les tests ;
3. il construit le paquet et le contrôle (`twine check`) ;
4. il le publie sur PyPI ;
5. il crée la release GitHub.

Read the Docs reconstruit la documentation de son côté.

La publication passe par Trusted Publishing, donc sans jeton PyPI. Il faut
l'avoir déclarée une fois sur pypi.org, dans les réglages du projet
(*Publishing* > *GitHub*) :
- dépôt : `sanjuant/iziproxy` ;
- workflow : `release.yml` ;
- environnement : `pypi`.

Une version publiée sur PyPI ne peut plus être remplacée : un correctif
demande un nouveau numéro.

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
