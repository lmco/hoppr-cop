## Development
The development environment can be setup with ...

```
# If you don't have python enabled by default, create an alias.
alias poetry="python3 -m poetry"


pip install poetry  # Installs poetry
poetry install      # Installs all dependencies
```

Once its setup you can run commands within the environment like ...

```
poetry run hoppr-cop --format html <path-to-sbom> # This runs the CLI 

poetry run black -l 120 vuln/
poetry run pylint vuln/
```
