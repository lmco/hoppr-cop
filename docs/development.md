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


## Module rules

These are intended to ensure that code can be extracted into individual plugins when the appropriate level of maturity
is reached.

Modules must not import from other modules in this project except `common` or other intentionally common modules.

* Each module should include a README that defines any tools that must be installed, any expected environment variables,
  and package dependencies
* Each module should implement a typer CLI that accepts at minimum a cyclonedx 1.4 BOM as a Path argument.
    * It is recommended that the CLI provide an option to enhance the BOM with vulnerability information and write it to
      a specified location
    * It is recommended that the CLI provide an option for an output directory
    * It is recommended that the CLI provide an option for output formats
* Any module can set the following properties to dictate if the plugin should be activated. Alternatively they can
  override the `should_activate` function
    * `required_environment_variables`
    * `required_tools_on_path`

* Each module should implement the interface `VulnerabilitySuper` as defined in `common.vulnerability_scanner`
* Each vulnerability scanner needs a no arg `__init__` function.
* Each module must map the tool specific results to
  the [cyclone dx 1.4 vulnerability spec](https://cyclonedx.org/docs/1.4/json/#vulnerabilities)
    * valuable metadata that is not in the spec should be put under properties. These properties must follow the proper
      taxonomy 