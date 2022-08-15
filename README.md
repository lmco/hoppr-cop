# Security Plugins 
This is a temporary project to flesh out the correct structure for a set of plugins intended at collecting vulnerability information and other 
relevant security information related to package URLS.  

## Module rules 
These are intended to ensure that code can be extracted into individual plugins when the appropriate level of maturity is reached. 

Modules must not import from other modules in this project except `common` or other intentionally common modules. 
* Each module should include a README that defines any tools that must be installed, any expected environment variables, and package dependencies 
* Each module should implement a typer CLI that accepts at minimum a cyclonedx 1.4 BOM as a Path argument. 
  * It is recommended that the CLI provide an option to enhance the BOM with vulnerability information and write it to a specified location
  * It is recommended that the CLI provide an option for an output directory 
  * It is recommended that the CLI provide an option for output formats 
* Any module can set the following properties to dictate if the plugin should be activated.  Alternatively they can override the `should_activate` function
  * `required_environment_variables`
  * `required_tools_on_path`

* Each module should implement the interface `VulnerabilitySuper` as defined in `common.vulnerability_scanner`
* Each vulnerability scanner needs a no arg `__init__` function. 
* Each module must map the tool specific results to the [cyclone dx 1.4 vulnerability spec](https://cyclonedx.org/docs/1.4/json/#vulnerabilities)
  * valuable metadata that is not in the spec should be put under properties.  These properties must follow the proper taxonomy 


# Data Sources

## Grype

- Alpine Linux SecDB: https://secdb.alpinelinux.org/
- Amazon Linux ALAS: https://alas.aws.amazon.com/AL2/alas.rss
- RedHat RHSAs: https://www.redhat.com/security/data/oval/
- Debian Linux CVE Tracker: https://security-tracker.debian.org/tracker/data/json
- Github GHSAs: https://github.com/advisories
- National Vulnerability Database (NVD): https://nvd.nist.gov/vuln/data-feeds
- Oracle Linux OVAL: https://linux.oracle.com/security/oval/
- RedHat Linux Security Data: https://access.redhat.com/hydra/rest/securitydata/
- Suse Linux OVAL: https://ftp.suse.com/pub/projects/security/oval/
- Ubuntu Linux Security: https://people.canonical.com/~ubuntu-security/