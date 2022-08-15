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

## Coverage By Package Manager 

* golang  - gemnasium, trivy, grype, oss-index  (have only seen results from trivy / oss-index)
* npm - gemnasium, trivy, grype, oss-index (confirmed results from all 4)
* maven - gemnasium, trivy, grype, oss-index (confirmed results from all 4)
* pypi - gemnasium, trivy, grype, oss-index (confirmed results from all 4)
* nuget - gemnasium, trivy, oss-index, grype ( no testing)
* gem - gemnasium, trivy, grype, oss-index (tested but got no results using a small bom)
* rpm - grype, oss-index (oss-index coverage seems quite poor, trivy has rpm in their database but blows up on rpm purls)
* deb - grype (trivy has deb in their database but blows up on rpm purls)
* raw - fnci via efoss data.  

## Gemnasium 

As a note the official gemnasium database has terms of service that say it can't be used in 3rd party tools without explicit permission.  
The community datasource is essentially the same it is just 30 days delayed. 

Tracking external sources
One of the main challenges of maintaining a vulnerability database
is to learn about security advisories recently published.
To that goal, the GitLab team checks external sources on a regular basis.
If an external source lists an advisory that is not already in gemnasium-db,
they research and check the advisory, add metadata to it, and publish it to this repo
following the contribution guidelines.

Tracking process and schedule
Below is the list of data-sources we check for updates on a daily basis:

NVD JSON feeds

GitHub security advisory database by means
of the Trivy Advisory Database

Ruby Advisory DB

Below is a list of data-sources from which we sourced data in the past. Those
data-sources are checked occasionally:

FriendsOfPHP security advisories
Victims CVE DB
oss-security mailing list

While the advisory tracking for NVD and ruby-advisory-db is semi-automated,
we check the oss-security mailing list manually.
For the manual source tracking, we use the following strategy:

Look for vulnerability announcement that do not have a CVE with an announcement day not older than 4 weeks
Generate an identifier (as explained in our contribution guidelines)
Create an MR (according to our contribution guidelines)

It's preferred to create merge requests right away but the team member
in charge of checking the source may not be immediately available to do that,
and creating issues is a way to delay the task or to pass it on to another team member.


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

## Trivy
# OS
### Note the OS datasources do not seem to work with SBOM integration we should open an issue with trivy to address

| OS                 | Source                                      |
|--------------------|---------------------------------------------|
| Arch Linux         | [Vulnerable Issues][arch]                   |
| Alpine Linux       | [secdb][alpine]                             |
| Amazon Linux       | [Amazon Linux Security Center][amazon]      |
| Debian             | [Security Bug Tracker][debian-tracker]      |
|                    | [OVAL][debian-oval]                         |
| Ubuntu             | [Ubuntu CVE Tracker][ubuntu]                |
| RHEL/CentOS        | [OVAL][rhel-oval]                           |
|                    | [Security Data][rhel-api]                   |
| AlmaLinux          | [AlmaLinux Product Errata][alma]            |
| Rocky Linux        | [Rocky Linux UpdateInfo][rocky]             |
| Oracle Linux       | [OVAL][oracle]                              |
| CBL-Mariner        | [OVAL][mariner]                             |
| OpenSUSE/SLES      | [CVRF][suse]                                |
| Photon OS          | [Photon Security Advisory][photon]          |

# Programming Language

| Language                     | Source                                              | Commercial Use  | Delay[^1]|
| ---------------------------- | ----------------------------------------------------|:---------------:|:--------:|
| PHP                          | [PHP Security Advisories Database][php]             | ✅              | -        |
|                              | [GitHub Advisory Database (Composer)][php-ghsa]     | ✅              | -        |
| Python                       | [GitHub Advisory Database (pip)][python-ghsa]       | ✅              | -        |
|                              | [Open Source Vulnerabilities (PyPI)][python-osv]    | ✅              | -        |
| Ruby                         | [Ruby Advisory Database][ruby]                      | ✅              | -        |
|                              | [GitHub Advisory Database (RubyGems)][ruby-ghsa]    | ✅              | -        |
| Node.js                      | [Ecosystem Security Working Group][nodejs]          | ✅              | -        |
|                              | [GitHub Advisory Database (npm)][nodejs-ghsa]       | ✅              | -        |
| Java                         | [GitLab Advisories Community][gitlab]               | ✅              | 1 month  |
|                              | [GitHub Advisory Database (Maven)][java-ghsa]       | ✅              | -        |
| Go                           | [GitLab Advisories Community][gitlab]               | ✅              | 1 month  |
|                              | [The Go Vulnerability Database][go]                 | ✅              | -        |
| Rust                         | [Open Source Vulnerabilities (crates.io)][rust-osv] | ✅              | -        |
| .NET                         | [GitHub Advisory Database (NuGet)][dotnet-ghsa]     | ✅              | -        |

[^1]: Intentional delay between vulnerability disclosure and registration in the DB

# Others

| Name                            | Source     |  
| --------------------------------|------------|
| National Vulnerability Database | [NVD][nvd] | 

# Data source selection
Trivy **only** consumes security advisories from the sources listed in the following tables.

As for packages installed from OS package managers (`dpkg`, `yum`, `apk`, etc.), Trivy uses the advisory database from the appropriate **OS vendor**.

For example: for a python package installed from `yum` (Amazon linux), Trivy will only get advisories from [ALAS][amazon2]. But for a python package installed from another source (e.g. `pip`), Trivy will get advisories from the `GitLab` and `GitHub` databases.

This advisory selection is essential to avoid getting false positives because OS vendors usually backport upstream fixes, and the fixed version can be different from the upstream fixed version.
The severity is from the selected data source. If the data source does not provide severity, it falls back to NVD, and if NVD does not have severity, it will be UNKNOWN.


[arch]: https://security.archlinux.org/
[alpine]: https://secdb.alpinelinux.org/
[amazon]: https://alas.aws.amazon.com/
[debian-tracker]: https://security-tracker.debian.org/tracker/
[debian-oval]: https://www.debian.org/security/oval/
[ubuntu]: https://ubuntu.com/security/cve
[rhel-oval]: https://www.redhat.com/security/data/oval/v2/
[rhel-api]: https://www.redhat.com/security/data/metrics/
[alma]: https://errata.almalinux.org/
[rocky]: https://download.rockylinux.org/pub/rocky/
[oracle]: https://linux.oracle.com/security/oval/
[suse]: http://ftp.suse.com/pub/projects/security/cvrf/
[photon]: https://packages.vmware.com/photon/photon_cve_metadata/
[mariner]: https://github.com/microsoft/CBL-MarinerVulnerabilityData/

[php-ghsa]: https://github.com/advisories?query=ecosystem%3Acomposer
[python-ghsa]: https://github.com/advisories?query=ecosystem%3Apip
[ruby-ghsa]: https://github.com/advisories?query=ecosystem%3Arubygems
[nodejs-ghsa]: https://github.com/advisories?query=ecosystem%3Anpm
[java-ghsa]: https://github.com/advisories?query=ecosystem%3Amaven
[dotnet-ghsa]: https://github.com/advisories?query=ecosystem%3Anuget

[php]: https://github.com/FriendsOfPHP/security-advisories
[ruby]: https://github.com/rubysec/ruby-advisory-db
[nodejs]: https://github.com/nodejs/security-wg
[gitlab]: https://gitlab.com/gitlab-org/advisories-community
[go]: https://github.com/golang/vulndb

[python-osv]: https://osv.dev/list?q=&ecosystem=PyPI
[rust-osv]: https://osv.dev/list?q=&ecosystem=crates.io

[nvd]: https://nvd.nist.gov/