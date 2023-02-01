## Installation

hoppr-cop is available as a python module.

### Prerequisites

#### Note python 3.10 is required
The remaining prerequisites are optional, if not performed that scanner will not be activated.

1. [Install grype](https://github.com/anchore/grype#installation) `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`
2. [Install trivy](https://aquasecurity.github.io/trivy/v0.31.2/getting-started/installation/) `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.31.2`
3. Register for a [free account with OSS-Index](https://ossindex.sonatype.org/user/register)
    1. Get the api token from your account page.  Export your username and token as `OSS_INDEX_TOKEN` and `OSS_INDEX_USER`

### Install Python Module

#### Note python 3.10 is required to install the tool

`pip install hoppr-cop`

### Usage

#### CLI

Note the first time you run the command each day can be quite slow as it downloads the databases.  Subsequent runs should be much more performant.

![](usage.png)

#### Hoppr Plugin Configuration


| Name | Default | Options | Notes |
| -----| ------- | ------- | -------- |
| output_dir | `self.context.collect_root_dir + "/generic"` | Local directory path | Default leverages the output location for hoppr which allows for any output to be included in the bundle. |
| base_report_name | `hopprcop-vulnerability-results` | String |
| scanners | `hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner`<br>`hopprcop.grype. grype_scanner.GrypeScanner`<br>`hopprcop.ossindex.oss_index_scanner.OSSIndexScanner`<br> | `hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner`<br>`hopprcop.grype.grype_scanner.GrypeScanner`<br>`hopprcop.ossindex.oss_index_scanner.OSSIndexScanner`<br>`hopprcop.trivy.trivy_scanner.TrivyScanner` | |                                                     
| result_formats | `embedded_cyclone_dx_vex` | `embedded_cyclone_dx_vex`<br>`linked_cyclone_dx_vex`<br>`table`<br>`html`<br>`cyclone_dx`<br>`gitlab`| `embedded_cyclone_dx_vex` and `linked_cyclone_dx_vex` are hoppr specific outputs and handle either embedding vulnerability information inside of the hoppr delivered bom or linking to it via a [VEX Bom](https://cyclonedx.org/capabilities/vex). The other options are default hoppr-cop formats. |

#### Example Hoppr Transfer File Configuration
```
schemaVersion: v1
kind: Transfer
stages:
  Vulnerability Check:
    plugins:
    - name: "hopprcop.hoppr_plugin.hopprcop_plugin"
      config:
        result_formats:
          - embedded_cyclone_dx_vex
          - html
        scanners: 
          - hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner
          - hopprcop.grype.grype_scanner.GrypeScanner
          - hopprcop.ossindex.oss_index_scanner.OSSIndexScanner
          - hopprcop.trivy.trivy_scanner.TrivyScanner

max_processes: 3
```

## Contributing

See the [Contribution Guidelines](contributing.md)
