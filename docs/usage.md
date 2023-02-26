# Usage

## CLI

Note the first time you run the command each day can be quite slow as it downloads the databases.  Subsequent runs should be much more performant.

![](usage.png)

## Hoppr Plugin Configuration


| Name | Default | Options | Notes |
| -----| ------- | ------- | -------- |
| output_dir | `self.context.collect_root_dir + "/generic"` | Local directory path | Default leverages the output location for hoppr which allows for any output to be included in the bundle. |
| base_report_name | `hopprcop-vulnerability-results` | String |
| scanners | `hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner`<br>`hopprcop.grype. grype_scanner.GrypeScanner`<br>`hopprcop.ossindex.oss_index_scanner.OSSIndexScanner`<br> | `hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner`<br>`hopprcop.grype.grype_scanner.GrypeScanner`<br>`hopprcop.ossindex.oss_index_scanner.OSSIndexScanner`<br>`hopprcop.trivy.trivy_scanner.TrivyScanner` | |                                                     
| result_formats | `embedded_cyclone_dx_vex` | `embedded_cyclone_dx_vex`<br>`linked_cyclone_dx_vex`<br>`table`<br>`html`<br>`cyclone_dx`<br>`gitlab`| `embedded_cyclone_dx_vex` and `linked_cyclone_dx_vex` are hoppr specific outputs and handle either embedding vulnerability information inside of the hoppr delivered bom or linking to it via a [VEX Bom](https://cyclonedx.org/capabilities/vex). The other options are default hoppr-cop formats. |

### Example Hoppr Transfer File Configuration
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