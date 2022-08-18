# Use as Python Library

This library can also be used programmatically, here is an example of interacting with the combined scanner from python code.
```python
from pathlib import Path

from security_commons.common.reporting.models import ReportFormat
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.utils import parse_sbom
from hopprcop.combined.combined_scanner import CombinedScanner
from hopprcop.gemnasium.gemnasium_scanner import GemnasiumScanner
from hopprcop.grype.grype_scanner import GrypeScanner
from hopprcop.trivy.trivy_scanner import TrivyScanner
from hopprcop.ossindex.oss_index_scanner import OSSIndexScanner

output_dir = Path("./reports")
bom = Path("bom.json")
formats = [ReportFormat.HTML]

reporting = Reporting(output_dir, bom.name.removesuffix(".json"))
combined = CombinedScanner()
combined.set_scanners([GemnasiumScanner(), GrypeScanner(), TrivyScanner, OSSIndexScanner()])
parsed_bom = parse_sbom(bom)
result = combined.get_vulnerabilities_by_sbom(parsed_bom)
reporting.generate_vulnerability_reports(formats, result, parsed_bom)
```
