from pathlib import Path

from security_commons.common.reporting.models import ReportFormat
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.utils import parse_sbom
from hopprcop.combined.combined_scanner import CombinedScanner
from hopprcop.gemnasium.gemnasium_scanner import GemnasiumScanner
from hopprcop.grype.grype_scanner import GrypeScanner
from hopprcop.trivy.trivy_scanner import TrivyScanner

bom = Path("npm.json")
combined = CombinedScanner()
combined.set_scanners([GemnasiumScanner(), GrypeScanner(), TrivyScanner()])
parsed_bom = parse_sbom(bom)
result = combined.get_vulnerabilities_by_sbom(parsed_bom)
counts={
    "Gemnasium":0,
    "Grype": 0,
    "Trivy":0
}
for r in result:
    for v in result[r]:
        for t in v.tools:
            counts[t.name] = counts[t.name] + 1


print (counts)

for tool in counts:
    assert counts[tool] > 0, tool + " vulnerability count should be greater than zero"
