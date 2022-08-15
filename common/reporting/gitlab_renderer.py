""" Render Gitlab vulnerabilites"""
import json
from collections import defaultdict
from pathlib import Path
from typing import List

class GitlabReportRenderer():
    """Renders a gitlab dependencies report. This drives the BOM and vulnerabilities features in gitlab"""



    def render(
        self,
        bom: dict,
        enhanced_components: List[EFossCycloneComponent],
        output_path: Path,
        options: dict = None,
    ):
        self.render_vulnerabilities(enhanced_components, output_path / "gl-dependency-scanning-report.json")
        self.render_license_report(enhanced_components, output_path / "gl-license-scanning-report.json")



    def render_license_report(self, enhanced_components: List[EFossCycloneComponent], output_path: Path):
        """renders the license compliance report for gitlab"""
        report = {"version": "2.1", "dependencies": [], "licenses": []}
        for component in enhanced_components:
            if component.efoss_component is not None and component.efoss_component.licenses is not None:
                ids = set()
                for lic in component.efoss_component.licenses:
                    spdx = self.spdx_utils.get_spdx(lic)
                    license_id = lic.licenseId.replace("CUSTOM-", "").lower()
                    license_name = lic.licenseName
                    url = ""
                    if spdx is not None:
                        license_id = spdx["licenseId"]
                        license_name = spdx["name"]
                        url = spdx["reference"]
                    ids.add(license_id)
                    existing_matches = list(filter(lambda x, lic_id=license_id: x["id"] == lic_id, report["licenses"]))
                    if len(existing_matches) == 0:
                        report["licenses"].append({"id": license_id, "name": license_name, "url": url})
                dependency = {
                    "name": component.efoss_component.name,
                    "version": component.efoss_component.version,
                    "package_manager": component.efoss_component.repositoryFormat.lower(),
                    # "path": "",
                    "licenses": list(ids),
                }
                report["dependencies"].append(dependency)

        with open(output_path, "w", encoding="utf-8") as out:
            out.write(json.dumps(report, indent=4, sort_keys=True, default=str))
            out.close()

    @staticmethod
    def generate_row(vuln: Vulnerability, component: EFossCycloneComponent):
        """Generates a report row"""
        return {
            "category": "dependency_scanning",
            "name": vuln.description,
            "description": vuln.description,
            "cve": vuln.id,
            "severity": vuln.ratings[0].severity,
            "confidence": "Undefined",
            "identifiers": [{"type": "cve", "name": vuln.id, "value": vuln.id}],
            "scanner": {"id": "efoss", "name": "FNCI"},
            "location": {
                "dependency": {
                    "package": {"name": component.efoss_component.name},
                    "version": component.efoss_component.version,
                }
            },
        }
