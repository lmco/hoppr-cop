""""Interacts with the trivy cli to scan an sbom"""
import json
import tempfile
from subprocess import PIPE, Popen
from typing import Optional

from hoppr_cyclonedx_models.cyclonedx_1_4 import CyclonedxSoftwareBillOfMaterialsStandard as Bom_1_4
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Tool
from packageurl import PackageURL

from common.utils import (
    build_bom_dict_from_purls,
)
from common.vulnerability_scanner import VulnerabilitySuper


class TrivyScanner(VulnerabilitySuper):
    """ "Interacts with the trivy cli to scan an sbom"""

    required_tools_on_path = ["trivy"]
    supported_types = ["npm", "maven", "pypi", "gem", "golang", "nuget", "connan"]

    def get_vulnerabilities_by_purl(self, purls: list[PackageURL]) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        results = {}
        for purl in purls:
            results[purl.to_string()] = []

        purls = list(filter(lambda x: x.type in self.supported_types, purls))
        if len(purls) > 0:
            bom = build_bom_dict_from_purls(purls)

            with tempfile.NamedTemporaryFile(mode="w") as bom_file:
                bom_file.write(json.dumps(bom))

                with Popen(
                    ["trivy", "sbom", "--format", "cyclonedx", str(bom_file.name)], stdout=PIPE, stdin=PIPE, stderr=PIPE
                ) as process:
                    stdout_data = process.communicate(input=b"")[0]
                    bom_file.close()
            bom_dict = json.loads(stdout_data)
            bom_dict["metadata"]["component"]["type"] = "application"
            bom_dict["metadata"]["component"]["name"] = "generated"
            trivy_result = Bom_1_4(**bom_dict)

            for vuln in trivy_result.vulnerabilities:
                for affects in vuln.affects:
                    _, _, purl = str(affects.ref).partition("#")
                    affects.ref.__root__ = purl.strip("'")
                    if vuln.ratings is not None:
                        results[str(affects.ref.__root__)].append(vuln)
                vuln.tools = [Tool(vendor="Aquasec", name="Trivy")]

        return results
