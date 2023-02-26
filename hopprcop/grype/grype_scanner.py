""""Interacts with the grype cli to scan a sbom"""
# This file is part of hoppr-cop
#
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Copyright (c) 2022 Lockheed Martin Corporation
# pylint: disable=duplicate-code
import json
import os
from subprocess import PIPE, Popen
from typing import Optional, Union

from cvss import CVSS3, CVSS2
from hoppr_cyclonedx_models.cyclonedx_1_3 import (
    CyclonedxSoftwareBillOfMaterialSpecification as Bom_1_3,
)
from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    CyclonedxSoftwareBillOfMaterialsStandard as Bom_1_4,
)
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Rating, Severity, Tool
from packageurl import PackageURL
from security_commons.common.utils import (
    get_vulnerability_source,
    get_advisories_from_urls,
    get_references_from_ids,
    build_bom_from_purls,
)
from security_commons.common.vulnerability_scanner import VulnerabilitySuper

from hopprcop.grype.models import Match, GrypeResult


class GrypeScanner(VulnerabilitySuper):
    """This scanner utilizes the anchore grype command line to gather vulnerabilities"""

    required_tools_on_path = ["grype"]
    grype_os_distro = os.getenv("OS_DISTRIBUTION", None)

    def __init__(self):
        super()

    def get_vulnerabilities_by_purl(
        self, purls: list[PackageURL]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        bom = build_bom_from_purls(purls)
        return self.get_vulnerabilities_by_sbom(bom)

    def get_vulnerabilities_by_sbom(
        self, bom: [Union[Bom_1_4, Bom_1_3]]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Parse a cyclone dx 1.4 compatible BOM and return a list of vulnerabilities "
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        args = ["grype", "--output", "json"]
        if self.grype_os_distro is not None:
            args = args + ["--distro", self.grype_os_distro]
        with Popen(args, stdout=PIPE, stdin=PIPE, stderr=PIPE) as process:
            stdout_data = process.communicate(input=(bytes(bom.json(), "utf-8")))[0]
            result = GrypeResult(**json.loads(stdout_data))
            results = {}
        for component in bom.components:
            if component.purl is not None:
                results[component.purl] = []

        for match in list(result.matches):
            purl = PackageURL.from_string(match.artifact.purl)
            if not (purl.type == "npm" and purl.namespace == "@types"):
                results[match.artifact.purl].append(self.__convert_to_cyclone_dx(match))
        return results

    @staticmethod
    def __convert_to_cyclone_dx(match: Match) -> Vulnerability:
        """Converts a match to a vulnerability"""

        related = (
            match.vulnerability
            if len(match.related_vulnerabilities) == 0
            else match.related_vulnerabilities[0]
        )
        for related_vuln in match.related_vulnerabilities:
            if related_vuln.id.startswith("CVE"):
                related = related_vuln
                break

        cyclone_vuln = Vulnerability(
            id=related.id,
            description=related.description,
            ratings=[],
            recommendation=(
                f"State: {match.vulnerability.fix.state} | "
                f"Fix Versions: {','.join(match.vulnerability.fix.versions)}"
            ),
            source=get_vulnerability_source(related.id),
        )

        ids = [match.vulnerability.id] + list(
            map(lambda x: x.id, match.related_vulnerabilities)
        )

        cyclone_vuln.source.url = related.data_source
        cyclone_vuln.advisories = get_advisories_from_urls(related.urls)
        cyclone_vuln.references = get_references_from_ids(ids, cyclone_vuln.id)
        cvss_scores = (
            match.vulnerability.cvss
            if len(match.vulnerability.cvss) > 0
            else related.cvss
        )
        for cvss in cvss_scores:
            if cvss.version.startswith("3"):
                cvss3 = CVSS3(cvss.vector)
                method = "CVSSv31" if cvss.version == "3.1" else "CVSSv3"
                cyclone_vuln.ratings.append(
                    Rating(
                        score=cvss3.base_score,
                        severity=Severity[cvss3.severities()[0].lower()],
                        method=method,
                        vector=cvss.vector,
                    )
                )
            elif cvss.version.startswith("2"):
                cvss2 = CVSS2(cvss.vector)
                cyclone_vuln.ratings.append(
                    Rating(
                        score=cvss2.base_score,
                        severity=Severity[cvss2.severities()[0].lower()],
                        method="CVSSv2",
                        vector=cvss.vector,
                    )
                )
        if len(cyclone_vuln.ratings) == 0 and match.vulnerability.severity is not None:
            cyclone_vuln.ratings.append(
                Rating(
                    severity=Severity[match.vulnerability.severity.lower()],
                    method="other",
                )
            )
        cyclone_vuln.tools = [Tool(vendor="Anchore", name="Grype")]
        return cyclone_vuln
