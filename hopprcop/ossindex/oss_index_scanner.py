"""A vulnerability scanner that locates vulnerabilities in Sonotypes' OSS Index. """
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
import os
from typing import Optional, List

from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSS3MalformedError
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Rating, Severity, Tool
from packageurl import PackageURL
from requests.auth import HTTPBasicAuth
from security_commons.common.utils import (
    get_vulnerability_source,
    get_advisories_from_urls,
)
from security_commons.common.vulnerability_scanner import VulnerabilitySuper

from hopprcop.ossindex.api.model import OssIndexComponent
from hopprcop.ossindex.api.model import Vulnerability as OssVulnerability
from hopprcop.ossindex.api.ossindex import OssIndex


class OSSIndexScanner(VulnerabilitySuper):
    """A vulnerability scanner that locates vulnerabilities in Sonotypes' OSS Index."""

    required_environment_variables = ["OSS_INDEX_TOKEN", "OSS_INDEX_USER"]
    api = OssIndex()
    api.osthentication = HTTPBasicAuth(
        os.getenv("OSS_INDEX_TOKEN"), os.getenv("OSS_INDEX_USER")
    )

    supported_types = [
        "npm",
        "maven",
        "pypi",
        "gem",
        "golang",
        "nuget",
        "rpm",
        "connan",
    ]

    def get_vulnerabilities_by_purl(
        self, purls: list[PackageURL]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        purls = list(filter(lambda x: x.type in self.supported_types, purls))
        cleaned_purl_map = {}

        def remove_qualifiers(pkg_url: PackageURL) -> PackageURL:
            before_cleaning = pkg_url.to_string()
            pkg_url.qualifiers.clear()
            if pkg_url.type == "rpm":
                pkg_url = PackageURL(
                    name=pkg_url.name, type=pkg_url.type, version=pkg_url.version
                )
            cleaned_purl_map[pkg_url.to_string()] = before_cleaning
            return pkg_url

        purls = list(map(remove_qualifiers, purls))

        results: List[OssIndexComponent] = self.api.get_component_report(packages=purls)
        enhanced_results = {}

        for result in results:
            purl = result.coordinates
            enhanced_results[cleaned_purl_map[purl]] = []
            for vulnerability in result.vulnerabilities:
                enhanced_results[cleaned_purl_map[purl]].append(
                    self.__convert_to_cyclone_dx(vulnerability)
                )
        return enhanced_results

    @staticmethod
    def __convert_to_cyclone_dx(vulnerability: OssVulnerability) -> Vulnerability:
        """convert an OSS Index vulnerability to cyclone dx."""
        vuln_id = (
            vulnerability.cve
            if vulnerability.cve is not None
            else vulnerability.display_name
        )
        cwes = [int(vulnerability.cwe.replace("CWE-", ""))]

        cyclone_vuln = Vulnerability(
            id=vuln_id,
            description=vulnerability.description,
            cwes=cwes,
            source=get_vulnerability_source(vuln_id),
        )
        cyclone_vuln.ratings = []
        if vulnerability.cvss_vector is not None:
            try:
                cvss = CVSS3(vulnerability.cvss_vector)
                cyclone_vuln.ratings.append(
                    Rating(
                        score=cvss.base_score,
                        severity=Severity[cvss.severities()[0].lower()],
                        method="CVSSv3",
                        vector=cvss.vector,
                    )
                )
            except CVSS3MalformedError:
                cvss = CVSS2(vulnerability.cvss_vector)
                cyclone_vuln.ratings.append(
                    Rating(
                        score=cvss.base_score,
                        severity=Severity[cvss.severities()[0].lower()],
                        method="CVSSv2",
                        vector=cvss.vector,
                    )
                )
        cyclone_vuln.advisories = get_advisories_from_urls(
            list(vulnerability.external_references)
        )
        cyclone_vuln.tools = [Tool(vendor="Sonotype", name="OSS-Index")]

        return cyclone_vuln
