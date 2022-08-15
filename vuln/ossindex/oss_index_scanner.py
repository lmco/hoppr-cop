"""A vulnerability scanner that locates vulnerabilities in Sonotypes' OSS Index. """
import os
from typing import Optional, List

from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSS3MalformedError
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Rating, Severity, Tool
from packageurl import PackageURL
from requests.auth import HTTPBasicAuth

from common.utils import get_vulnerability_source, get_advisories_from_urls
from common.vulnerability_scanner import VulnerabilitySuper
from vuln.ossindex.api.model import OssIndexComponent
from vuln.ossindex.api.model import Vulnerability as OssVulnerability
from vuln.ossindex.api.ossindex import OssIndex


class OSSIndexScanner(VulnerabilitySuper):
    """A vulnerability scanner that locates vulnerabilities in Sonotypes' OSS Index."""

    required_environment_variables = ["OSS_INDEX_TOKEN", "OSS_INDEX_USER"]
    api = OssIndex()
    api.osthentication = HTTPBasicAuth(os.getenv("OSS_INDEX_TOKEN"), os.getenv("OSS_INDEX_USER"))

    supported_types = ["npm", "maven", "pypi", "gem", "golang", "nuget", "rpm", "connan"]

    def get_vulnerabilities_by_purl(self, purls: list[PackageURL]) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        purls = list(filter(lambda x: x.type in self.supported_types, purls))

        def remove_qualifiers(pkg_url: PackageURL) -> PackageURL:
            pkg_url.qualifiers.clear()
            if pkg_url.type == "rpm":
                pkg_url = PackageURL(name=pkg_url.name, type=pkg_url.type, version=pkg_url.version)
            return pkg_url

        purls = list(map(remove_qualifiers, purls))

        results: List[OssIndexComponent] = self.api.get_component_report(packages=purls)
        enhanced_results = {}
        for result in results:
            purl = result.coordinates
            enhanced_results[purl] = []
            for vulnerability in result.vulnerabilities:
                enhanced_results[purl].append(self.__convert_to_cyclone_dx(vulnerability))
        return enhanced_results

    @staticmethod
    def __convert_to_cyclone_dx(vulnerability: OssVulnerability) -> Vulnerability:
        """convert an OSS Index vulnerability to cyclone dx."""
        vuln_id = vulnerability.cve if vulnerability.cve is not None else vulnerability.display_name
        cwes = [int(vulnerability.cwe.replace("CWE-", ""))]

        cyclone_vuln = Vulnerability(
            id=vuln_id, description=vulnerability.description, cwes=cwes, source=get_vulnerability_source(vuln_id)
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
        cyclone_vuln.advisories = get_advisories_from_urls(list(vulnerability.external_references))
        cyclone_vuln.tools = [Tool(vendor="Sonotype", name="OSS-Index")]

        return cyclone_vuln
