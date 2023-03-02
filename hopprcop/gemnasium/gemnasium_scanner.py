"""A Vulnerability Scanner for Gitlab's Gemnasiumm Database """
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
import pkgutil
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import requests
import typer
import yaml
from cvss import CVSS2, CVSS3
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Rating, Severity, Tool
from packageurl import PackageURL

from security_commons.common.utils import (
    get_vulnerability_source,
    get_advisories_from_urls,
    get_references_from_ids,
)
from security_commons.common.vulnerability_scanner import VulnerabilitySuper
from hopprcop.gemnasium.models import GemnasiumVulnerability


class GemnasiumScanner(VulnerabilitySuper):
    """A Vulnerability Scanner for Gitlab's Gemnasiumm Database"""

    supported_formats = ["npm", "maven", "pypi", "gem", "golang", "connan"]

    database_path = None
    # url = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.zip"
    url = os.getenv(
        "GEMNASIUM_DATABASE_ZIP",
        "https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.zip",
    )

    semver_path = "/usr/local/bin/semver"
    required_tools_on_path = ["ruby"]

    def __init__(self):
        self.database_path = Path(self.__get_cache_dir()) / "gemnasium"

        if self.should_activate():
            if not Path(self.semver_path).exists():
                self.__extract_semver_to_local()
            self.__download_and_extract_database()

    def __extract_semver_to_local(self):
        """If the ruby semver command isn't installed then extract from this package"""
        data = pkgutil.get_data(__name__, "semver").decode("utf-8")
        self.semver_path = Path(tempfile.gettempdir()) / "semver"
        with open(self.semver_path, "w", encoding="UTF-8") as file:
            file.write(data)
            file.close()
        os.chmod(
            self.semver_path,
            stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH,
        )

    def __download_and_extract_database(self):
        """Downloads the gymnasium database"""
        url = urlparse(self.url)

        path_to_zip_file = Path(self.__get_cache_dir()) / os.path.basename(url.path)

        def do_download_and_unpack():
            typer.echo(f"Updating Gemnasium database to {self.database_path}")
            request = requests.get(self.url, allow_redirects=True)
            with open(path_to_zip_file, "wb") as file:
                file.write(request.content)
                file.close()

            with zipfile.ZipFile(path_to_zip_file, "r") as zip_ref:
                zip_ref.extractall(self.database_path)

        if not path_to_zip_file.exists():
            do_download_and_unpack()
        else:
            file_time = os.path.getmtime(path_to_zip_file)
            # Check against 24 hours
            older_than_one_day = (time.time() - file_time) / 3600 > 24 * 1
            if older_than_one_day:
                shutil.rmtree(self.database_path / path_to_zip_file.stem)
                do_download_and_unpack()
        self.database_path = self.database_path / path_to_zip_file.stem

    def __is_affected_range(self, repository_format, version, affected_range) -> bool:
        """
        Checks if the version matches the affected range based on package manager specific semantic versioning.
        :param repository_format:
        :param version:
        :param affected_range:
        :return:
        """
        try:
            output = subprocess.run(
                [
                    self.semver_path,
                    "check_version",
                    repository_format,
                    version,
                    affected_range,
                ],
                capture_output=True,
                text=True,
                check=False,
                # TODO this command suddenly started throwing errors, not sure what changed but it needs investigated.
                # It looks like  a spell checker package changed
            )
            return "matches" in str(output)
        except Exception as err:  # pylint: disable=broad-except
            print(f"Failed to check version for: {repository_format} {version} {err}")
            return False

    def get_vulnerabilities_by_purl(
        self, purls: list[PackageURL]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        vulnerabilities_by_purl = {}
        for purl in purls:
            vulnerabilities_by_purl[purl.to_string()] = []
            path = self.__get_path(purl)
            if path.exists():
                for filename in os.listdir(path):
                    try:
                        if (path / filename).is_file():
                            with open(path / filename, "r", encoding="UTF-8") as file:
                                data = yaml.full_load(file)
                                file.close()
                                vuln = GemnasiumVulnerability(**data)

                                if self.__is_affected_range(
                                    purl.type, purl.version, vuln.affected_range
                                ):
                                    vulnerability = self.__convert_to_cyclone_dx(vuln)
                                    if len(vulnerability.ratings) > 0:
                                        vulnerabilities_by_purl[
                                            purl.to_string()
                                        ].append(vulnerability)
                    except:  # pylint: disable=bare-except
                        print(f"failed to parse gemnasium file for {purl}")

        return vulnerabilities_by_purl

    @staticmethod
    def __convert_to_cyclone_dx(vuln: GemnasiumVulnerability) -> Vulnerability:
        # pylint: disable=duplicate-code
        """Converts a gemnasium vulnerabity to a vulnerability"""
        res = list(filter(lambda x: "cve-" in x.lower(), vuln.identifiers))
        vuln_id = res[0] if len(res) > 1 else vuln.identifiers[0]
        cwes = []
        if vuln.cwe_ids is not None:
            cwes = list(map(lambda x: int(x.replace("CWE-", "")), vuln.cwe_ids))
        cyclone_vuln = Vulnerability(
            id=vuln_id,
            recommendation=vuln.solution,
            cwes=cwes,
            description=vuln.description,
            ratings=[],
            source=get_vulnerability_source(vuln_id),
        )
        cyclone_vuln.advisories = get_advisories_from_urls(vuln.urls)
        cyclone_vuln.references = get_references_from_ids(
            vuln.identifiers, cyclone_vuln.id
        )
        if vuln.cvss_v3 is not None:
            cvss = CVSS3(vuln.cvss_v3)
            cyclone_vuln.ratings.append(
                Rating(
                    score=cvss.base_score,
                    severity=Severity[cvss.severities()[0].lower()],
                    method="CVSSv3",
                    vector=str(cvss.clean_vector()),
                )
            )
        elif vuln.cvss_v2 is not None:
            cvss = CVSS2(vuln.cvss_v2)
            cyclone_vuln.ratings.append(
                Rating(
                    score=cvss.base_score,
                    severity=Severity[cvss.severities()[0].lower()],
                    method="CVSSv2",
                    vector=cvss.clean_vector(),
                )
            )
        cyclone_vuln.tools = [Tool(vendor="Gitlab", name="Gemnasium")]
        return cyclone_vuln

    @staticmethod
    def __get_cache_dir() -> Path:
        cache = os.getenv("CACHE_DIR")
        if cache is not None:
            return Path(cache)

        return Path(tempfile.gettempdir())

    def __get_path(self, purl: PackageURL):
        """build a path to the gemnasium path"""
        repo_format = purl.type
        if repo_format == "npm":
            if purl.namespace != "" and purl.namespace is not None:
                path_slug = f"npm/{purl.namespace}/{purl.name}"
            else:
                path_slug = f"npm/{purl.name}"
        elif repo_format == "maven":
            path_slug = f"maven/{purl.namespace}/{purl.name}"
        elif repo_format == "golang":
            path_slug = f"go/{purl.namespace}/{purl.name}"
        else:
            path_slug = f"{repo_format}/{purl.name}"

        return self.database_path / Path(path_slug)
