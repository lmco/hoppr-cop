""""Interacts with the trivy cli to scan an sbom"""
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
import json
import os
import tempfile
from subprocess import PIPE, Popen
from typing import Optional, Union

import typer
from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    CyclonedxSoftwareBillOfMaterialsStandard as Bom_1_4,
)
from hoppr_cyclonedx_models.cyclonedx_1_3 import (
    CyclonedxSoftwareBillOfMaterialSpecification as Bom_1_3,
)

from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    Component as Bom_1_4_Component,
)
from hoppr_cyclonedx_models.cyclonedx_1_3 import (
    Component as Bom_1_3_Component,
)
from hoppr_cyclonedx_models.cyclonedx_1_4 import Vulnerability, Tool
from packageurl import PackageURL

from security_commons.common.utils import (
    build_bom_dict_from_purls,
)
from security_commons.common.vulnerability_scanner import VulnerabilitySuper


class TrivyScanner(VulnerabilitySuper):
    """ "Interacts with the trivy cli to scan an sbom"""

    # used to store the operating system component discovered in the provided bom for generating the bom for trivy
    __os_component: Optional[Union[Bom_1_4_Component, Bom_1_3_Component]] = None

    trivy_os_distro = os.getenv("OS_DISTRIBUTION", None)

    required_tools_on_path = ["trivy"]
    supported_types = [
        "npm",
        "maven",
        "pypi",
        "gem",
        "golang",
        "nuget",
        "conan",
        "rpm",
        "deb",
    ]

    def get_vulnerabilities_by_purl(
        self, purls: list[PackageURL]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Get the vulnerabilities for a list of package URLS (purls)
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        results = {}
        for purl in purls:
            results[purl.to_string()] = []

        purls = list(filter(lambda x: x.type in self.supported_types, purls))
        if len(purls) > 0:
            bom = build_bom_dict_from_purls(purls)
            self.__add_operating_system_component(bom)

            with tempfile.NamedTemporaryFile(mode="w") as bom_file:
                bom_file.write(json.dumps(bom))
                bom_file.flush()
                args = ["trivy", "sbom", "--format", "cyclonedx", str(bom_file.name)]
                cache = os.getenv("CACHE_DIR")
                if cache is not None:
                    args = args + ["--cache-dir", cache]
                with Popen(
                    args,
                    stdout=PIPE,
                    stdin=PIPE,
                    stderr=PIPE,
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

    def get_vulnerabilities_by_sbom(
        self, bom: [Union[Bom_1_4, Bom_1_3]]
    ) -> dict[str, Optional[list[Vulnerability]]]:
        """Accepts a cyclone dx compatible BOM and returns a list of vulnerabilities "
        This function will return a dictionary of package URL to vulnerabilities or none if no vulnerabilities are found
        """
        purls = []
        self.__os_component = None

        for component in bom.components:
            if component.purl is not None and component.purl != "":
                purls.append(PackageURL.from_string(component.purl))
            if "operating_system" in str(component.dict()["type"]):
                self.__os_component = component
        return self.get_vulnerabilities_by_purl(purls)

    def __add_operating_system_component(self, bom: dict):
        version = None
        distro = None
        if self.trivy_os_distro is not None:
            parts = self.trivy_os_distro.split(":")
            if len(parts) != 2:
                typer.echo(self.trivy_os_distro + " is an invalid distribution ")
            else:
                distro = parts[0]
                version = parts[1]
        elif self.__os_component is not None:
            version = self.__os_component.version
            distro = self.__os_component.name

        if version is not None and distro is not None:
            component = {
                "bom-ref": "ab16d2bb-90f7-4049-96ce-8c473ba13bd2",
                "type": "operating-system",
                "name": distro,
                "version": version,
            }
            bom["components"].append(component)
