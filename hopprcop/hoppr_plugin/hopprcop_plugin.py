import uuid
from copy import deepcopy
from pathlib import Path
from typing import List, Optional

from hoppr.base_plugins.hoppr import HopprPlugin, hoppr_process
from hoppr.result import Result
from hoppr.hoppr_types.bom_access import BomAccess
from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    Component,
    Vulnerability,
    Affect,
)
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.reporting.models import ReportFormat
from hopprcop.combined.combined_scanner import CombinedScanner

from hopprcop.combined.cli import get_scanners
from hopprcop import __version__


class HopprCopPlugin(HopprPlugin):
    """
    hoppr plugin wrapper for hopprcop integration
    """

    EMBEDDED_VEX = "embedded_cyclone_dx_vex"
    LINKED_VEX = "linked_cyclone_dx_vex"

    bom_access = BomAccess.FULL_ACCESS

    def get_version(self) -> str:
        """
        __version__ required for all HopprPlugin implementations
        """
        return __version__

    @hoppr_process
    def pre_stage_process(self) -> Result:
        """
        Supply sbom to hoppr cop to perform vulnerabilty check
        """
        self.get_logger().info("[ Executing hopprcop vulnerability check ]")
        self.get_logger().flush()

        output_dir = self.config.get(
            "output_dir", Path(self.context.collect_root_dir, "generic")
        )
        base_report_name = self.config.get(
            "base_report_name", "hopprcop-vulnerability-results"
        )

        reporting = Reporting(output_dir, base_report_name)
        scanners = self.config.get("scanners", get_scanners())
        formats = self.config.get("result_formats", [self.EMBEDDED_VEX])

        combined = CombinedScanner()
        combined.set_scanners(scanners)
        parsed_bom = self.context.delivered_sbom

        results = combined.get_vulnerabilities_by_sbom(parsed_bom)

        # Map bom ref to results to adhere to bom spec for affects references - uses bom-ref
        bom_ref_to_results = dict[str, self.ComponentVulnerabilityWrapper]()

        # Map purls to components
        purl_to_component = {
            component.purl: component for component in parsed_bom.components
        }

        # Delivered Bom version
        bom_version = 1 if parsed_bom.version is not None else parsed_bom.version

        # Generate Delivered Bom Serial Number if it doesn't exist
        bom_serial_number = (
            parsed_bom.serialNumber.split(":")[-1]
            if parsed_bom.serialNumber is not None
            else uuid.uuid4()
        )

        parsed_bom.serialNumber = f"urn:uuid:{bom_serial_number}"
        hoppr_delivered_bom = deepcopy(parsed_bom)
        hoppr_vuln_results = deepcopy(results)

        # Build dictionary to go from bom-ref to vulnerabilities
        for purl in hoppr_vuln_results:
            component = purl_to_component[purl]
            bom_ref = component.bom_ref.__root__
            wrapper = self.ComponentVulnerabilityWrapper(
                bom_serial_number, bom_version, hoppr_vuln_results[purl]
            )
            bom_ref_to_results[bom_ref] = wrapper

        if self.EMBEDDED_VEX in formats:
            flattened_results = self.add_bom_ref_and_flatten(
                reporting, bom_ref_to_results
            )
            Reporting.add_vulnerabilities_to_bom(hoppr_delivered_bom, flattened_results)
        elif self.LINKED_VEX in formats:
            flattened_results = self.add_bom_ref_and_flatten(
                reporting, bom_ref_to_results, True
            )
            vex_bom = Reporting.link_vulnerabilities_to_bom(flattened_results)
            with open(
                output_dir.joinpath(f"{base_report_name}-vex.json"),
                "w",
                encoding="UTF-8",
            ) as file:
                file.write(vex_bom.json(exclude_none=True, by_alias=True))
                file.close()

        filtered_formats = list(
            filter(lambda x: x != self.LINKED_VEX and x != self.EMBEDDED_VEX, formats)
        )

        if len(filtered_formats) > 0:
            filtered_formats = [
                ReportFormat[format.upper()] for format in filtered_formats
            ]
            reporting.generate_vulnerability_reports(
                filtered_formats, results, parsed_bom
            )

        return Result.success(return_obj=hoppr_delivered_bom)

    def add_bom_ref_and_flatten(
        self,
        reporting: Reporting,
        bom_ref_to_component: dict[str, List[Component]],
        external_ref: bool = False,
    ) -> List[Vulnerability]:
        flattened_vulnerabilities: List[Vulnerability] = []
        for bom_ref in bom_ref_to_component:
            for vuln in bom_ref_to_component[bom_ref].vulnerabilities:
                vuln.affects = [] if vuln.affects is None else vuln.affects
                if external_ref:
                    vuln.affects.append(
                        Affect(
                            **{
                                "ref": f"urn:cdx:{bom_ref_to_component[bom_ref].serial_number}/{bom_ref_to_component[bom_ref].version}#{bom_ref}"
                            }
                        )
                    )
                else:
                    vuln.affects.append(Affect(**{"ref": bom_ref}))

                flattened_vulnerabilities.append(vuln)

        flattened_vulnerabilities.sort(key=reporting.get_score, reverse=True)
        return flattened_vulnerabilities

    class ComponentVulnerabilityWrapper:
        def __init__(self, serial_number=None, version=None, vulnerabilities=None):
            self.serial_number = serial_number
            self.version = version
            self.vulnerabilities = vulnerabilities
