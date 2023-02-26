import uuid
from copy import deepcopy
from pathlib import Path
from typing import List

from hoppr.base_plugins.hoppr import HopprPlugin, hoppr_process
from hoppr.result import Result
from hoppr.hoppr_types.bom_access import BomAccess
from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    Component,
    CyclonedxSoftwareBillOfMaterialsStandard as Bom_1_4,
    Vulnerability,
    Affect,
)

from security_commons.common.reporting.reporting import Reporting
from security_commons.common.reporting.models import ReportFormat
from security_commons.common.vulnerability_combiner import combine_vulnerabilities
from hopprcop.combined.combined_scanner import CombinedScanner

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
        scanners = self.config.get("scanners", get_scanners())
        formats = self.config.get("result_formats", [self.EMBEDDED_VEX])

        output_dir.mkdir(parents=True, exist_ok=True)

        reporting = Reporting(output_dir, base_report_name)
        combined = CombinedScanner()
        combined.set_scanners(scanners)
        parsed_bom = self.context.delivered_sbom

        results = combined.get_vulnerabilities_by_sbom(parsed_bom)

        # Map bom ref to results - uses purl as ref
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
        parsed_bom.vulnerabilities = (
            [] if parsed_bom.vulnerabilities is None else parsed_bom.vulnerabilities
        )

        # Build dictionary to go from bom-ref to vulnerabilities
        for purl in results:
            component = purl_to_component[purl]
            bom_ref = component.purl  # component.bom_ref.__root__

            if len(parsed_bom.vulnerabilities) > 0:
                # Account for existing vulnerabilites on bom
                for existing_vulnerability in parsed_bom.vulnerabilities:
                    for affect in existing_vulnerability.affects:
                        if (
                            affect.ref == bom_ref
                            or affect.ref == component.bom_ref.__root__
                        ):
                            results[purl].append(existing_vulnerability)

                results[purl] = combine_vulnerabilities([{purl: results[purl]}])[0]

            updated_results = deepcopy(results[purl])

            wrapper = self.ComponentVulnerabilityWrapper(
                bom_serial_number, bom_version, updated_results
            )
            bom_ref_to_results[bom_ref] = wrapper

        hoppr_delivered_bom = self.__perform_hoppr_bom_updates(
            reporting, deepcopy(parsed_bom), bom_ref_to_results, formats
        )
        self.__perform_hopprcop_reporting(reporting, parsed_bom, results, formats)

        return Result.success(return_obj=hoppr_delivered_bom)

    def __add_bom_ref_and_flatten(
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

    def __perform_hoppr_bom_updates(
        self,
        reporting: Reporting,
        parsed_bom: Bom_1_4,
        bom_ref_to_results: dict[str, any],
        formats,
    ):
        if self.EMBEDDED_VEX in formats:
            flattened_results = self.__add_bom_ref_and_flatten(
                reporting, bom_ref_to_results
            )
            # Existing vulnerabilities were accounted for
            parsed_bom.vulnerabilities = []
            Reporting.add_vulnerabilities_to_bom(parsed_bom, flattened_results)
        elif self.LINKED_VEX in formats and self.EMBEDDED_VEX not in formats:
            flattened_results = self.__add_bom_ref_and_flatten(
                reporting, bom_ref_to_results, True
            )
            # Existing vulnerabilities were accounted for
            parsed_bom.vulnerabilities = []
            vex_bom = Reporting.link_vulnerabilities_to_bom(flattened_results)
            with open(
                reporting.output_dir.joinpath(f"{reporting.base_name}-vex.json"),
                "w",
                encoding="UTF-8",
            ) as file:
                file.write(vex_bom.json(exclude_none=True, by_alias=True))
                file.close()

        return parsed_bom

    def __perform_hopprcop_reporting(
        self,
        reporting: Reporting,
        parsed_bom: Bom_1_4,
        results: dict[str, List[Vulnerability]],
        formats: List[str],
    ):
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

    class ComponentVulnerabilityWrapper:
        def __init__(self, serial_number=None, version=None, vulnerabilities=None):
            self.serial_number = serial_number
            self.version = version
            self.vulnerabilities = vulnerabilities


def get_scanners() -> List[str]:
    """Defines scanners to use for hoppr cop"""
    return [
        "hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner",
        "hopprcop.grype.grype_scanner.GrypeScanner",
        "hopprcop.trivy.trivy_scanner.TrivyScanner",
        "hopprcop.ossindex.oss_index_scanner.OSSIndexScanner",
    ]
