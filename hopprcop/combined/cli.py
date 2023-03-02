"""A Vulnerability Scanner that combines results from all configured scanners"""
# pylint: disable=duplicate-code
from pathlib import Path
from typing import List

import typer
from security_commons.common.reporting.models import ReportFormat
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.utils import parse_sbom, parse_sbom_json_string
from typer import Typer

from hopprcop.combined.combined_scanner import CombinedScanner
from hopprcop.gemnasium.gemnasium_scanner import GemnasiumScanner
from hopprcop.grype.grype_scanner import GrypeScanner
from hopprcop.ossindex.oss_index_scanner import OSSIndexScanner
from hopprcop.trivy.trivy_scanner import TrivyScanner

app = Typer()


@app.command()
def vulnerability_report(
    bom: str = typer.Argument(None, help="the path to a cyclone-dx BOM"),
    formats: List[ReportFormat] = typer.Option(
        ["table"],
        "--format",
        help="The report formats to generate",
    ),
    output_dir: Path = typer.Option(
        Path.cwd(), help="The directory where reports will be writen"
    ),
    base_report_name: str = typer.Option(
        None, help="The base name supplied for the generated reports"
    ),
    os_distro: str = typer.Option(
        None,
        help=(
            "The operating system distribution; this is important "
            "to ensure accurate reporting of OS vulnerabilities from grype. "
            "Examples include rhel:8.6 or rocky:9 "
        ),
        envvar="OS_DISTRIBUTION",
    ),
):
    """Generates vulnerability reports based on the specified BOM and formats"""
    try:
        if base_report_name is None:
            if bom.endswith(".json"):
                base_report_name = bom.removesuffix(".json")
            elif bom.endswith(".xml"):
                base_report_name = bom.removesuffix(".xml")
            else:
                base_report_name = "hoppr-cop-report"

        reporting = Reporting(output_dir, base_report_name)
        combined = CombinedScanner()
        grype_scanner = GrypeScanner()
        grype_scanner.grype_os_distro = os_distro
        combined.set_scanners(
            [grype_scanner, TrivyScanner(), OSSIndexScanner(), GemnasiumScanner()]
        )

        parsed_bom = None

        if bom.endswith(".json") or bom.endswith(".xml"):
            parsed_bom = parse_sbom(Path(bom))
        else:
            parsed_bom = parse_sbom_json_string(bom, "The json provided sbom")

        results = combined.get_vulnerabilities_by_sbom(parsed_bom)
        reporting.generate_vulnerability_reports(formats, results, parsed_bom)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"unexpected error: {exc}")
