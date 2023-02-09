"""A Vulnerability Scanner that combines results from all configured scanners"""
# pylint: disable=duplicate-code
from pathlib import Path
from typing import List

import typer
from typer import Typer

from security_commons.common.reporting.models import ReportFormat
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.utils import parse_sbom, parse_sbom_json_string
from hopprcop.combined.combined_scanner import CombinedScanner

app = Typer()


@app.command()
def vulnerability_report(
    bom: str = typer.Argument(None, help="the path to a cyclone-dx bom or json value"),
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
):
    """Generates vulnerability reports based on the specified BOM and formats"""

    if base_report_name is None:
        if bom.endswith(".json"):
            base_report_name = bom.removesuffix(".json")
        elif bom.endswith(".xml"):
            base_report_name = bom.removesuffix(".xml")
        else:
            base_report_name = "hoppr-cop-report"

    reporting = Reporting(output_dir, base_report_name)
    combined = CombinedScanner()
    combined.set_scanners(get_scanners())

    parsed_bom = None

    if bom.endswith(".json") or bom.endswith(".xml"):
        parsed_bom = parse_sbom(Path(bom))
    else:
        parsed_bom = parse_sbom_json_string(bom, "The json provided sbom")

    results = combined.get_vulnerabilities_by_sbom(parsed_bom)
    reporting.generate_vulnerability_reports(formats, results, parsed_bom)


def get_scanners() -> List[str]:
    """Defines scanners to use for hoppr cop"""
    return [
        "hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner",
        "hopprcop.grype.grype_scanner.GrypeScanner",
        "hopprcop.ossindex.oss_index_scanner.OSSIndexScanner",
    ]
