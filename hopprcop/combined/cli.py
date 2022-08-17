"""A Vulnerability Scanner that combines results from all configured scanners"""
# pylint: disable=duplicate-code
from pathlib import Path
from typing import List

import typer
from typer import Typer

from security_commons.common.reporting.models import ReportFormat
from security_commons.common.reporting.reporting import Reporting
from security_commons.common.utils import parse_sbom
from hopprcop.combined.combined_scanner import CombinedScanner

app = Typer()


@app.command()
def vulnerability_report(
    bom: Path = typer.Argument(None, help="the path to a cyclone-dx bom"),
    formats: List[ReportFormat] = typer.Option(
        ["table"],
        "--format",
        help="The report formats to generate ",
    ),
    output_dir: Path = typer.Option(
        Path.cwd(), help="The directory where reports will be writen"
    ),
):
    """generates vulnerability reports based on the specified BOM and formats"""
    reporting = Reporting(output_dir, bom.name.removesuffix(".json"))
    combined = CombinedScanner()
    combined.set_scanners(
        [
            "hopprcop.gemnasium.gemnasium_scanner.GemnasiumScanner",
            "hopprcop.grype.grype_scanner.GrypeScanner",
            "hopprcop.ossindex.oss_index_scanner.OSSIndexScanner",
        ]
    )
    parsed_bom = parse_sbom(bom)
    result = combined.get_vulnerabilities_by_sbom(parsed_bom)
    reporting.generate_vulnerability_reports(formats, result, parsed_bom)
