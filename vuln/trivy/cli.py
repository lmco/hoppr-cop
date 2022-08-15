""" A typer cli to execute the grype scanner individually"""
# pylint: disable=duplicate-code
from pathlib import Path
from typing import List

import typer
from typer import Typer

from common.reporting.models import ReportFormat
from common.reporting.reporting import Reporting
from common.utils import parse_sbom
from vuln.trivy.trivy_scanner import TrivyScanner

app = Typer()


@app.command()
def vulnerability_report(
    bom: Path = typer.Argument(None, help="the path to a cyclone-dx bom"),
    formats: List[ReportFormat] = typer.Option(
        ["table"],
        "--format",
        help="The report formats to generate ",
    ),
    output_dir: Path = typer.Option(Path.cwd(), help="The directory where reports will be writen"),
):
    """generate standardized reports from grype"""
    reporting = Reporting(output_dir, bom.name.removesuffix(".json"))
    scanner = TrivyScanner()
    if scanner.should_activate():
        parsed_bom = parse_sbom(bom)
        result = scanner.get_vulnerabilities_by_sbom(parsed_bom)
        reporting.generate_vulnerability_reports(formats, result, parsed_bom)
