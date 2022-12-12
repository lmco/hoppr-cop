from pathlib import Path

from hoppr.base_plugins.hoppr import HopprPlugin, hoppr_process
from hoppr.result import Result
from hoppr.hoppr_types.bom_access import BomAccess
from security_commons.common.reporting.models import ReportFormat

from hopprcop.combined.cli import run_hoppr_cop, get_scanners
from hopprcop import __version__


class HopprCopPlugin(HopprPlugin):
    """
    hoppr plugin wrapper for hopprcop integration
    """

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

        output_dir = self.config.get("output_dir", Path.cwd())
        base_report_name = self.config.get(
            "base_report_name", "hopprcop-vulnerability-results"
        )
        scanners = self.config.get("scanners", get_scanners())
        formats = self.config.get("result_formats", [ReportFormat.CYCLONE_DX])

        run_hoppr_cop(
            self.context.delivered_sbom.json(),
            base_report_name,
            formats,
            scanners,
            output_dir,
        )

        return Result.success()
