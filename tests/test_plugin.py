from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from hoppr.context import Context
from hoppr.configs.manifest import Manifest
from hoppr_cyclonedx_models.cyclonedx_1_4 import (
    CyclonedxSoftwareBillOfMaterialsStandard as Bom,
)
from hopprcop import __version__
from hopprcop.hoppr_plugin.hopprcop_plugin import HopprCopPlugin


class TestHopprCopPlugin(TestCase):
    simple_test_context = Context(
        manifest=Manifest.load_file(Path("hoppr-integration-test/manifest.yml")),
        collect_root_dir="COLLECTION_DIR",
        consolidated_sbom="BOM",
        delivered_sbom=Bom.parse_file("hoppr-integration-test/sbom.json"),
        retry_wait_seconds=1,
        max_processes=3
    )
    simple_config = {}


    def test_get_version(self):
        assert HopprCopPlugin.get_version(self) == __version__

    def test_pre_stage_process(self):
        Hoppr50 = HopprCopPlugin(self.simple_test_context, self.simple_config)
        result = Hoppr50.pre_stage_process()

        assert result.is_success()
