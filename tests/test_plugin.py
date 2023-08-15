import multiprocessing

from copy import deepcopy
from pathlib import Path
from unittest import TestCase

from hoppr import HopprContext, Manifest, Sbom

from hopprcop import __version__
from hopprcop.hoppr_plugin.hopprcop_plugin import HopprCopPlugin


class TestHopprCopPlugin(TestCase):
    manifest = Manifest.load(Path("hoppr-integration-test") / "manifest.yml")

    simple_test_context = HopprContext(
        repositories=manifest.repositories,
        collect_root_dir="COLLECTION_DIR",
        consolidated_sbom=manifest.consolidated_sbom,
        delivered_sbom = deepcopy(manifest.consolidated_sbom),
        retry_wait_seconds=1,
        max_processes=3,
        sboms=list(Sbom.loaded_sboms.values()),
        stages=[],
        logfile_lock=multiprocessing.Manager().RLock()
    )

    simple_config = {}


    def test_get_version(self):
        assert HopprCopPlugin.get_version(self) == __version__

    def test_pre_stage_process_success(self):
        Hoppr50 = HopprCopPlugin(self.simple_test_context, self.simple_config)
        result = Hoppr50.pre_stage_process()

        assert result.is_success()
