import os
import tempfile
import unittest
from pathlib import Path

import yaml

from deephole_client.config import AgentConfig
from deephole_client.platform_runtime import configure_platform_runtime


class AgentResultPathTests(unittest.TestCase):
    def test_agent_backend_config_uses_scan_dir_for_results(self) -> None:
        old_config_path = os.environ.get("CONFIG_PATH")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                scan_dir = Path(tmp) / "scans" / "scan-123"
                scan_dir.mkdir(parents=True)
                agent_config = AgentConfig()
                agent_config.opencode.serve_port = 4317

                configure_platform_runtime(agent_config, scan_dir)

                raw = yaml.safe_load((scan_dir / "config.yaml").read_text(encoding="utf-8"))
                self.assertEqual(raw["storage"]["scans_dir"], str(scan_dir))
                self.assertEqual(raw["storage"]["projects_dir"], str(scan_dir.parent))
                self.assertEqual(raw["opencode"]["serve_port"], 4317)
                self.assertEqual(
                    raw["threat_analysis"]["model_policy"],
                    {
                        "required_capability": "high",
                        "timeout_seconds": 3600,
                        "max_retries": 2,
                    },
                )
        finally:
            if old_config_path is None:
                os.environ.pop("CONFIG_PATH", None)
            else:
                os.environ["CONFIG_PATH"] = old_config_path

            import backend.config as _cfg
            _cfg._config = None

            import backend.registry as _reg
            _reg._registry = None


if __name__ == "__main__":
    unittest.main()
