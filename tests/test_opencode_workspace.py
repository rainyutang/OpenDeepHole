import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.fp_reviewer import _cleanup_fp_workspace, _create_fp_workspace
from backend.opencode.config import cleanup_workspace


class OpencodeWorkspaceTests(unittest.TestCase):
    def test_scan_cleanup_preserves_fp_review_skill_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            skills_dir = workspace / ".opencode" / "skills"
            for name in ("npd", "oob", "fp-review", "custom"):
                skill_dir = skills_dir / name
                skill_dir.mkdir(parents=True)
                (skill_dir / "SKILL.md").write_text(name, encoding="utf-8")

            with patch("backend.opencode.config.get_registry", return_value={"npd": object(), "oob": object()}):
                cleanup_workspace(workspace)

            self.assertFalse((skills_dir / "npd").exists())
            self.assertFalse((skills_dir / "oob").exists())
            self.assertTrue((skills_dir / "fp-review" / "SKILL.md").is_file())
            self.assertTrue((skills_dir / "custom" / "SKILL.md").is_file())
            self.assertTrue((workspace / "opencode.json").is_file())

    def test_scan_cleanup_removes_config_when_no_skills_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            skill_dir = workspace / ".opencode" / "skills" / "npd"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text("npd", encoding="utf-8")

            with patch("backend.opencode.config.get_registry", return_value={"npd": object()}):
                cleanup_workspace(workspace)

            self.assertFalse((workspace / ".opencode").exists())
            self.assertFalse((workspace / "opencode.json").exists())

    def test_fp_workspace_start_creates_project_root_skill_and_mcp_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)

            with patch("agent.fp_reviewer.load_local_feedback", return_value={}):
                self.assertEqual(_create_fp_workspace(workspace, 9123), workspace)

            config = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
            self.assertEqual(
                config["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            self.assertTrue((workspace / ".opencode" / "skills" / "fp-review" / "SKILL.md").is_file())

    def test_fp_cleanup_only_removes_fp_review_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            fp_dir = workspace / ".opencode" / "skills" / "fp-review"
            scan_dir = workspace / ".opencode" / "skills" / "npd"
            fp_dir.mkdir(parents=True)
            scan_dir.mkdir(parents=True)
            (fp_dir / "SKILL.md").write_text("fp", encoding="utf-8")
            (scan_dir / "SKILL.md").write_text("npd", encoding="utf-8")

            _cleanup_fp_workspace(workspace)

            self.assertFalse(fp_dir.exists())
            self.assertTrue((scan_dir / "SKILL.md").is_file())
            self.assertTrue((workspace / "opencode.json").is_file())


if __name__ == "__main__":
    unittest.main()
