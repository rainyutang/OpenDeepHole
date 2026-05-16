import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.api.checkers import _discover_catalog_items, list_checker_catalog
from backend.models import User


class CheckerCatalogTests(unittest.TestCase):
    def test_catalog_prefers_scenarios_over_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checker_dir = Path(tmp) / "intoverflow"
            checker_dir.mkdir()
            (checker_dir / "checker.yaml").write_text(
                "name: intoverflow\nlabel: Integer Overflow\ndescription: description\nenabled: true\n",
                encoding="utf-8",
            )
            skill_path = checker_dir / "SKILL.md"
            skill_path.write_text("# Skill intro\n", encoding="utf-8")
            (checker_dir / "SCENARIOS.md").write_text("# Scenario intro\n", encoding="utf-8")

            with patch("backend.api.checkers.CHECKERS_DIR", Path(tmp)):
                response = asyncio.run(
                    list_checker_catalog(
                        current_user=User(user_id="u1", username="alice", role="user")
                    )
                )

        self.assertEqual(len(response), 1)
        self.assertTrue(response[0].enabled)
        self.assertEqual(response[0].introduction, "# Scenario intro")
        self.assertEqual(response[0].introduction_source, "SCENARIOS.md")

    def test_catalog_includes_disabled_checkers_and_falls_back_to_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npd_dir = root / "npd"
            npd_dir.mkdir()
            (npd_dir / "checker.yaml").write_text(
                "name: npd\nlabel: NPD\ndescription: null pointer\nenabled: false\n",
                encoding="utf-8",
            )
            (npd_dir / "SKILL.md").write_text("# Skill only\n", encoding="utf-8")

            response = _discover_catalog_items(root)

        by_name = {item.name: item for item in response}
        self.assertFalse(by_name["npd"].enabled)
        self.assertEqual(by_name["npd"].introduction, "# Skill only")
        self.assertEqual(by_name["npd"].introduction_source, "SKILL.md")

    def test_catalog_falls_back_to_description_when_intro_files_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker_dir = root / "api_checker"
            checker_dir.mkdir()
            (checker_dir / "checker.yaml").write_text(
                "name: api_checker\nlabel: API Checker\ndescription: api description\nenabled: false\n",
                encoding="utf-8",
            )

            response = _discover_catalog_items(root)

        self.assertEqual(response[0].introduction, "api description")
        self.assertEqual(response[0].introduction_source, "checker.yaml")


if __name__ == "__main__":
    unittest.main()
