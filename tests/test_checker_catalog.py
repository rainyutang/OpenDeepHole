import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.checkers import list_checker_catalog
from backend.models import User


class CheckerCatalogTests(unittest.TestCase):
    def test_catalog_prefers_scenarios_over_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checker_dir = Path(tmp) / "intoverflow"
            checker_dir.mkdir()
            skill_path = checker_dir / "SKILL.md"
            skill_path.write_text("# Skill intro\n", encoding="utf-8")
            (checker_dir / "SCENARIOS.md").write_text("# Scenario intro\n", encoding="utf-8")

            registry = {
                "intoverflow": SimpleNamespace(
                    name="intoverflow",
                    label="Integer Overflow",
                    description="description",
                    directory=checker_dir,
                    skill_path=skill_path,
                )
            }

            with patch("backend.api.checkers.get_registry", return_value=registry):
                response = asyncio.run(
                    list_checker_catalog(
                        current_user=User(user_id="u1", username="alice", role="user")
                    )
                )

        self.assertEqual(len(response), 1)
        self.assertEqual(response[0].introduction, "# Scenario intro")
        self.assertEqual(response[0].introduction_source, "SCENARIOS.md")

    def test_catalog_falls_back_to_skill_then_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with_skill_dir = root / "npd"
            with_skill_dir.mkdir()
            with_skill_path = with_skill_dir / "SKILL.md"
            with_skill_path.write_text("# Skill only\n", encoding="utf-8")

            without_skill_dir = root / "api_checker"
            without_skill_dir.mkdir()
            missing_skill_path = without_skill_dir / "SKILL.md"

            registry = {
                "npd": SimpleNamespace(
                    name="npd",
                    label="NPD",
                    description="null pointer",
                    directory=with_skill_dir,
                    skill_path=with_skill_path,
                ),
                "api_checker": SimpleNamespace(
                    name="api_checker",
                    label="API Checker",
                    description="api description",
                    directory=without_skill_dir,
                    skill_path=missing_skill_path,
                ),
            }

            with patch("backend.api.checkers.get_registry", return_value=registry):
                response = asyncio.run(
                    list_checker_catalog(
                        current_user=User(user_id="u1", username="alice", role="user")
                    )
                )

        by_name = {item.name: item for item in response}
        self.assertEqual(by_name["npd"].introduction, "# Skill only")
        self.assertEqual(by_name["npd"].introduction_source, "SKILL.md")
        self.assertEqual(by_name["api_checker"].introduction, "api description")
        self.assertEqual(by_name["api_checker"].introduction_source, "checker.yaml")


if __name__ == "__main__":
    unittest.main()
