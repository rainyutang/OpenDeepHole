import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api import skills
from backend.models import SkillCreateJob, SkillImportRequest, User
from backend.registry import refresh_registry


class SkillMarketTests(unittest.TestCase):
    def tearDown(self) -> None:
        skills._jobs.clear()
        import backend.registry as registry

        registry._registry = None
        registry._registry_dirs = None

    def test_import_completed_skill_writes_public_project_level_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            user_skills_dir = Path(tmp) / "user_skills"
            cfg = SimpleNamespace(storage=SimpleNamespace(user_skills_dir=str(user_skills_dir)))
            job = SkillCreateJob(
                job_id="job-1",
                status="completed",
                name="Custom Audit",
                description="custom audit description",
                agent_id="agent-1",
                user_id="user-1",
            )
            skills._jobs[job.job_id] = job

            with (
                patch("backend.api.skills.get_config", return_value=cfg),
                patch("backend.config.get_config", return_value=cfg),
                patch("backend.registry.CHECKERS_DIR", Path(tmp) / "builtins"),
            ):
                response = asyncio.run(
                    skills.import_skill(
                        "job-1",
                        SkillImportRequest(
                            skill_md="# Custom Audit\n\n审计目标代码并调用 submit_result。",
                            scenarios_md="# 适用场景\n\n自定义审计。",
                        ),
                        current_user=User(user_id="user-1", username="alice", role="user"),
                    )
                )
                registry = refresh_registry()

            checker_dir = user_skills_dir / "custom_audit"
            self.assertTrue(response.ok)
            self.assertEqual(response.name, "custom_audit")
            self.assertTrue((checker_dir / "checker.yaml").is_file())
            self.assertTrue((checker_dir / "SKILL.md").is_file())
            self.assertTrue((checker_dir / "SCENARIOS.md").is_file())
            self.assertIn("custom_audit", registry)
            self.assertEqual(registry["custom_audit"].mode, "opencode")
            self.assertIsNone(registry["custom_audit"].analyzer)

    def test_import_rejects_incomplete_job(self) -> None:
        skills._jobs["job-2"] = SkillCreateJob(
            job_id="job-2",
            status="running",
            name="Running Skill",
            description="description",
            agent_id="agent-1",
            user_id="user-1",
        )

        with self.assertRaises(Exception) as ctx:
            asyncio.run(
                skills.import_skill(
                    "job-2",
                    SkillImportRequest(skill_md="# Draft"),
                    current_user=User(user_id="user-1", username="alice", role="user"),
                )
            )

        self.assertEqual(getattr(ctx.exception, "status_code", None), 400)


if __name__ == "__main__":
    unittest.main()
