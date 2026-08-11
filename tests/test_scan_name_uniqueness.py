import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from backend.api import scan as scan_api
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    CreateScanRequest,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
)
from backend.store.base import DuplicateScanNameError
from backend.store.sqlite import SqliteScanStore


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


def _record(
    scan_id: str,
    scan_name: str,
    *,
    user_id: str = "user-1",
    project_path: str = "/repo/project",
    created_at: str = "2026-08-11T00:00:00+00:00",
) -> tuple[ScanStatus, ScanMeta]:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id=f"project-{scan_id}",
        scan_items=[],
        created_at=created_at,
        status=ScanItemStatus.COMPLETE,
        progress=1.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=[],
        created_at=created_at,
        project_path=project_path,
        scan_name=scan_name,
        user_id=user_id,
    )
    return scan, meta


class ScanNameUniquenessTests(unittest.TestCase):
    def setUp(self) -> None:
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def tearDown(self) -> None:
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def test_scan_name_is_case_sensitive_and_unique_per_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_record("scan-1", "Release Audit"))

            with self.assertRaises(DuplicateScanNameError):
                store.save_scan(*_record("scan-2", "Release Audit"))

            store.save_scan(*_record("scan-3", "release audit"))
            store.save_scan(*_record("scan-4", "Release Audit", user_id="user-2"))
            self.assertEqual(store.get_scan_meta("scan-3").scan_name, "release audit")
            self.assertEqual(store.get_scan_meta("scan-4").scan_name, "Release Audit")

            self.assertTrue(store.delete_scan("scan-1"))
            store.save_scan(*_record("scan-5", "Release Audit"))
            self.assertEqual(store.get_scan_meta("scan-5").scan_name, "Release Audit")

    def test_migration_trims_and_deduplicates_without_changing_project_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scan.db"
            store = SqliteScanStore(db_path)
            store._conn.execute("DROP INDEX idx_scans_user_scan_name_unique")
            store._conn.commit()
            store.save_scan(*_record("scan-1", "  Release Audit  "))
            store.save_scan(
                *_record(
                    "scan-2",
                    "Release Audit",
                    created_at="2026-08-11T00:01:00+00:00",
                )
            )
            store.save_scan(
                *_record(
                    "scan-3",
                    "",
                    project_path=r"C:\\work\\service",
                    created_at="2026-08-11T00:02:00+00:00",
                )
            )
            store.close()

            migrated = SqliteScanStore(db_path)
            first = migrated.load_scan("scan-1")
            second = migrated.load_scan("scan-2")
            generated = migrated.load_scan("scan-3")
            self.assertEqual(first[1].scan_name, "Release Audit")
            self.assertRegex(second[1].scan_name, r"^Release Audit_[0-9a-f]{4}$")
            self.assertRegex(generated[1].scan_name, r"^service_[0-9a-f]{4}$")
            self.assertEqual(first[0].project_id, "project-scan-1")
            self.assertEqual(second[0].project_id, "project-scan-2")

    def test_manual_duplicate_returns_conflict_without_dispatching_agent_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_record("existing", "Release Audit"))
            user = User(user_id="user-1", username="alice", role="user")
            agent = AgentInfo(
                agent_id="agent-live",
                agent_key="stable-agent",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-08-11T00:00:00+00:00",
                user_id=user.user_id,
            )
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_mining_engines",
                    return_value=[],
                ),
                patch(
                    "backend.api.scan._resolve_threat_analysis_enabled",
                    return_value=True,
                ),
                patch(
                    "backend.api.scan._resolve_threat_analysis_method",
                    return_value=("deephole_threat_analysis", None),
                ),
                patch(
                    "backend.api.scan._resolve_fp_review_method",
                    return_value=("adversarial", None),
                ),
                patch(
                    "backend.api.agent.resolve_agent_connection_async",
                    new=AsyncMock(return_value=(agent.agent_id, agent)),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=AgentRemoteConfig(
                        model_pool={"models": [{
                            "id": "ready",
                            "model": "provider/model",
                            "enabled": True,
                        }]},
                    )),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                with self.assertRaises(HTTPException) as error:
                    asyncio.run(scan_api.create_agent_scan(
                        CreateScanRequest(
                            agent_key=agent.agent_key,
                            project_path="/repo/project",
                            scan_name="  Release Audit  ",
                            threat_analysis_enabled=True,
                            mining_engines=[],
                        ),
                        SimpleNamespace(base_url="http://testserver/"),
                        user,
                    ))

            self.assertEqual(error.exception.status_code, 409)
            self.assertIn("请修改", error.exception.detail)
            send.assert_not_awaited()

    def test_empty_name_uses_windows_basename_and_retries_suffix_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_record("existing", "service_00af"))
            user = User(user_id="user-1", username="alice", role="user")
            agent = AgentInfo(
                agent_id="agent-live",
                agent_key="stable-agent",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-08-11T00:00:00+00:00",
                user_id=user.user_id,
            )
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch("backend.api.scan.secrets.randbelow", return_value=0x00AF),
                patch("backend.api.scan._resolve_scan_mining_engines", return_value=[]),
                patch("backend.api.scan._resolve_threat_analysis_enabled", return_value=True),
                patch(
                    "backend.api.scan._resolve_threat_analysis_method",
                    return_value=("deephole_threat_analysis", None),
                ),
                patch(
                    "backend.api.scan._resolve_fp_review_method",
                    return_value=("adversarial", None),
                ),
                patch(
                    "backend.api.agent.resolve_agent_connection_async",
                    new=AsyncMock(return_value=(agent.agent_id, agent)),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=AgentRemoteConfig(
                        model_pool={"models": [{
                            "id": "ready",
                            "model": "provider/model",
                            "enabled": True,
                        }]},
                    )),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                response = asyncio.run(scan_api.create_agent_scan(
                    CreateScanRequest(
                        agent_key=agent.agent_key,
                        project_path=r"C:\\work\\service",
                        threat_analysis_enabled=True,
                        mining_engines=[],
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                    user,
                ))

            meta = store.get_scan_meta(response.scan_id)
            self.assertEqual(meta.scan_name, "service_00b0")
            self.assertEqual(store.load_scan(response.scan_id)[0].project_id, "service_00b0")
            self.assertEqual(send.await_args.args[1]["scan_name"], "service_00b0")


if __name__ == "__main__":
    unittest.main()
