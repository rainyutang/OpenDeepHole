from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from deephole_client.llm_proxy import manager as llm_proxy


def _effective_config(
    *,
    base_url: str = "https://snapengine.example/api/v2",
) -> dict:
    return {
        "provider": {
            "codemate": {
                "name": "Codemate",
                "options": {
                    "baseURL": base_url,
                    "apiKey": "must-not-be-written",
                },
                "models": {
                    "MiniMax-M2.7": {},
                    "maas-glm-5.1-zhipu-think": {},
                },
            },
        },
    }


class LLMProxyConfigTests(unittest.TestCase):
    def test_builds_requested_yaml_from_effective_codemate_config(self) -> None:
        result = llm_proxy.build_llm_proxy_config(
            _effective_config(base_url="https://snapengine.example/api/v2/"),
            [
                "codemate/MiniMax-M2.7",
                "codemate/maas-glm-5.1-zhipu-think",
                "codemate/MiniMax-M2.7",
            ],
        )

        self.assertIsNotNone(result)
        assert result is not None
        parsed = yaml.safe_load(result.content)
        self.assertEqual(parsed["server"], {
            "port": 31943,
            "host": "127.0.0.1",
        })
        self.assertEqual(parsed["providers"], [{
            "name": "codemate",
            "enabled": True,
            "api": (
                "https://snapengine.example/api/v2/chat/completions"
            ),
            "source_format": "openai_chat",
            "verify_ssl": False,
            "model_list": [
                "MiniMax-M2.7",
                "maas-glm-5.1-zhipu-think",
            ],
            "hook": "codemate_hook.py",
            "proxy_mode": "direct",
        }])
        self.assertNotIn("must-not-be-written", result.content.decode())
        self.assertEqual(result.routed_model_ids, (
            "codemate/MiniMax-M2.7",
            "codemate/maas-glm-5.1-zhipu-think",
        ))

    def test_empty_selection_needs_no_proxy(self) -> None:
        self.assertIsNone(
            llm_proxy.build_llm_proxy_config({}, [])
        )

    def test_rejects_cross_provider_and_unknown_models(self) -> None:
        for model_id, message in (
            ("other/MiniMax-M2.7", "codemate/model"),
            ("codemate/missing", "absent"),
        ):
            with self.subTest(model_id=model_id):
                with self.assertRaisesRegex(ValueError, message):
                    llm_proxy.build_llm_proxy_config(
                        _effective_config(),
                        [model_id],
                    )

    def test_loopback_is_appended_to_both_no_proxy_variables(self) -> None:
        with patch.dict(
            os.environ,
            {"NO_PROXY": "corp.example", "no_proxy": "10.0.0.0/8"},
            clear=False,
        ):
            llm_proxy._ensure_loopback_no_proxy()

            self.assertEqual(
                os.environ["NO_PROXY"],
                "corp.example,127.0.0.1,localhost",
            )
            self.assertEqual(
                os.environ["no_proxy"],
                "10.0.0.0/8,127.0.0.1,localhost",
            )


class LLMProxyManagerTests(unittest.TestCase):
    def test_starts_reuses_and_restarts_only_when_config_changes(self) -> None:
        class FakeProcess:
            pid = 43210
            returncode = None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "LLM_Proxy"
            root.mkdir()
            (root / "main.py").write_text("# supplied later\n", encoding="utf-8")
            state_path = Path(tmp) / "state" / "proxy.json"
            manager = llm_proxy.LLMProxyManager(
                proxy_root=root,
                process_state_path=state_path,
            )
            starts: list[str] = []
            stops: list[int] = []

            async def fake_start(desired) -> None:
                starts.append(desired.fingerprint)
                manager._process = FakeProcess()
                manager._fingerprint = desired.fingerprint
                manager._started_at = 1234.5
                manager._write_process_state()

            async def fake_stop() -> None:
                stops.append(1)
                manager._process = None
                manager._fingerprint = ""
                manager._started_at = None
                manager._remove_process_state()

            async def exercise():
                first = await manager.sync(
                    _effective_config(),
                    ["codemate/MiniMax-M2.7"],
                )
                second = await manager.sync(
                    _effective_config(),
                    ["codemate/MiniMax-M2.7"],
                )
                third = await manager.sync(
                    _effective_config(base_url="https://changed.example/v1"),
                    ["codemate/MiniMax-M2.7"],
                )
                return first, second, third

            with (
                patch.object(manager, "_start_locked", new=fake_start),
                patch.object(manager, "_stop_locked", new=fake_stop),
                patch.object(
                    manager,
                    "_wait_until_ready",
                    new=AsyncMock(),
                ),
                patch.object(
                    manager,
                    "_ready_once",
                    new=AsyncMock(return_value=True),
                ),
                patch.object(
                    manager,
                    "_port_accepting",
                    new=AsyncMock(return_value=False),
                ),
            ):
                first, second, third = asyncio.run(exercise())

            self.assertTrue(first.available)
            self.assertFalse(first.restarted)
            self.assertTrue(second.available)
            self.assertFalse(second.restarted)
            self.assertTrue(third.available)
            self.assertTrue(third.restarted)
            self.assertEqual(len(starts), 2)
            self.assertEqual(len(stops), 1)
            self.assertTrue(state_path.is_file())
            self.assertIn("changed.example", (
                root / "config.yaml"
            ).read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertEqual(
                    (root / "config.yaml").stat().st_mode & 0o777,
                    0o600,
                )

    def test_missing_entrypoint_keeps_generated_config_but_disables_proxy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "LLM_Proxy"
            root.mkdir()
            manager = llm_proxy.LLMProxyManager(
                proxy_root=root,
                process_state_path=Path(tmp) / "state.json",
            )

            result = asyncio.run(manager.sync(
                _effective_config(),
                ["codemate/MiniMax-M2.7"],
            ))

            self.assertFalse(result.available)
            self.assertIn("entrypoint is missing", result.error)
            self.assertTrue((root / "config.yaml").is_file())

    def test_unknown_port_owner_is_never_started_or_terminated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "LLM_Proxy"
            root.mkdir()
            (root / "main.py").touch()
            manager = llm_proxy.LLMProxyManager(
                proxy_root=root,
                process_state_path=Path(tmp) / "state.json",
            )
            with (
                patch.object(
                    manager,
                    "_port_accepting",
                    new=AsyncMock(return_value=True),
                ),
                patch.object(
                    manager,
                    "_start_locked",
                    new=AsyncMock(),
                ) as start,
            ):
                result = asyncio.run(manager.sync(
                    _effective_config(),
                    ["codemate/MiniMax-M2.7"],
                ))

            self.assertFalse(result.available)
            self.assertIn("unowned process", result.error)
            start.assert_not_awaited()

    def test_empty_selection_stops_owned_process_and_removes_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "LLM_Proxy"
            root.mkdir()
            config_path = root / "config.yaml"
            config_path.write_text("server: {}\n", encoding="utf-8")
            manager = llm_proxy.LLMProxyManager(
                proxy_root=root,
                process_state_path=Path(tmp) / "state.json",
            )
            stop = AsyncMock()
            with patch.object(manager, "_stop_locked", new=stop):
                result = asyncio.run(manager.sync({}, []))

            self.assertTrue(result.available)
            self.assertFalse(result.running)
            stop.assert_awaited_once()
            self.assertFalse(config_path.exists())


if __name__ == "__main__":
    unittest.main()
