"""Tests for OpenCode 2.x version selection, V2 plugins, auth, and HTTP/SSE protocol."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.agents.configuration import _validate_managed_config
from backend.application import ApplicationError
from backend.models import AgentOpenCodeModelConfig, AgentRemoteConfig
from deephole_client import llm_runtime
from deephole_client.config import (
    AgentConfig,
    OpenCodeConfig,
    OpenCodeModelConfig,
    active_opencode_executable,
    apply_remote_config,
    load_config,
    remote_config_dict,
    save_config,
)
from deephole_client.opencode_integration import build_opencode_session_runtime
from task_agent import run_opencode_task, shutdown_opencode
from task_agent._opencode_v2 import (
    normalize_opencode_version,
    parse_opencode_major_version,
    verify_opencode_executable_version,
)
from task_agent.model_pool import _model_health_identity, model_options
from task_agent.serve_client import (
    OpenCodeServeKey,
    OpenCodeServeManager,
    OpenCodeServeStartupError,
    _write_command_binding,
    _write_knowledge_binding,
    _write_serve_config_file,
)
from task_agent.standalone import load_standalone_config


def test_agent_remote_config_and_validation_preserve_dual_executables() -> None:
    default_cfg = AgentRemoteConfig()
    assert default_cfg.schema_version == 11
    assert default_cfg.base.opencode_version == "1"
    assert default_cfg.base.executable == "opencode"
    assert default_cfg.base.executable_v2 == "opencode"
    assert default_cfg.opencode.opencode_version == "1"
    assert default_cfg.opencode.executable == "opencode"

    v2_cfg = AgentRemoteConfig.model_validate({
        "schema_version": 11,
        "base": {
            "tool": "opencode",
            "opencode_version": "2",
            "executable": "/opt/opencode1/bin/opencode",
            "executable_v2": "/usr/local/bin/opencode2",
        },
        "model_pool": {
            "models": [
                AgentOpenCodeModelConfig(
                    id="m1",
                    model="openai/gpt-5",
                    enabled=True,
                ).model_dump(),
            ],
        },
    })
    assert v2_cfg.opencode.opencode_version == "2"
    assert v2_cfg.opencode.executable == "/usr/local/bin/opencode2"
    assert v2_cfg.opencode.executable_v2 == "/usr/local/bin/opencode2"
    _validate_managed_config(v2_cfg)

    # Inactive executable can be empty without blocking save of the active version.
    v1_with_blank_v2 = v2_cfg.model_copy(deep=True)
    v1_with_blank_v2.base.opencode_version = "1"
    v1_with_blank_v2.base.executable_v2 = "   "
    _validate_managed_config(v1_with_blank_v2)

    # Active v2 executable cannot be blank.
    v2_blank = v2_cfg.model_copy(deep=True)
    v2_blank.base.executable_v2 = "   "
    with pytest.raises(ApplicationError, match="工具可执行文件不能为空"):
        _validate_managed_config(v2_blank)

    with pytest.raises(ValueError, match="Unsupported OpenCode version"):
        AgentRemoteConfig.model_validate({
            "schema_version": 11,
            "base": {"tool": "opencode", "opencode_version": "3"},
        })


def test_client_config_runtime_and_model_pool_switch_between_v1_and_v2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "deephole_client.opencode_integration.get_global_opencode_workspace",
        lambda: tmp_path / "workspace",
    )
    yaml_path = tmp_path / "agent.yaml"
    yaml_path.write_text("agent_name: dual-opencode\n", encoding="utf-8")

    cfg = load_config(yaml_path)
    apply_remote_config(cfg, {
        "schema_version": 11,
        "base": {
            "tool": "opencode",
            "opencode_version": "2",
            "executable": "/opt/v1/opencode",
            "executable_v2": "/opt/v2/opencode",
            "no_proxy": "127.0.0.1",
            "opencode_serve_port": 4319,
        },
        "model_pool": {
            "models": [{"id": "m1", "model": "deepseek/deepseek-chat", "enabled": True}],
        },
    })
    assert cfg.opencode.opencode_version == "2"
    assert cfg.opencode.executable == "/opt/v1/opencode"
    assert cfg.opencode.executable_v2 == "/opt/v2/opencode"
    assert active_opencode_executable(cfg.opencode) == "/opt/v2/opencode"

    save_config(cfg)
    reloaded = load_config(yaml_path)
    exported = remote_config_dict(reloaded)
    assert exported["base"] == {
        "tool": "opencode",
        "opencode_version": "2",
        "executable": "/opt/v1/opencode",
        "executable_v2": "/opt/v2/opencode",
        "no_proxy": "127.0.0.1",
        "opencode_serve_port": 4319,
    }

    rt_v2 = build_opencode_session_runtime(reloaded.opencode, directory=tmp_path)
    assert rt_v2.opencode_version == "2"
    assert rt_v2.executable == "/opt/v2/opencode"
    assert rt_v2.kwargs()["opencode_version"] == "2"

    reloaded.opencode.opencode_version = "1"
    rt_v1 = build_opencode_session_runtime(reloaded.opencode, directory=tmp_path)
    assert rt_v1.opencode_version == "1"
    assert rt_v1.executable == "/opt/v1/opencode"

    # Model health identity must isolate v1 vs v2 even when executable names match.
    same_name_v1 = OpenCodeConfig(
        opencode_version="1",
        executable="opencode",
        executable_v2="opencode",
        models=[OpenCodeModelConfig(id="m1", model="openai/gpt-5")],
    )
    same_name_v2 = OpenCodeConfig(
        opencode_version="2",
        executable="opencode",
        executable_v2="opencode",
        models=[OpenCodeModelConfig(id="m1", model="openai/gpt-5")],
    )
    opt_v1 = model_options(same_name_v1)[0]
    opt_v2 = model_options(same_name_v2)[0]
    assert _model_health_identity(opt_v1) == ("openai/gpt-5", False, "opencode", "opencode")
    assert _model_health_identity(opt_v2) == ("openai/gpt-5", False, "opencode:2", "opencode")
    assert _model_health_identity(opt_v1) != _model_health_identity(opt_v2)


def test_llm_runtime_marks_dirty_when_opencode_version_or_v2_executable_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deephole_client.main as main
    from task_agent import config_reload

    coordinator = config_reload.ConfigReloadCoordinator()
    monkeypatch.setattr(config_reload, "_coordinator", coordinator)
    monkeypatch.setattr(llm_runtime, "_active", None)
    monkeypatch.setattr(llm_runtime, "_source", None)
    refresh = AsyncMock()
    monkeypatch.setattr(main, "_refresh_live_runtime", refresh)

    async def scenario() -> None:
        cfg = AgentConfig()
        llm_runtime.initialize(cfg)
        coordinator._state = "active"
        coordinator._applied_revision = coordinator._desired_revision

        cfg.opencode.opencode_version = "2"
        await llm_runtime.update(cfg)
        assert refresh.await_args_list[-1].kwargs["mark_dirty"] is True

        cfg.opencode.executable_v2 = "/usr/local/bin/opencode2"
        await llm_runtime.update(cfg)
        assert refresh.await_args_list[-1].kwargs["mark_dirty"] is True

        await llm_runtime.update(cfg)
        assert refresh.await_args_list[-1].kwargs["mark_dirty"] is False

    asyncio.run(scenario())


def test_standalone_yaml_supports_opencode_version_and_executable_v2(tmp_path: Path) -> None:
    project_dir = tmp_path / "src"
    project_dir.mkdir()
    yaml_file = tmp_path / "task-agent.yaml"
    yaml_file.write_text(
        textwrap.dedent(
            f"""\
            schema_version: 2
            context:
              project_dir: {project_dir}
              work_dir: {tmp_path / 'work'}
              workspace_dir: {tmp_path / 'ws'}
            serve:
              tool: opencode
              opencode_version: "2"
              executable: /opt/v1/opencode
              executable_v2: /opt/v2/opencode
              port: 4399
            model_pool:
              models:
                - id: m1
                  model: openai/gpt-5
                  capability: high
                  enabled: true
            """
        ),
        encoding="utf-8",
    )
    loaded = load_standalone_config(yaml_file)
    assert loaded.opencode.opencode_version == "2"
    assert loaded.opencode.executable == "/opt/v2/opencode"

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        yaml_file.read_text(encoding="utf-8").replace('opencode_version: "2"', 'opencode_version: "9"'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="serve.opencode_version must be '1' or '2'"):
        load_standalone_config(bad_yaml)


def test_version_guard_rejects_mismatched_major_without_port_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert normalize_opencode_version("1.x") == "1"
    assert normalize_opencode_version("v2") == "2"
    assert parse_opencode_major_version("1.19.5\n") == ("1", "1.19.5")
    assert parse_opencode_major_version("opencode v2.1.3\n") == ("2", "2.1.3")
    assert parse_opencode_major_version("Bun v1.4.4 (Linux x64)\n") == (None, "")
    assert parse_opencode_major_version("0.0.0-20260901-canary\n") == (None, "0.0.0")

    with pytest.raises(OpenCodeServeStartupError, match="OpenCode 版本不匹配") as exc_info:
        verify_opencode_executable_version(
            configured_version="2",
            executable="/usr/bin/opencode",
            version_output="1.19.5\n",
            error_cls=OpenCodeServeStartupError,
        )
    assert exc_info.value.retry_kind == "config"

    async def run() -> None:
        import task_agent.serve_client as serve_client

        manager = OpenCodeServeManager()
        manager._stop_owned_serve_on_port = AsyncMock(
            return_value=serve_client._PreviousServeCleanupResult()
        )
        start_once = AsyncMock()
        manager._start_once_locked = start_once
        monkeypatch.setattr(serve_client, "_resolve_executable", lambda name: name)

        async def fake_version(_cmd, _timeout=3.0) -> str:
            return "1.19.5\n"

        monkeypatch.setattr(serve_client, "_run_command_text_async", fake_version)
        with pytest.raises(OpenCodeServeStartupError, match="当前配置选择 OpenCode 2.x"):
            await manager._start_locked(
                OpenCodeServeKey(
                    tool="opencode",
                    executable="/usr/bin/opencode",
                    opencode_version="2",
                    serve_port_auto=True,
                ),
                startup_cwd=tmp_path,
            )
        assert start_once.await_count == 0

    asyncio.run(run())


def test_v2_generated_plugins_execute_under_node_esm_contract(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to execute generated ESM plugins")

    config_path = _write_serve_config_file(
        tmp_path,
        json.dumps({"plugins": ["file:///custom/a.mjs"], "plugin": ["file:///custom/b.mjs"]}),
        opencode_version="2",
    )
    written_cfg = json.loads(config_path.read_text(encoding="utf-8"))
    assert "plugins" not in written_cfg
    plugin_uris = written_cfg["plugin"]
    assert plugin_uris[:2] == ["file:///custom/a.mjs", "file:///custom/b.mjs"]
    v2_plugin_uris = [uri for uri in plugin_uris if "opendeephole-" in uri]
    assert len(v2_plugin_uris) == 2
    assert all("-v2-" in uri for uri in v2_plugin_uris)
    from urllib.parse import unquote, urlparse

    v2_plugin_entry_uris: list[str] = []
    for uri in v2_plugin_uris:
        plugin_dir = Path(unquote(urlparse(uri).path))
        assert plugin_dir.is_dir(), f"OpenCode 2.3 requires plugin directory, got {plugin_dir}"
        pkg = json.loads((plugin_dir / "package.json").read_text(encoding="utf-8"))
        assert pkg["type"] == "module"
        assert pkg["main"] == "./index.mjs"
        entry = plugin_dir / "index.mjs"
        assert entry.is_file()
        v2_plugin_entry_uris.append(entry.as_uri())

    session_id = "sess-v2-node-test"
    canonical_cmd = f"{sys.executable} /opt/validator/validate.py --strict"
    _, audit_path = _write_command_binding(
        tmp_path,
        session_id=session_id,
        required_commands=(canonical_cmd,),
        bash_command_match_mode="bound_python_script",
        success_markers=((canonical_cmd, "VALID_OK"),),
        path_prepend=("/opt/custom-bin",),
        tool_rules={"bash": True, "write": True, "read": True, "question": False, "mcp__kb__*": True},
        permission_rules=[
            {"permission": "edit", "pattern": str(tmp_path / "allowed" / "*"), "action": "allow"},
            {"permission": "edit", "pattern": str(tmp_path / "denied" / "*"), "action": "deny"},
        ],
        task_type="threat_analysis",
    )
    _write_knowledge_binding(
        tmp_path,
        session_id=session_id,
        project_id="proj-42",
        mcp_name="kb",
        blocked_tool_ids=["mcp__kb__list_projects", "mcp__kb__set_project"],
    )

    harness = tmp_path / "run_v2_plugins.mjs"
    harness.write_text(
        textwrap.dedent(
            f"""\
            import assert from "node:assert/strict"
            import fs from "node:fs/promises"

            const fwMod = (await import({json.dumps(v2_plugin_entry_uris[0])})).default
            const kbMod = (await import({json.dumps(v2_plugin_entry_uris[1])})).default

            assert.equal(typeof fwMod, "object")
            assert.equal(fwMod.id, "opendeephole-file-write-hook")
            assert.equal(typeof fwMod.setup, "function")
            assert.equal(typeof kbMod, "object")
            assert.equal(kbMod.id, "opendeephole-knowledge-project-hook")
            assert.equal(typeof kbMod.setup, "function")

            const hooks = {{ event: [], perm: [], shell: [], before: [], after: [] }}
            const ctx = {{
              location: {{ directory: {json.dumps(str(tmp_path))} }},
              worktree: {{}},
              event: {{
                subscribe: async (arg) => {{
                  hooks.event.push(arg)
                  async function* stream() {{
                    yield {{
                      type: "session.created",
                      data: {{ sessionID: "child-sess-1", parentID: {json.dumps(session_id)} }},
                    }}
                  }}
                  return stream()
                }},
              }},
              permission: {{ hook: async (name, fn) => {{ if (name === "evaluate") hooks.perm.push(fn) }} }},
              shell: {{ hook: async (name, fn) => {{ if (name === "create.before") hooks.shell.push(fn) }} }},
              tool: {{
                hook: async (name, fn) => {{
                  if (name === "execute.before") hooks.before.push(fn)
                  if (name === "execute.after") hooks.after.push(fn)
                }},
              }},
            }}
            await fwMod.setup(ctx)
            await kbMod.setup(ctx)
            await new Promise((r) => setTimeout(r, 20))

            // 1. Permission evaluation hook (including relative resource paths in OpenCode 2.3)
            const permShellOk = {{ sessionID: {json.dumps(session_id)}, action: "shell", effect: "ask", resources: ["python3 /opt/validator/validate.py --tampered"] }}
            await hooks.perm[0](permShellOk)
            assert.equal(permShellOk.effect, "allow")

            const permShellBad = {{ sessionID: {json.dumps(session_id)}, action: "shell", effect: "ask", resources: ["rm -rf /"] }}
            await hooks.perm[0](permShellBad)
            assert.equal(permShellBad.effect, "deny")

            const permEditRelOk = {{ sessionID: {json.dumps(session_id)}, action: "write", effect: "ask", resources: ["allowed/out.json"] }}
            await hooks.perm[0](permEditRelOk)
            assert.equal(permEditRelOk.effect, "allow")

            const permQuestion = {{ sessionID: {json.dumps(session_id)}, action: "question", effect: "allow", resources: ["*"] }}
            await hooks.perm[0](permQuestion)
            assert.equal(permQuestion.effect, "deny")

            // 2. Shell hook with sessionID (v2.0 style) AND without sessionID (real v2.3.2 style after tool.execute.before)
            const shellEvt = {{
              sessionID: {json.dumps(session_id)},
              command: "python3 /opt/validator/validate.py --wrong-arg",
              env: {{ OPENCODE_SERVER_PASSWORD: "secret", OPENCODE_SERVER_USERNAME: "opencode", PATH: "/usr/bin" }},
            }}
            await hooks.shell[0](shellEvt)
            assert.equal("OPENCODE_SERVER_PASSWORD" in shellEvt.env, false)
            assert.equal("OPENCODE_SERVER_USERNAME" in shellEvt.env, false)
            assert.equal(shellEvt.env.PATH.startsWith("/opt/custom-bin"), true)
            assert.equal(shellEvt.command, {json.dumps(canonical_cmd)})

            // 3. Real OpenCode 2.3 single-arg tool.execute.before + shell.create.before without sessionID + single-arg execute.after
            const shellInput = {{ command: "python3 /opt/validator/validate.py --ignored" }}
            await hooks.before[0]({{ tool: "shell", sessionID: {json.dumps(session_id)}, id: "c1", input: shellInput }})
            assert.equal(shellInput.command, {json.dumps(canonical_cmd)})

            const shellEvtNoSid = {{
              command: shellInput.command,
              env: {{ OPENCODE_SERVER_PASSWORD: "secret2", PATH: "/usr/bin" }},
            }}
            await hooks.shell[0](shellEvtNoSid)
            assert.equal("OPENCODE_SERVER_PASSWORD" in shellEvtNoSid.env, false)
            assert.equal(shellEvtNoSid.env.PATH.startsWith("/opt/custom-bin"), true)

            await hooks.after[0]({{
              tool: "shell",
              sessionID: {json.dumps(session_id)},
              id: "c1",
              input: shellInput,
              status: "completed",
              result: {{
                output: {{ exitCode: 0, output: "running...\\nVALID_OK\\n" }},
                content: [{{ type: "text", text: "running...\\nVALID_OK\\n" }}],
                metadata: {{ status: "completed", exit: 0 }},
              }},
            }})

            const writeAfterEvt = {{
              tool: "write",
              sessionID: {json.dumps(session_id)},
              id: "c2",
              input: {{ path: "allowed/result.json", content: "hi" }},
              status: "completed",
              result: {{ output: "Created file successfully: allowed/result.json", content: [{{ type: "text", text: "Created file successfully: allowed/result.json" }}] }},
            }}
            await hooks.after[0](writeAfterEvt)
            assert.equal(writeAfterEvt.result.metadata.opendeepholeFileWrites.files.length, 1)
            assert.equal(writeAfterEvt.result.metadata.opendeepholeFileWrites.files[0].created, true)

            // Knowledge plugin blocks set_project and injects project_id on query tools (including inherited child session!)
            await assert.rejects(
              () => hooks.before[1]({{ tool: "mcp__kb__set_project", sessionID: "child-sess-1", input: {{}} }}),
              /platform-only/,
            )
            const kbQueryArgs = {{ query: "auth" }}
            await hooks.before[1]({{ tool: "mcp__kb__search_docs", sessionID: "child-sess-1", input: kbQueryArgs }})
            assert.equal(kbQueryArgs.project_id, "proj-42")
            console.log("NODE_V2_PLUGINS_OK")
            """
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [node, str(harness)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    assert "NODE_V2_PLUGINS_OK" in completed.stdout

    audits = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [entry["kind"] for entry in audits] == ["command", "file_write"]
    assert audits[0]["success"] is True
    assert audits[0]["success_marker_matched"] is True
    assert audits[1]["path"] == str((tmp_path / "allowed" / "result.json").resolve())


def _create_mock_opencode_v2_binary(tmp_path: Path, state_file: Path) -> Path:
    """Create an executable script that speaks OpenCode 2.x HTTP + SSE with mandatory Basic Auth."""
    server_script = tmp_path / "mock_opencode_v2_server.py"
    server_script.write_text(
        textwrap.dedent(
            """\
            from __future__ import annotations
            import asyncio
            import base64
            import json
            import os
            import sys
            from pathlib import Path
            from urllib.parse import parse_qs, urlsplit

            STATE_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else None

            def record(event: dict) -> None:
                if STATE_FILE is None:
                    return
                with STATE_FILE.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\\n")

            if "--version" in sys.argv:
                print("opencode 2.1.4")
                raise SystemExit(0)

            idx = sys.argv.index("--port")
            PORT = int(sys.argv[idx + 1])
            USERNAME = os.environ.get("OPENCODE_SERVER_USERNAME", "opencode")
            PASSWORD = os.environ.get("OPENCODE_SERVER_PASSWORD", "")
            if not PASSWORD:
                print("missing OPENCODE_SERVER_PASSWORD", file=sys.stderr)
                raise SystemExit(2)
            EXPECTED_AUTH = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

            sessions: dict[str, dict] = {}
            messages: dict[str, list[dict]] = {}
            mcps: dict[str, dict] = {}
            sse_queues: list[asyncio.Queue] = []
            seq = 0

            def broadcast(event: dict) -> None:
                for q in list(sse_queues):
                    q.put_nowait(event)

            async def send_json(writer: asyncio.StreamWriter, status: int, payload: object) -> None:
                reason = {200: "OK", 201: "Created", 202: "Accepted", 401: "Unauthorized", 404: "Not Found"}.get(status, "OK")
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                headers = (
                    f"HTTP/1.1 {status} {reason}\\r\\n"
                    "Content-Type: application/json\\r\\n"
                    f"Content-Length: {len(body)}\\r\\n"
                    "Connection: close\\r\\n\\r\\n"
                ).encode("ascii")
                writer.write(headers + body)
                await writer.drain()
                writer.close()

            async def run_async_turn(session_id: str, body: dict) -> None:
                global seq
                await asyncio.sleep(0.05)
                prompt_text = str(body.get("prompt") or "")
                model_obj = body.get("model") or {"providerID": "mock", "modelID": "v2-pro"}
                # Emit interactive permission.asked to verify unattended auto-rejection
                broadcast({
                    "payload": {
                        "type": "permission.asked",
                        "properties": {"id": "perm-req-1", "sessionID": session_id},
                    }
                })
                broadcast({
                    "payload": {
                        "type": "session.tool.called",
                        "properties": {"sessionID": session_id, "callID": "call-1", "tool": "read", "input": {"filePath": "a.c"}},
                    }
                })
                broadcast({
                    "payload": {
                        "type": "session.tool.success",
                        "properties": {"sessionID": session_id, "callID": "call-1", "content": "int main() {}"},
                    }
                })
                seq += 1
                step1_id = f"msg-{seq}"
                messages.setdefault(session_id, []).append({
                    "id": step1_id,
                    "sessionID": session_id,
                    "role": "assistant",
                    "providerID": model_obj["providerID"],
                    "modelID": model_obj["modelID"],
                    "finish": "tool-calls",
                    "time": {"created": 1, "completed": 2},
                    "tokens": {"input": 100, "output": 25, "reasoning": 5, "cache": {"read": 10, "write": 0}},
                    "parts": [{"type": "tool", "callID": "call-1", "tool": "read", "state": {"status": "completed", "input": {"filePath": "a.c"}, "output": "ok"}}],
                })
                # Create a child session to exercise GET /api/session?parentID=... token tree collection
                child_id = f"{session_id}-child"
                sessions[child_id] = {"id": child_id, "parentID": session_id, "status": {"type": "idle"}}
                messages[child_id] = [{
                    "id": f"child-msg-{seq}",
                    "sessionID": child_id,
                    "role": "assistant",
                    "providerID": model_obj["providerID"],
                    "modelID": model_obj["modelID"],
                    "finish": "stop",
                    "time": {"created": 1, "completed": 2},
                    "tokens": {"input": 40, "output": 10, "reasoning": 0, "cache": {"read": 0, "write": 0}},
                    "parts": [{"type": "text", "text": "subtask ok"}],
                }]
                await asyncio.sleep(0.05)
                reply_json = json.dumps({"verdict": "ok-v2", "echo": prompt_text[:24]}, ensure_ascii=False)
                broadcast({
                    "payload": {
                        "type": "session.text.delta",
                        "properties": {"sessionID": session_id, "delta": reply_json},
                    }
                })
                broadcast({
                    "payload": {
                        "type": "session.text.ended",
                        "properties": {"sessionID": session_id, "text": reply_json},
                    }
                })
                seq += 1
                step2_id = f"msg-{seq}"
                messages.setdefault(session_id, []).append({
                    "id": step2_id,
                    "sessionID": session_id,
                    "role": "assistant",
                    "providerID": model_obj["providerID"],
                    "modelID": model_obj["modelID"],
                    "finish": "stop",
                    "time": {"created": 3, "completed": 4},
                    "tokens": {"input": 60, "output": 15, "reasoning": 0, "cache": {"read": 0, "write": 0}},
                    "parts": [{"type": "text", "text": reply_json}],
                })
                sessions[session_id]["status"] = {"type": "idle"}
                broadcast({
                    "payload": {
                        "type": "session.status",
                        "properties": {"sessionID": session_id, "status": {"type": "idle"}},
                    }
                })

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                global seq
                try:
                    req_line = await reader.readline()
                    if not req_line:
                        writer.close()
                        return
                    method, raw_target, _ = req_line.decode("latin1").strip().split(" ", 2)
                    headers: dict[str, str] = {}
                    while True:
                        line = await reader.readline()
                        if line in (b"\\r\\n", b"\\n", b""):
                            break
                        k, v = line.decode("latin1").split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                    length = int(headers.get("content-length", "0") or 0)
                    raw_body = await reader.readexactly(length) if length > 0 else b""
                    parsed_url = urlsplit(raw_target)
                    path = parsed_url.path
                    query = parse_qs(parsed_url.query)

                    if headers.get("authorization") != EXPECTED_AUTH:
                        record({"kind": "unauthorized", "path": path})
                        await send_json(writer, 401, {"error": "Unauthorized"})
                        return

                    record({"kind": "request", "method": method, "path": path})

                    # V1 routes intentionally 404 on this pure V2 server
                    if not path.startswith("/api/"):
                        await send_json(writer, 404, {"error": "v1 route removed in v2"})
                        return

                    if method == "GET" and path == "/api/health":
                        await send_json(writer, 200, {"healthy": True, "pid": os.getpid(), "version": "2.1.4"})
                        return

                    if method == "GET" and path == "/api/doc":
                        await send_json(writer, 200, {
                            "openapi": "3.1.0",
                            "paths": {
                                "/api/health": {},
                                "/api/provider": {},
                                "/api/tool/ids": {},
                                "/api/mcp": {},
                                "/api/session": {},
                                "/api/session/{sessionID}/prompt": {},
                                "/api/session/{sessionID}/interrupt": {},
                            },
                        })
                        return

                    if method == "GET" and path == "/api/provider":
                        await send_json(writer, 200, {
                            "all": [{
                                "id": "mock",
                                "name": "Mock V2 Provider",
                                "models": {
                                    "v2-pro": {
                                        "id": "v2-pro",
                                        "name": "Mock V2 Pro",
                                        "limit": {"context": 128000, "output": 16000},
                                    }
                                },
                            }],
                            "connected": ["mock"],
                        })
                        return

                    if method == "GET" and path == "/api/tool/ids":
                        await send_json(writer, 200, {"ids": ["read", "write", "edit", "bash"]})
                        return

                    if path == "/api/mcp":
                        if method == "POST":
                            body = json.loads(raw_body.decode("utf-8") or "{}")
                            mcps[body["name"]] = {"status": "connected" if body.get("config", {}).get("enabled", True) else "disabled"}
                        await send_json(writer, 200, mcps)
                        return

                    if method == "GET" and path in {"/api/global/event", "/api/event"}:
                        q: asyncio.Queue = asyncio.Queue()
                        sse_queues.append(q)
                        writer.write(
                            b"HTTP/1.1 200 OK\\r\\n"
                            b"Content-Type: text/event-stream\\r\\n"
                            b"Cache-Control: no-cache\\r\\n"
                            b"Connection: keep-alive\\r\\n\\r\\n"
                        )
                        writer.write(b'data: {"payload":{"type":"server.connected","properties":{}}}\\n\\n')
                        await writer.drain()
                        try:
                            while True:
                                evt = await q.get()
                                writer.write(f"data: {json.dumps(evt, ensure_ascii=False)}\\n\\n".encode("utf-8"))
                                await writer.drain()
                        except Exception:
                            pass
                        finally:
                            if q in sse_queues:
                                sse_queues.remove(q)
                            writer.close()
                        return

                    if path == "/api/session" and method == "POST":
                        seq += 1
                        sid = f"v2-sess-{seq}"
                        body = json.loads(raw_body.decode("utf-8") or "{}")
                        sessions[sid] = {"id": sid, "title": body.get("title", ""), "status": {"type": "idle"}}
                        messages[sid] = []
                        await send_json(writer, 201, sessions[sid])
                        return

                    if path == "/api/session" and method == "GET":
                        parent_filter = (query.get("parentID") or [""])[0]
                        items = list(sessions.values())
                        if parent_filter:
                            items = [s for s in items if s.get("parentID") == parent_filter]
                        await send_json(writer, 200, items)
                        return

                    parts = [p for p in path.split("/") if p]
                    # parts: ["api", "session", sid, ...]
                    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "session":
                        sid = parts[2]
                        if len(parts) == 3 and method == "GET":
                            if sid not in sessions:
                                await send_json(writer, 404, {"error": "not found"})
                            else:
                                await send_json(writer, 200, sessions[sid])
                            return
                        if len(parts) == 3 and method == "PATCH":
                            # OpenCode 2.x may not expose PATCH permission on session
                            await send_json(writer, 405, {"error": "method not allowed"})
                            return
                        if len(parts) == 4 and parts[3] == "prompt" and method == "POST":
                            body = json.loads(raw_body.decode("utf-8") or "{}")
                            sessions[sid]["status"] = {"type": "busy"}
                            asyncio.create_task(run_async_turn(sid, body))
                            await send_json(writer, 202, {"queued": True, "sessionID": sid})
                            return
                        if len(parts) == 4 and parts[3] == "message" and method == "GET":
                            await send_json(writer, 200, {"messages": messages.get(sid, [])})
                            return
                        if len(parts) == 4 and parts[3] == "interrupt" and method == "POST":
                            record({"kind": "interrupt", "sessionID": sid})
                            sessions.setdefault(sid, {"id": sid})["status"] = {"type": "idle"}
                            await send_json(writer, 200, {"interrupted": True})
                            return
                        if len(parts) == 6 and parts[3] == "permission" and parts[5] == "reply" and method == "POST":
                            body = json.loads(raw_body.decode("utf-8") or "{}")
                            record({"kind": "permission_reply", "sessionID": sid, "requestID": parts[4], "body": body})
                            await send_json(writer, 200, {"ok": True})
                            return

                    await send_json(writer, 404, {"error": f"unhandled {method} {path}"})
                except Exception as exc:
                    record({"kind": "server_error", "error": repr(exc)})
                    try:
                        writer.close()
                    except Exception:
                        pass

            async def main() -> None:
                server = await asyncio.start_server(handle, "127.0.0.1", PORT)
                async with server:
                    await server.serve_forever()

            asyncio.run(main())
            """
        ),
        encoding="utf-8",
    )
    wrapper = tmp_path / "opencode2-mock"
    wrapper.write_text(
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(server_script))} {shlex.quote(str(state_file))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


import shlex  # noqa: E402


def test_end_to_end_opencode_v2_serve_models_prompt_continuation_and_interrupt(
    tmp_path: Path,
) -> None:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = int(sock.getsockname()[1])

    state_file = tmp_path / "v2_server_events.jsonl"
    v2_bin = _create_mock_opencode_v2_binary(tmp_path, state_file)
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "a.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    standalone_yaml = tmp_path / "task-agent-v2.yaml"
    standalone_yaml.write_text(
        textwrap.dedent(
            f"""\
            schema_version: 2
            context:
              project_dir: {project_dir}
              work_dir: {tmp_path / 'work'}
              workspace_dir: {tmp_path / 'workspace'}
            serve:
              tool: opencode
              opencode_version: "2"
              executable: /nonexistent/opencode-v1
              executable_v2: {v2_bin}
              port: {free_port}
              timeout: 30
              idle_timeout: 15
            model_pool:
              models:
                - id: mock/v2-pro
                  model: mock/v2-pro
                  capability: high
                  enabled: true
            """
        ),
        encoding="utf-8",
    )
    output_schema = {
        "type": "object",
        "properties": {
            "verdict": {"type": "string"},
            "echo": {"type": "string"},
        },
        "required": ["verdict", "echo"],
        "additionalProperties": False,
    }

    async def scenario() -> None:
        await shutdown_opencode()
        try:
            streamed_lines: list[str] = []
            first = await run_opencode_task(
                task_name="v2-audit-1",
                task_type="vulnerability_mining",
                prompt="audit first turn",
                required_capability="high",
                output_schema=output_schema,
                config_path=standalone_yaml,
                output=streamed_lines.append,
            )
            assert first.status == "success"
            assert first.structured == {"verdict": "ok-v2", "echo": "audit first turn"}
            assert first.session_id.startswith("v2-sess-")
            # Parent (100+60 input, 25+15 output) + child (40 input, 10 output) = 200 input, 50 output
            assert first.token_usage is not None
            assert first.token_usage["input_tokens"] == 200
            assert first.token_usage["output_tokens"] == 50
            assert any("TOOL CALL" in line or "read" in line for line in streamed_lines)

            # Continuation on the same V2 session
            second = await run_opencode_task(
                task_name="v2-audit-2",
                task_type="vulnerability_mining",
                prompt="audit second turn",
                required_capability="high",
                output_schema=output_schema,
                session_id=first.session_id,
                config_path=standalone_yaml,
            )
            assert second.status == "success"
            assert second.session_id == first.session_id
            assert second.structured == {"verdict": "ok-v2", "echo": "audit second turn"}

            # Verify direct ServeManager v2 model listing, child lookup, auth enforcement, and interrupt
            from task_agent.serve_client import get_serve_manager
            import httpx

            manager = get_serve_manager()
            # Unauthenticated request to the live V2 Serve must fail with 401
            async with httpx.AsyncClient(base_url=manager.base_url, trust_env=False) as raw_client:
                unauth = await raw_client.get("/api/health")
                assert unauth.status_code == 401

            assert manager._key is not None
            runtime_kwargs = {
                "tool": "opencode",
                "executable": str(v2_bin),
                "opencode_version": "2",
                "directory": project_dir,
                "config_workspace": tmp_path / "workspace",
                "config_content": manager._key.config_content,
                "env_overrides": {"OPENCODE_SERVE_PORT": str(free_port)},
            }
            models_res = await manager.list_models(**runtime_kwargs, refresh=True)
            assert [m.id for m in models_res.models] == ["mock/v2-pro"]

            children = await manager.get_session_children(first.session_id, **runtime_kwargs)
            assert [c["id"] for c in children] == [f"{first.session_id}-child"]

            aborted = await manager.abort_session(first.session_id, **runtime_kwargs)
            assert aborted == {"interrupted": True}

            # Allow background auto-reject task to flush
            await asyncio.sleep(0.05)
        finally:
            await shutdown_opencode()

    asyncio.run(scenario())

    events = [
        json.loads(line)
        for line in state_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kinds = [e["kind"] for e in events]
    assert "unauthorized" in kinds
    assert "interrupt" in kinds
    perm_replies = [e for e in events if e["kind"] == "permission_reply"]
    assert perm_replies and perm_replies[0]["body"]["effect"] == "deny"


def _create_mock_opencode_v232_binary(tmp_path: Path, state_file: Path) -> Path:
    """Create a mock OpenCode 2.3.2 server matching real v2.3 Effect HttpApi + SPA HTML fallback."""
    server_script = tmp_path / "mock_opencode_v232_server.py"
    server_script.write_text(
        textwrap.dedent(
            """\
            from __future__ import annotations
            import asyncio
            import base64
            import json
            import os
            import sys
            from pathlib import Path
            from urllib.parse import urlsplit

            STATE_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else None

            def record(event: dict) -> None:
                if STATE_FILE is None:
                    return
                with STATE_FILE.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\\n")

            if "--version" in sys.argv:
                print("opencode v2.3.2")
                raise SystemExit(0)

            idx = sys.argv.index("--port")
            PORT = int(sys.argv[idx + 1])
            USERNAME = os.environ.get("OPENCODE_SERVER_USERNAME", "opencode")
            PASSWORD = os.environ.get("OPENCODE_SERVER_PASSWORD", "")
            EXPECTED_AUTH = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

            sessions: dict[str, dict] = {}
            messages: dict[str, list[dict]] = {}
            sse_queues: list[asyncio.Queue] = []
            seq = 0

            def broadcast(event: dict) -> None:
                for q in list(sse_queues):
                    q.put_nowait(event)

            async def send_json(writer: asyncio.StreamWriter, status: int, payload: object) -> None:
                reason = {200: "OK", 201: "Created", 202: "Accepted", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}.get(status, "OK")
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                headers = (
                    f"HTTP/1.1 {status} {reason}\\r\\n"
                    "Content-Type: application/json\\r\\n"
                    f"Content-Length: {len(body)}\\r\\n"
                    "Connection: close\\r\\n\\r\\n"
                ).encode("ascii")
                writer.write(headers + body)
                await writer.drain()
                writer.close()

            async def send_spa_html(writer: asyncio.StreamWriter) -> None:
                body = b"<!doctype html><html><body>OpenCode Web Shell</body></html>"
                headers = (
                    "HTTP/1.1 200 OK\\r\\n"
                    "Content-Type: text/html; charset=utf-8\\r\\n"
                    f"Content-Length: {len(body)}\\r\\n"
                    "Connection: close\\r\\n\\r\\n"
                ).encode("ascii")
                writer.write(headers + body)
                await writer.drain()
                writer.close()

            async def run_v232_turn(session_id: str, prompt_text: str) -> None:
                global seq
                await asyncio.sleep(0.04)
                broadcast({"type": "session.status", "properties": {"sessionID": session_id, "status": {"type": "busy"}}})
                seq += 1
                reply = json.dumps({"verdict": "ok-v232", "echo": prompt_text[-18:]}, ensure_ascii=False)
                # Intentionally omit `time.completed` and `info.finish` to mirror v2.3 rows
                messages.setdefault(session_id, []).append({
                    "id": f"msg-232-{seq}",
                    "sessionID": session_id,
                    "role": "assistant",
                    "time": {"created": 100},
                    "parts": [{"id": f"prt-{seq}", "type": "text", "text": reply}],
                })
                sessions[session_id]["status"] = {"type": "idle"}
                broadcast({"type": "session.status", "properties": {"sessionID": session_id, "status": {"type": "idle"}}})

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                global seq
                try:
                    req_line = await reader.readline()
                    if not req_line:
                        writer.close()
                        return
                    method, raw_target, _ = req_line.decode("latin1").strip().split(" ", 2)
                    headers: dict[str, str] = {}
                    while True:
                        line = await reader.readline()
                        if line in (b"\\r\\n", b"\\n", b""):
                            break
                        k, v = line.decode("latin1").split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                    length = int(headers.get("content-length", "0") or 0)
                    raw_body = await reader.readexactly(length) if length > 0 else b""
                    path = urlsplit(raw_target).path

                    if headers.get("authorization") != EXPECTED_AUTH:
                        await send_json(writer, 401, {"error": "Unauthorized"})
                        return

                    record({"kind": "request", "method": method, "path": path})

                    # Real OpenCode v2.3.2 health/discovery endpoint: ServerInfo without `healthy: true`
                    if method == "GET" and path == "/api/info":
                        await send_json(writer, 200, {
                            "version": "2.3.2",
                            "pid": os.getpid(),
                            "urls": [f"http://127.0.0.1:{PORT}"],
                            "paths": {"tmp": "/tmp/opencode"},
                        })
                        return

                    # Real OpenCode v2.3.2 OpenAPI spec at `/doc` with strict Effect Schema definitions
                    if method == "GET" and path == "/doc":
                        await send_json(writer, 200, {
                            "openapi": "3.1.0",
                            "paths": {
                                "/api/info": {"get": {}},
                                "/api/model": {"get": {}},
                                "/api/provider": {"get": {}},
                                "/api/config": {"get": {}},
                                "/api/event": {"get": {}},
                                "/api/session": {
                                    "get": {},
                                    "post": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {"$ref": "#/components/schemas/SessionCreateInput"}
                                                }
                                            }
                                        }
                                    },
                                },
                                "/api/session/{id}/message": {"get": {}},
                                "/api/session/{id}/prompt": {
                                    "post": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {"$ref": "#/components/schemas/SessionPromptInput"}
                                                }
                                            }
                                        }
                                    }
                                },
                                "/api/session/{id}/interrupt": {"post": {}},
                            },
                            "components": {
                                "schemas": {
                                    "SessionCreateInput": {
                                        "type": "object",
                                        "properties": {
                                            "title": {"type": "string"},
                                            "location": {
                                                "type": "object",
                                                "properties": {"directory": {"type": "string"}},
                                            },
                                        },
                                        "additionalProperties": False,
                                    },
                                    "SessionPromptInput": {
                                        "type": "object",
                                        "properties": {
                                            "parts": {"type": "array", "items": {"type": "object"}},
                                            "agent": {"type": "string"},
                                            "model": {
                                                "type": "object",
                                                "properties": {
                                                    "providerID": {"type": "string"},
                                                    "modelID": {"type": "string"},
                                                },
                                            },
                                        },
                                        "additionalProperties": False,
                                    },
                                }
                            },
                        })
                        return

                    # Real v2.3 `/api/provider` returns provider ID strings; `/api/model` returns catalog
                    if method == "GET" and path == "/api/provider":
                        await send_json(writer, 200, ["opencode", "openai-compatible"])
                        return

                    if method == "GET" and path == "/api/model":
                        await send_json(writer, 200, [
                            {
                                "id": "Qwen3-Coder",
                                "modelID": "Qwen3-Coder",
                                "providerID": "openai-compatible",
                                "name": "Qwen3 Coder",
                                "enabled": True,
                                "status": "active",
                                "limit": {"context": 200000, "output": 32000},
                            },
                            {
                                "id": "unconfigured-claude",
                                "modelID": "claude-4",
                                "providerID": "anthropic",
                                "name": "Unconfigured Claude",
                                "enabled": False,
                                "status": "disabled",
                                "limit": {"context": 200000, "output": 16000},
                            },
                        ])
                        return

                    if method == "GET" and path == "/api/config":
                        await send_json(writer, 200, {"provider": {}})
                        return

                    if method == "GET" and path == "/api/event":
                        q: asyncio.Queue = asyncio.Queue()
                        sse_queues.append(q)
                        writer.write(
                            b"HTTP/1.1 200 OK\\r\\n"
                            b"Content-Type: text/event-stream\\r\\n"
                            b"Cache-Control: no-cache\\r\\n"
                            b"Connection: keep-alive\\r\\n\\r\\n"
                        )
                        writer.write(b'data: {"type":"server.connected","properties":{}}\\n\\n')
                        await writer.drain()
                        try:
                            while True:
                                evt = await q.get()
                                writer.write(f"data: {json.dumps(evt, ensure_ascii=False)}\\n\\n".encode("utf-8"))
                                await writer.drain()
                        except Exception:
                            pass
                        finally:
                            if q in sse_queues:
                                sse_queues.remove(q)
                            writer.close()
                        return

                    if path == "/api/session" and method == "POST":
                        body = json.loads(raw_body.decode("utf-8") or "{}")
                        extra = set(body) - {"title", "location"}
                        if extra:
                            record({"kind": "schema_rejected", "path": path, "extra": sorted(extra)})
                            await send_json(writer, 400, {"error": f"Unexpected properties: {sorted(extra)}"})
                            return
                        seq += 1
                        sid = f"v232-sess-{seq}"
                        sessions[sid] = {"id": sid, "title": body.get("title", ""), "status": {"type": "idle"}}
                        messages[sid] = []
                        await send_json(writer, 201, sessions[sid])
                        return

                    if path == "/api/session" and method == "GET":
                        await send_json(writer, 200, [])
                        return

                    parts = [p for p in path.split("/") if p]
                    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "session":
                        sid = parts[2]
                        if len(parts) == 3 and method == "GET":
                            await send_json(writer, 200, sessions[sid])
                            return
                        if len(parts) == 4 and parts[3] == "prompt" and method == "POST":
                            body = json.loads(raw_body.decode("utf-8") or "{}")
                            extra = set(body) - {"parts", "agent", "model"}
                            if extra or not isinstance(body.get("parts"), list):
                                record({"kind": "schema_rejected", "path": path, "extra": sorted(extra)})
                                await send_json(writer, 400, {"error": f"Invalid prompt schema: {sorted(extra)}"})
                                return
                            prompt_text = "".join(str(p.get("text") or "") for p in body["parts"] if isinstance(p, dict))
                            sessions[sid]["status"] = {"type": "busy"}
                            asyncio.create_task(run_v232_turn(sid, prompt_text))
                            await send_json(writer, 202, {"accepted": True})
                            return
                        if len(parts) == 4 and parts[3] == "message" and method == "GET":
                            await send_json(writer, 200, {"data": messages.get(sid, [])})
                            return

                    # Unmatched GET routes (including `/api/health`, `/global/health`, `/api/global/event`,
                    # `/api/tool/ids`, `/api/config/providers`) return HTTP 200 SPA HTML in OpenCode 2.3.2!
                    if method == "GET":
                        record({"kind": "spa_html_fallback", "path": path})
                        await send_spa_html(writer)
                        return

                    await send_json(writer, 404, {"error": f"unhandled {method} {path}"})
                except Exception as exc:
                    record({"kind": "server_error", "error": repr(exc)})
                    try:
                        writer.close()
                    except Exception:
                        pass

            async def main() -> None:
                server = await asyncio.start_server(handle, "127.0.0.1", PORT)
                async with server:
                    await server.serve_forever()

            asyncio.run(main())
            """
        ),
        encoding="utf-8",
    )
    wrapper = tmp_path / "opencode232-mock"
    wrapper.write_text(
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(server_script))} {shlex.quote(str(state_file))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def test_opencode_v232_api_info_html_fallback_model_catalog_and_strict_schema(
    tmp_path: Path,
) -> None:
    """Regression test for OpenCode 2.3.2 `/api/info` health check, HTML fallback routes, and Effect Schema."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = int(sock.getsockname()[1])

    state_file = tmp_path / "v232_events.jsonl"
    v232_bin = _create_mock_opencode_v232_binary(tmp_path, state_file)
    project_dir = tmp_path / "project232"
    project_dir.mkdir()
    standalone_yaml = tmp_path / "task-agent-v232.yaml"
    standalone_yaml.write_text(
        textwrap.dedent(
            f"""\
            schema_version: 2
            context:
              project_dir: {project_dir}
              work_dir: {tmp_path / 'work232'}
              workspace_dir: {tmp_path / 'workspace232'}
            serve:
              tool: opencode
              opencode_version: "2"
              executable: /nonexistent/opencode-v1
              executable_v2: {v232_bin}
              port: {free_port}
              timeout: 30
              idle_timeout: 15
            model_pool:
              models:
                - id: openai-compatible/Qwen3-Coder
                  model: openai-compatible/Qwen3-Coder
                  capability: high
                  enabled: true
            """
        ),
        encoding="utf-8",
    )
    output_schema = {
        "type": "object",
        "properties": {
            "verdict": {"type": "string"},
            "echo": {"type": "string"},
        },
        "required": ["verdict", "echo"],
        "additionalProperties": False,
    }

    async def scenario() -> None:
        from task_agent.serve_client import get_serve_manager

        await shutdown_opencode()
        try:
            manager = get_serve_manager()
            reloaded = await manager.reload_runtime(
                tool="opencode",
                executable=str(v232_bin),
                opencode_version="2",
                directory=project_dir,
                config_workspace=tmp_path / "workspace232",
                config_content="{}",
                serve_port_auto=True,
            )
            assert [m.id for m in reloaded.models] == ["openai-compatible/Qwen3-Coder"]

            res = await run_opencode_task(
                task_name="v232-threat-check",
                task_type="threat_analysis",
                prompt="verify v232 prompt",
                required_capability="high",
                output_schema=output_schema,
                config_path=standalone_yaml,
            )
            assert res.status == "success"
            assert res.structured == {"verdict": "ok-v232", "echo": "verify v232 prompt"}
        finally:
            await shutdown_opencode()

    asyncio.run(scenario())

    events = [
        json.loads(line)
        for line in state_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rejected = [e for e in events if e.get("kind") == "schema_rejected"]
    assert rejected == [], f"Unexpected Effect Schema rejections: {rejected}"
    info_calls = [e for e in events if e.get("kind") == "request" and e.get("path") == "/api/info"]
    assert len(info_calls) >= 2


def test_platform_runtime_preserves_opencode_v2_for_scan_resume_and_live_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.config as backend_config
    from deephole_client.platform_runtime import (
        configure_platform_runtime,
        ensure_platform_runtime_configured,
        refresh_platform_runtime_config,
    )
    from task_agent.host import (
        _get_opencode_configuration_state,
        configure_opencode,
        reset_opencode_configuration,
    )

    previous_host_state = _get_opencode_configuration_state()
    monkeypatch.setattr(backend_config, "_config", None)
    monkeypatch.setattr(llm_runtime, "_active", None)
    monkeypatch.setattr(llm_runtime, "_source", None)
    monkeypatch.delenv("CONFIG_PATH", raising=False)
    monkeypatch.setattr(
        "deephole_client.opencode_integration.get_global_opencode_workspace",
        lambda: tmp_path / "workspace",
    )

    try:
        cfg = AgentConfig()
        apply_remote_config(cfg, {
            "schema_version": 11,
            "base": {
                "tool": "opencode",
                "opencode_version": "2",
                "executable": "/opt/v1/opencode",
                "executable_v2": "/opt/v2/opencode",
                "no_proxy": "10.0.0.0/8",
                "opencode_serve_port": None,
            },
            "model_pool": {
                "models": [
                    {"id": "m1", "model": "openai/gpt-5", "enabled": True},
                ],
            },
        })

        scan_dir = tmp_path / "scans" / "scan-resume-v2"
        configure_platform_runtime(cfg, scan_dir)

        loaded = backend_config.get_config()
        assert loaded.opencode.opencode_version == "2"
        assert loaded.opencode.executable == "/opt/v1/opencode"
        assert loaded.opencode.executable_v2 == "/opt/v2/opencode"

        options = model_options(loaded.opencode)
        assert len(options) == 1
        assert options[0].opencode_version == "2"
        assert options[0].executable == "/opt/v2/opencode"

        runtime = build_opencode_session_runtime(loaded.opencode, directory=tmp_path)
        assert runtime.opencode_version == "2"
        assert runtime.executable == "/opt/v2/opencode"

        # Live refresh immediately after configure_platform_runtime must update the
        # active backend config in-place without dropping opencode_version.
        cfg.opencode.opencode_version = "1"
        refresh_platform_runtime_config(cfg)
        assert backend_config.get_config().opencode.opencode_version == "1"

        cfg.opencode.opencode_version = "2"
        cfg.opencode.executable = "opencode"
        cfg.opencode.executable_v2 = "opencode"
        refresh_platform_runtime_config(cfg)
        refreshed = backend_config.get_config()
        assert refreshed.opencode.opencode_version == "2"
        assert refreshed.opencode.executable_v2 == "opencode"
        assert build_opencode_session_runtime(refreshed.opencode, directory=tmp_path).opencode_version == "2"

        # Starting from an uninitialized backend config (e.g., Agent startup or
        # standalone fp_review / vulnerability_validation), ensure_platform_runtime_configured
        # must populate backend.config._config with the active 2.x settings.
        backend_config._config = None
        ensure_platform_runtime_configured(SimpleNamespace())  # type: ignore[arg-type]
        assert backend_config._config is None
        ensure_platform_runtime_configured(cfg)
        assert backend_config._config is not None
        assert backend_config.get_config().opencode.opencode_version == "2"
        assert backend_config.get_config().opencode.executable_v2 == "opencode"
    finally:
        if previous_host_state[0] == "host" and previous_host_state[1] is not None:
            configure_opencode(previous_host_state[1])
        else:
            reset_opencode_configuration()


def test_backend_config_load_normalizes_opencode_version_and_executable_v2(tmp_path: Path) -> None:
    import backend.config as backend_config

    explicit_yaml = tmp_path / "explicit.yaml"
    explicit_yaml.write_text(
        textwrap.dedent(
            """\
            opencode:
              tool: opencode
              opencode_version: "2.x"
              executable: /opt/v1/opencode
              executable_v2: /opt/v2/opencode
            """
        ),
        encoding="utf-8",
    )
    loaded = backend_config.load_config(str(explicit_yaml))
    assert loaded.opencode.opencode_version == "2"
    assert loaded.opencode.executable == "/opt/v1/opencode"
    assert loaded.opencode.executable_v2 == "/opt/v2/opencode"

    legacy_v2_yaml = tmp_path / "legacy-v2.yaml"
    legacy_v2_yaml.write_text(
        textwrap.dedent(
            """\
            opencode:
              tool: opencode
              opencode_version: "2"
              executable: /custom/opencode2
            """
        ),
        encoding="utf-8",
    )
    legacy_loaded = backend_config.load_config(str(legacy_v2_yaml))
    assert legacy_loaded.opencode.opencode_version == "2"
    assert legacy_loaded.opencode.executable_v2 == "/custom/opencode2"

    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text(
        "opencode:\n  opencode_version: '3'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unsupported OpenCode version"):
        backend_config.load_config(str(invalid_yaml))


def test_opencode_v232_wire_helpers_envelopes_messages_permissions_mcp_and_sse(tmp_path: Path) -> None:
    """Unit tests covering exact OpenCode 2.3.2 OpenAPI wire formats."""
    import base64
    from task_agent._opencode_v2 import (
        build_v2_mcp_put_config,
        extract_config_providers_v2,
        extract_mcp_status_map_v2,
        normalize_message_list,
        normalize_v2_error,
        translate_v1_permissions_to_v2,
        translate_v2_permissions_to_v1,
    )
    from task_agent.serve_client import (
        _ServeEventState,
        _event_properties,
        _handle_serve_event,
        _session_id,
    )

    # 1. Exact user-reported `POST /api/session` response envelope `{data: {id: "ses_..."}}`
    assert _session_id({
        "data": {
            "id": "ses_e0d8ed169ffejg9C9etGjAc3xL",
            "projectID": "global",
            "cost": 0,
            "tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}},
            "time": {"created": 1795068866202, "updated": 1795068866202},
            "title": "threat-pattern-iterative-audit",
        }
    }) == "ses_e0d8ed169ffejg9C9etGjAc3xL"

    # 2. `GET /api/session/{id}/message` desc cursor -> chronological asc + native 2.3 message types
    desc_cursor = base64.urlsafe_b64encode(
        json.dumps({"id": "msg_3", "order": "desc", "direction": "previous"}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    raw_messages = {
        "data": [
            {"id": "msg_3", "time": {"created": 300}, "type": "idle", "outcome": "succeeded"},
            {
                "id": "msg_2",
                "time": {"created": 200, "completed": 250},
                "type": "assistant",
                "agent": "build",
                "model": {"id": "Qwen3-Coder", "providerID": "openai-compatible"},
                "finish": "stop",
                "tokens": {"input": 100, "output": 40, "reasoning": 0, "cache": {"read": 5, "write": 0}},
                "content": [
                    {
                        "type": "tool",
                        "id": "call_1",
                        "name": "write",
                        "executed": True,
                        "state": {
                            "status": "completed",
                            "input": {"path": "out/a.txt", "content": "hi"},
                            "content": [{"type": "text", "text": "Created file successfully: out/a.txt"}],
                            "metadata": {"truncated": False},
                        },
                    },
                    {"type": "text", "text": '{"ok": true}'},
                ],
            },
            {"id": "msg_1", "time": {"created": 100}, "type": "user", "text": "hello"},
        ],
        "cursor": {"previous": desc_cursor, "next": None},
    }
    normalized = normalize_message_list(raw_messages, fallback_session_id="ses_1")
    assert normalized is not None
    assert [m["info"]["id"] for m in normalized] == ["msg_1", "msg_2", "msg_3"]
    assert [m["info"]["role"] for m in normalized] == ["user", "assistant", "idle"]
    asst = normalized[1]
    assert asst["info"]["providerID"] == "openai-compatible"
    assert asst["info"]["modelID"] == "Qwen3-Coder"
    assert asst["parts"][0]["type"] == "tool"
    assert asst["parts"][0]["tool"] == "write"
    assert asst["parts"][0]["callID"] == "call_1"
    assert asst["parts"][0]["state"]["output"] == "Created file successfully: out/a.txt"
    assert asst["parts"][1] == {"id": "msg_2:text:1", "type": "text", "text": '{"ok": true}', "messageID": "msg_2"}

    # 3. Error normalization preserves HTTP status + responseBody (e.g. TM.00001005)
    norm_err = normalize_v2_error({
        "type": "api",
        "message": "Invalid API key",
        "status": 401,
        "response": {"body": '{"error":{"code":"TM.00001005"}}'},
    })
    assert norm_err["name"] == "APIError"
    assert norm_err["data"]["statusCode"] == 401
    assert "TM.00001005" in norm_err["data"]["responseBody"]

    # 4. Permission rule translation (bash -> shell + directory-relative resource)
    proj_dir = tmp_path / "proj"
    v2_perms = translate_v1_permissions_to_v2(
        [
            {"permission": "bash", "pattern": "*", "action": "deny"},
            {"permission": "edit", "pattern": str(proj_dir / "out" / "**"), "action": "allow"},
        ],
        directory=proj_dir,
    )
    assert {"action": "shell", "resource": "*", "effect": "deny"} in v2_perms
    assert {"action": "edit", "resource": "out/**", "effect": "allow"} in v2_perms
    v1_roundtrip = translate_v2_permissions_to_v1(v2_perms)
    assert {"permission": "shell", "pattern": "*", "action": "deny"} in v1_roundtrip

    # 5. MCP config translation and status envelope parsing
    put_cfg = build_v2_mcp_put_config({
        "type": "remote",
        "url": "http://127.0.0.1:9000/mcp",
        "enabled": False,
        "timeout": 4500,
    })
    assert put_cfg == {
        "type": "remote",
        "url": "http://127.0.0.1:9000/mcp",
        "disabled": True,
        "timeout": {"startup": 4500, "catalog": 4500, "execution": 4500},
    }
    mcp_map = extract_mcp_status_map_v2({
        "location": {"directory": str(proj_dir)},
        "data": [{"name": "kb", "status": {"status": "connected"}}],
    })
    assert mcp_map == {"kb": {"status": "connected"}}

    # 6. `GET /api/config` document array provider extraction
    cfg_provs, cfg_valid = extract_config_providers_v2([
        {"type": "document", "path": "/tmp/opencode.json", "info": {"provider": {"custom": {"models": {"m1": {"name": "M1"}}}}}},
    ])
    assert cfg_valid is True
    assert cfg_provs[0]["id"] == "custom"

    # 7. Real 2.3.2 SSE events (`data` field, `session.tool.input.started` -> `called` name lookup, `session.execution.succeeded`)
    emitted: list[str] = []
    writes: list = []
    state = _ServeEventState("opencode", "ses_sse", emitted.append, on_file_write=writes.append)
    state.start_progress()
    ev_type, ev_props = _event_properties({"type": "session.execution.started", "data": {"sessionID": "ses_sse"}})
    assert ev_type == "session.execution.started" and ev_props["sessionID"] == "ses_sse"
    _handle_serve_event({"type": "session.execution.started", "data": {"sessionID": "ses_sse"}}, state)
    _handle_serve_event(
        {"type": "session.tool.input.started", "data": {"sessionID": "ses_sse", "assistantMessageID": "msg_a", "id": "call_w", "name": "write"}},
        state,
    )
    _handle_serve_event(
        {"type": "session.tool.called", "data": {"sessionID": "ses_sse", "assistantMessageID": "msg_a", "id": "call_w", "input": {"path": "out/f.txt", "content": "x"}}},
        state,
    )
    _handle_serve_event(
        {
            "type": "session.tool.success",
            "data": {
                "sessionID": "ses_sse",
                "assistantMessageID": "msg_a",
                "id": "call_w",
                "content": [{"type": "text", "text": "Created file successfully: out/f.txt"}],
            },
        },
        state,
    )
    _handle_serve_event({"type": "session.execution.succeeded", "data": {"sessionID": "ses_sse"}}, state)
    assert state.session_terminal is True
    assert any("name=write" in line for line in emitted), emitted
    assert len(writes) == 1 and writes[0].path == "out/f.txt" and writes[0].created is True


def test_real_opencode_v232_binary_integration(tmp_path: Path) -> None:
    """Opt-in integration test against an isolated real opencode 2.3.x binary.

    Enable via `OPENDEEPHOLE_REAL_OPENCODE_V2_BIN=/path/to/opencode`.
    """
    real_bin = os.environ.get("OPENDEEPHOLE_REAL_OPENCODE_V2_BIN", "").strip()
    if not real_bin or not Path(real_bin).is_file():
        pytest.skip("Set OPENDEEPHOLE_REAL_OPENCODE_V2_BIN to run real opencode 2.x integration test")

    import http.server
    import socket
    import threading

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        llm_port = int(s.getsockname()[1])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        serve_port = int(s.getsockname()[1])

    seen_requests: list[dict] = []

    class _MockLLM(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}")
            seen_requests.append(body)
            reply = json.dumps({"verdict": "ok-real-bin", "turn": len(seen_requests)})
            chunks = [
                {
                    "id": f"c{len(seen_requests)}",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": body.get("model", "m1"),
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": reply}, "finish_reason": None}],
                },
                {
                    "id": f"c{len(seen_requests)}",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": body.get("model", "m1"),
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 25, "completion_tokens": 10, "total_tokens": 35},
                },
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for ch in chunks:
                self.wfile.write(f"data: {json.dumps(ch)}\n\n".encode("utf-8"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", llm_port), _MockLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir()
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    yaml_path = tmp_path / "real-v2.yaml"
    yaml_path.write_text(
        textwrap.dedent(
            f"""\
            schema_version: 2
            context:
              project_dir: {project_dir}
              work_dir: {work_dir}
              workspace_dir: {ws_dir}
            serve:
              tool: opencode
              opencode_version: "2"
              executable: /nonexistent/opencode-v1
              executable_v2: {real_bin}
              port: {serve_port}
              timeout: 45
              idle_timeout: 25
              opencode_config:
                provider:
                  mock:
                    npm: "@ai-sdk/openai-compatible"
                    options:
                      baseURL: "http://127.0.0.1:{llm_port}/v1"
                      apiKey: "sk-local"
                    models:
                      m1:
                        name: "Mock M1"
                        limit:
                          context: 128000
                          output: 16000
            model_pool:
              models:
                - id: mock/m1
                  model: mock/m1
                  capability: high
                  enabled: true
            """
        ),
        encoding="utf-8",
    )
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}, "turn": {"type": "integer"}},
        "required": ["verdict", "turn"],
        "additionalProperties": False,
    }
    xdg_keys = {
        "XDG_DATA_HOME": str(tmp_path / "xdg/data"),
        "XDG_CONFIG_HOME": str(tmp_path / "xdg/config"),
        "XDG_CACHE_HOME": str(tmp_path / "xdg/cache"),
        "XDG_STATE_HOME": str(tmp_path / "xdg/state"),
    }
    prev_env = {k: os.environ.get(k) for k in xdg_keys}
    os.environ.update(xdg_keys)
    try:
        async def scenario() -> None:
            await shutdown_opencode()
            try:
                t1 = await run_opencode_task(
                    task_name="real-v2-t1",
                    task_type="vulnerability_mining",
                    prompt="Turn 1 check",
                    required_capability="high",
                    output_schema=schema,
                    config_path=yaml_path,
                )
                assert t1.status == "success", t1
                assert t1.structured == {"verdict": "ok-real-bin", "turn": 1}
                assert t1.session_id.startswith("ses_")
                t2 = await run_opencode_task(
                    task_name="real-v2-t2",
                    task_type="vulnerability_mining",
                    prompt="Turn 2 continuation",
                    required_capability="high",
                    output_schema=schema,
                    session_id=t1.session_id,
                    config_path=yaml_path,
                )
                assert t2.status == "success", t2
                assert t2.session_id == t1.session_id
                assert t2.structured == {"verdict": "ok-real-bin", "turn": 2}
            finally:
                await shutdown_opencode()

        asyncio.run(scenario())
    finally:
        server.shutdown()
        server.server_close()
        for k, v in prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
