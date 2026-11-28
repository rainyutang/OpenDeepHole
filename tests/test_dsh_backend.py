"""Comprehensive unit and end-to-end tests for the DeepSeek Harness (`sdk-minimal`) backend."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from backend.agents.configuration import _validate_managed_config
from backend.application import ApplicationError
from backend.models import AgentBaseConfig, AgentRemoteConfig
from deephole_client.config import (
    AgentConfig,
    OpenCodeConfig,
    apply_remote_config,
    normalize_cli_config,
    remote_config_dict,
)
from deephole_client.opencode_integration import build_opencode_session_runtime
from task_agent.dsh.approval_policy import DshApprovalArbitrator
from task_agent.dsh.error_mapping import map_dsh_failure
from task_agent.dsh.event_bridge import (
    DshEventBridge,
    normalize_dsh_finish_reason,
    parse_dsh_bash_output,
    parse_dsh_usage,
    verify_required_bash_commands,
)
from task_agent.dsh.manager import DeepSeekHarnessManager
from task_agent.dsh.model_catalog import (
    check_dsh_runtime_available,
    list_dsh_models,
    resolve_dsh_model,
)
from task_agent.dsh.patch_composer import (
    DshMcpMountSpec,
    build_cordis_patch_document,
    compose_dsh_patch_file,
    detect_leading_skill_name,
    sanitize_mcp_server_name,
)
from task_agent.host import OpenCodeSessionRuntime
from task_agent.kb_mcp_proxy import (
    KnowledgeBaseMcpProxy,
    _find_blocked_tools_call,
    rewrite_tools_list_result,
)
from task_agent.model_pool import model_options
from task_agent.runtime_backend import (
    TOOL_DEEPSEEK_HARNESS,
    TOOL_OPENCODE,
    get_runtime_manager,
    normalize_runtime_tool,
    resolve_cli_runtime_identity,
)
from task_agent.serve_client import (
    OpenCodeFileWrite,
    OpenCodeModelAccessError,
    OpenCodeModelNotFoundError,
    OpenCodeProviderQuotaError,
    OpenCodeServeStartupError,
    OpenCodeTaskQualityError,
)
from task_agent.standalone import load_standalone_config


# ---------------------------------------------------------------------------
# 1. Runtime registry & OpenCodeSessionRuntime non-invasive kwargs separation
# ---------------------------------------------------------------------------


def test_runtime_backend_registry_and_kwargs_isolation(tmp_path: Path) -> None:
    assert normalize_runtime_tool("opencode") == TOOL_OPENCODE
    assert normalize_runtime_tool("deepseek_harness") == TOOL_DEEPSEEK_HARNESS
    assert normalize_runtime_tool("unknown") == TOOL_OPENCODE
    with pytest.raises(ValueError):
        normalize_runtime_tool("unknown", strict=True)

    assert isinstance(get_runtime_manager(TOOL_DEEPSEEK_HARNESS), DeepSeekHarnessManager)

    oc_runtime = OpenCodeSessionRuntime(
        directory=tmp_path,
        tool=TOOL_OPENCODE,
        executable="opencode",
        backend_options={"ignored_for_opencode": True},
    )
    assert "backend_options" not in oc_runtime.kwargs()
    assert "backend_options" not in oc_runtime.kwargs_for_backend()

    dsh_runtime = OpenCodeSessionRuntime(
        directory=tmp_path,
        tool=TOOL_DEEPSEEK_HARNESS,
        executable="dsh",
        backend_options={"dsh_profile": "sdk-minimal"},
    )
    assert "backend_options" not in dsh_runtime.kwargs()
    assert dsh_runtime.kwargs_for_backend()["backend_options"] == {"dsh_profile": "sdk-minimal"}


def test_model_pool_options_and_cli_identity_for_dsh() -> None:
    cli = OpenCodeConfig(
        tool=TOOL_DEEPSEEK_HARNESS,
        dsh_executable="/opt/bin/dsh",
        models=[
            SimpleNamespace(
                id="m1",
                model="custom/qwen",
                use_default_model=False,
                capability="high",
                weight=1.0,
                max_concurrency=2,
                enabled=True,
                timeout=None,
                idle_timeout=None,
                max_retries=None,
                limit_context=128000,
                limit_output=16384,
                time_windows=[],
            )
        ],
    )
    assert resolve_cli_runtime_identity(cli) == (TOOL_DEEPSEEK_HARNESS, "/opt/bin/dsh")
    opts = model_options(cli)
    assert len(opts) == 1
    assert opts[0].tool == TOOL_DEEPSEEK_HARNESS
    assert opts[0].executable == "/opt/bin/dsh"


# ---------------------------------------------------------------------------
# 2. Model catalog & provider/model resolution
# ---------------------------------------------------------------------------


def test_model_catalog_lists_web_local_and_official(tmp_path: Path) -> None:
    dsh_home = tmp_path / "dsh_home"
    dsh_home.mkdir()
    (dsh_home / "cordis.patch.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "insert": [
                        {
                            "id": "llm-pi-ai",
                            "name": "@deepseek-ai/dsh-llm-pi-ai",
                            "config": {
                                "providers": {
                                    "local-gw": {
                                        "api": "openai-completions",
                                        "baseURL": "http://127.0.0.1:8080/v1",
                                        "models": [
                                            {"id": "local-coder", "contextWindow": 65536, "maxTokens": 8192}
                                        ],
                                    }
                                }
                            },
                        }
                    ]
                }
            ]
        ),
        encoding="utf-8",
    )
    providers = {
        "openrouter": {
            "npm": "@ai-sdk/openai-compatible",
            "options": {"baseURL": "https://openrouter.ai/api/v1", "apiKey": "sk-or-secret"},
            "models": {
                "anthropic/claude-3.7-sonnet": {
                    "name": "Claude 3.7",
                    "limit": {"context": 200000, "output": 32768},
                }
            },
        }
    }
    res = list_dsh_models(
        llm_providers=providers,
        dsh_home=dsh_home,
        env={"DEEPSEEK_API_KEY": "sk-ds-official"},
    )
    ids = [m.id for m in res.models]
    assert "openrouter/anthropic/claude-3.7-sonnet" in ids
    assert "local-gw/local-coder" in ids
    assert "deepseek-official/deepseek-flash" in ids
    assert "deepseek-official/deepseek-v4-pro" in ids

    resolved = resolve_dsh_model(
        "openrouter/anthropic/claude-3.7-sonnet",
        llm_providers=providers,
    )
    assert resolved.is_pi_ai is True
    assert resolved.provider_id == "openrouter"
    assert resolved.model_id == "anthropic/claude-3.7-sonnet"
    assert resolved.api_key == "sk-or-secret"
    assert resolved.context_window == 200000
    assert resolved.max_tokens == 32768


# ---------------------------------------------------------------------------
# 3. Patch composer (sdk-minimal, zero-secret YAML, skills, on-demand MCP)
# ---------------------------------------------------------------------------


def test_patch_composer_minimal_zero_secret_and_on_demand_mcp(tmp_path: Path) -> None:
    dsh_home = tmp_path / "dsh_home"
    skills_dir = tmp_path / "skills"
    work_dir = tmp_path / "work"
    skills_dir.mkdir()
    work_dir.mkdir()

    resolved = resolve_dsh_model(
        "corp/coder-pro",
        llm_providers={
            "corp": {
                "npm": "@ai-sdk/openai-compatible",
                "options": {
                    "baseURL": "https://llm.example.com/v1",
                    "apiKey": "SUPER_SECRET_KEY_12345",
                    "headers": {"X-Org": "sec"},
                },
                "models": {
                    "coder-pro": {
                        "limit": {"context": 128000, "output": 16384},
                    }
                },
            }
        },
    )

    # Pure sdk-minimal default: no MCP plugins mounted, secret stays in env only.
    composed = compose_dsh_patch_file(
        resolved_model=resolved,
        dsh_home=dsh_home,
        prompt="/npd check src/main.c",
        system_prompt="Focus on null dereference.",
        skill_roots=(skills_dir,),
        write_roots=(work_dir,),
        allowed_bash_commands=(),
        disable_all_tools=False,
        mcp_mounts=(),
    )
    try:
        raw_yaml = composed.patch_path.read_text(encoding="utf-8")
        assert "SUPER_SECRET_KEY_12345" not in raw_yaml
        assert composed.env["OPENDEEPHOLE_DSH_API_KEY"] == "SUPER_SECRET_KEY_12345"
        assert "@deepseek-ai/dsh-mcp-client" not in raw_yaml
        assert "@deepseek-ai/dsh-skill" in raw_yaml
        assert "@deepseek-ai/dsh-tool-skill" in raw_yaml
        assert "includeDefaultRoots: false" in raw_yaml
        assert "watch: false" in raw_yaml
        assert "skill" in raw_yaml and "npd" in raw_yaml
        if os.name != "nt":
            assert stat.S_IMODE(composed.patch_path.stat().st_mode) == 0o600
        # Bash disabled when no allowed_bash_commands
        doc = composed.patch_document
        assert any(row.get("id") == "persistent-bash" and row.get("disabled") is True for row in doc)
    finally:
        composed.patch_path.unlink(missing_ok=True)

    # disable_all_tools=True disables all tools and mounts neither skills nor MCP
    doc_disabled, _env, mounted_skills = build_cordis_patch_document(
        resolved_model=resolved,
        skill_roots=(skills_dir,),
        write_roots=(work_dir,),
        disable_all_tools=True,
        mcp_mounts=(
            DshMcpMountSpec(
                id="mcp-code-graph",
                server_name="codegraph",
                transport="stdio",
                command="codegraph",
            ),
        ),
    )
    assert mounted_skills is False
    inserted = doc_disabled[0]["insert"]
    assert not any(r.get("name") == "@deepseek-ai/dsh-mcp-client" for r in inserted)
    assert not any(r.get("name") == "@deepseek-ai/dsh-skill" for r in inserted)
    assert any(r.get("id") == "tool-fs" and r.get("disabled") is True for r in doc_disabled)
    gate = next(r for r in inserted if r.get("id") == "odh-tool-gate")
    assert gate["config"]["denyAll"] is True

    # On-demand MCP mount sanitizes names cleanly
    used: set[str] = set()
    assert sanitize_mcp_server_name("my mcp / graph!", fallback="cg", used=used) == "my_mcp_graph"
    assert sanitize_mcp_server_name("my mcp / graph!", fallback="cg", used=used) == "my_mcp_graph_2"
    assert detect_leading_skill_name("/npd-audit check file.c") == "npd-audit"
    assert detect_leading_skill_name("regular prompt") == ""


# ---------------------------------------------------------------------------
# 4. Programmatic approval arbitrator
# ---------------------------------------------------------------------------


def test_approval_arbitrator_write_roots_symlink_and_bash_modes(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    work_dir = tmp_path / "work"
    repo_dir.mkdir()
    work_dir.mkdir()
    script_path = work_dir / "validate_result.py"
    script_path.write_text("print('OK')\n", encoding="utf-8")

    # Symlink inside work_dir escaping to repo_dir must be rejected!
    escape_link = work_dir / "escape"
    escape_link.symlink_to(repo_dir)

    canonical_cmd = f"python3 {script_path} --strict"
    arb = DshApprovalArbitrator(
        cwd=repo_dir,
        write_roots=(work_dir,),
        allowed_bash_commands=(canonical_cmd,),
        bash_command_match_mode="bound_python_script",
    )

    # Source repo write rejected
    arb.register_tool_call("c1", "write", json.dumps({"file_path": str(repo_dir / "main.c")}))
    assert arb.decide({"toolName": "write", "callId": "c1"})[0] == "rejected"

    # Symlink escape rejected
    arb.register_tool_call("c2", "write", json.dumps({"file_path": str(escape_link / "evil.c")}))
    assert arb.decide({"toolName": "write", "callId": "c2"})[0] == "rejected"

    # Work dir write approved & tracked
    target_out = work_dir / "out.json"
    arb.register_tool_call("c3", "write", json.dumps({"file_path": str(target_out)}))
    assert arb.decide({"toolName": "write", "callId": "c3"})[0] == "allowed-once"
    pending = arb.pop_pending_write("c3")
    assert pending is not None and pending.path == str(target_out.resolve()) and pending.created is True

    # Bound python script approved even with different python alias / args
    arb.register_tool_call("c4", "bash", json.dumps({"command": f"python {script_path} --other"}))
    assert arb.decide({"toolName": "bash", "callId": "c4"})[0] == "allowed-once"
    assert arb.approved_bash_command("c4") == canonical_cmd

    # Unlisted bash rejected
    arb.register_tool_call("c5", "bash", json.dumps({"command": "rm -rf /tmp/x"}))
    assert arb.decide({"toolName": "bash", "callId": "c5"})[0] == "rejected"

    # Interactive tool rejected
    assert arb.decide({"toolName": "ask_user_question", "callId": "c6"})[0] == "rejected"

    # disable_all_tools rejects everything
    disabled_arb = DshApprovalArbitrator(
        cwd=repo_dir,
        write_roots=(work_dir,),
        allowed_bash_commands=(canonical_cmd,),
        disable_all_tools=True,
    )
    disabled_arb.register_tool_call("c7", "write", json.dumps({"file_path": str(target_out)}))
    assert disabled_arb.decide({"toolName": "write", "callId": "c7"})[0] == "rejected"


# ---------------------------------------------------------------------------
# 5. Event bridge, token accounting, required bash verification & error mapping
# ---------------------------------------------------------------------------


def test_event_bridge_tokens_file_writes_and_bash_audit(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    cmd = "python3 /tmp/check.py"
    arb = DshApprovalArbitrator(
        cwd=tmp_path,
        write_roots=(work_dir,),
        allowed_bash_commands=(cmd,),
    )
    lines: list[str] = []
    usages: list[Any] = []
    writes: list[OpenCodeFileWrite] = []
    models_seen: list[str] = []
    progress_calls: list[int] = []

    bridge = DshEventBridge(
        session_id="dsh-sess-1",
        model_label="corp/coder",
        log_stage="vulnerability_mining",
        arbitrator=arb,
        emit_line=lines.append,
        emit_token_usage=usages.append,
        emit_response_model=models_seen.append,
        emit_file_write=writes.append,
        emit_model_progress=lambda: progress_calls.append(1),
    )

    # Assistant message with usage
    bridge.handle_notification(
        SimpleNamespace(
            method="session.event",
            payload={
                "sessionId": "dsh-sess-1",
                "event": {
                    "type": "assistant/message",
                    "data": {
                        "message": {
                            "id": "msg-1",
                            "source": {"provider": "corp", "model": "coder"},
                            "content": [{"type": "text", "text": "Checking..."}],
                        },
                        "usage": {
                            "inputTokens": 100,
                            "outputTokens": 40,
                            "reasoningTokens": 15,
                            "cacheReadTokens": 20,
                        },
                    },
                },
            },
        )
    )
    assert models_seen == ["corp/coder"]
    assert len(progress_calls) == 1
    assert len(usages) == 1
    acc = bridge.accumulated_token_usage()
    assert acc is not None
    assert acc.counters.input_tokens == 100
    assert acc.counters.output_tokens == 40
    assert acc.counters.reasoning_tokens == 15
    assert acc.counters.cache_read_tokens == 20

    # File write approved + succeeded
    target = work_dir / "report.json"
    bridge.handle_notification(
        SimpleNamespace(
            method="session.event",
            payload={
                "sessionId": "dsh-sess-1",
                "event": {
                    "type": "tool/call",
                    "data": {"callId": "call-w", "name": "write", "arguments": json.dumps({"file_path": str(target)})},
                },
            },
        )
    )
    assert arb.decide({"toolName": "write", "callId": "call-w"})[0] == "allowed-once"
    bridge.handle_notification(
        SimpleNamespace(
            method="session.event",
            payload={
                "sessionId": "dsh-sess-1",
                "event": {
                    "type": "tool/result",
                    "data": {
                        "message": {
                            "toolCallId": "call-w",
                            "isError": False,
                            "content": [{"type": "text", "text": "wrote"}],
                        }
                    },
                },
            },
        )
    )
    assert len(writes) == 1 and writes[0].path == str(target.resolve())

    # Bash approved + succeeded with marker
    bridge.handle_notification(
        SimpleNamespace(
            method="session.event",
            payload={
                "sessionId": "dsh-sess-1",
                "event": {
                    "type": "tool/call",
                    "data": {"callId": "call-b", "name": "bash", "arguments": json.dumps({"command": cmd})},
                },
            },
        )
    )
    assert arb.decide({"toolName": "bash", "callId": "call-b"})[0] == "allowed-once"
    bridge.handle_notification(
        SimpleNamespace(
            method="session.event",
            payload={
                "sessionId": "dsh-sess-1",
                "event": {
                    "type": "tool/result",
                    "data": {
                        "message": {
                            "toolCallId": "call-b",
                            "isError": False,
                            "content": [{"type": "text", "text": "VALIDATED_OK\n[Command finished with exit code 0]"}],
                        }
                    },
                },
            },
        )
    )
    verify_required_bash_commands(
        required_commands=(cmd,),
        success_markers=((cmd, "VALIDATED_OK"),),
        audits=bridge.bash_audits,
    )
    with pytest.raises(OpenCodeTaskQualityError) as exc_info:
        verify_required_bash_commands(
            required_commands=(cmd,),
            success_markers=((cmd, "MISSING_MARKER"),),
            audits=bridge.bash_audits,
        )
    assert exc_info.value.failure_kind == "command_output_marker_missing"

    assert normalize_dsh_finish_reason("max-tokens") == "length"
    assert normalize_dsh_finish_reason("completed") == "stop"
    assert parse_dsh_bash_output("out\n[Command finished with exit code 2]") == ("out", 2, False)
    assert parse_dsh_usage({"inputTokens": 5, "outputTokens": 3}).total_tokens == 8


def test_error_mapping_and_secret_redaction() -> None:
    providers = {
        "corp": {
            "options": {"baseURL": "https://api.example.com/v1", "apiKey": "sk-top-secret-999"},
            "models": {"m1": {}},
        }
    }
    exc, kind = map_dsh_failure(
        failure={"code": "RATE_LIMITED", "status": 429, "message": "rate limit with sk-top-secret-999", "providerRetryAfterMs": 12000},
        model="corp/m1",
        llm_providers=providers,
    )
    assert isinstance(exc, OpenCodeProviderQuotaError)
    assert kind == "quota"
    assert exc.retry_after_seconds == 12.0
    assert "sk-top-secret-999" not in str(exc)

    exc2, kind2 = map_dsh_failure(
        failure={"code": "MISSING_CREDENTIAL", "status": 401, "message": "Invalid api key sk-top-secret-999"},
        model="corp/m1",
        llm_providers=providers,
    )
    assert isinstance(exc2, OpenCodeModelAccessError)
    assert kind2 == "access_denied"
    assert "sk-top-secret-999" not in str(exc2)

    exc3, _ = map_dsh_failure(
        failure={"code": "MODEL_NOT_FOUND", "message": "no adapter registered for provider foo"},
        model="foo/bar",
        llm_providers=providers,
    )
    assert isinstance(exc3, OpenCodeModelNotFoundError)

    exc4, _ = map_dsh_failure(
        error=FileNotFoundError("/missing/dsh"),
        model="corp/m1",
        startup_phase=True,
    )
    assert isinstance(exc4, OpenCodeServeStartupError)


# ---------------------------------------------------------------------------
# 6. KnowledgeBaseMcpProxy blocked_tools support
# ---------------------------------------------------------------------------


def test_kb_mcp_proxy_blocks_project_management_tools() -> None:
    raw = {
        "tools": [
            {
                "name": "search_docs",
                "inputSchema": {
                    "type": "object",
                    "properties": {"project_id": {"type": "string"}, "query": {"type": "string"}},
                    "required": ["project_id", "query"],
                },
            },
            {"name": "list_projects", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "set_project", "inputSchema": {"type": "object", "properties": {}}},
        ]
    }
    rewritten, with_pid, without_pid = rewrite_tools_list_result(
        raw,
        blocked_tools=frozenset({"list_projects", "set_project"}),
    )
    assert [t["name"] for t in rewritten["tools"]] == ["search_docs"]
    assert "project_id" not in rewritten["tools"][0]["inputSchema"]["properties"]
    assert rewritten["tools"][0]["inputSchema"]["required"] == ["query"]
    assert with_pid == {"search_docs"}
    assert without_pid == set()

    hit = _find_blocked_tools_call(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "set_project", "arguments": {}}},
        frozenset({"list_projects", "set_project"}),
    )
    assert hit == (7, "set_project")


# ---------------------------------------------------------------------------
# 7. Backend, Host AgentConfig & Standalone YAML integration
# ---------------------------------------------------------------------------


def test_backend_and_agent_config_roundtrip_deepseek_harness(tmp_path: Path) -> None:
    remote = AgentRemoteConfig(
        base=AgentBaseConfig(
            tool="deepseek_harness",
            dsh_executable="",
            dsh_profile="sdk-minimal",
        )
    )
    _validate_managed_config(remote)
    assert remote.opencode.tool == "deepseek_harness"
    assert remote.opencode.dsh_profile == "sdk-minimal"

    # AgentConfig apply + export round-trip
    agent_cfg = AgentConfig()
    apply_remote_config(agent_cfg, remote.model_dump())
    assert agent_cfg.opencode.tool == "deepseek_harness"
    assert agent_cfg.opencode.dsh_profile == "sdk-minimal"
    exported = remote_config_dict(agent_cfg)
    assert exported["base"]["tool"] == "deepseek_harness"
    assert exported["base"]["dsh_profile"] == "sdk-minimal"
    assert exported["base"]["dsh_executable"] == ""

    # Host runtime dispatch
    runtime = build_opencode_session_runtime(agent_cfg.opencode, directory=tmp_path)
    assert runtime.tool == "deepseek_harness"
    assert runtime.backend_options["dsh_profile"] == "sdk-minimal"
    assert "dsh_home" in runtime.backend_options

    # OpenCode validation still rejects blank executable when tool == opencode
    bad_oc = AgentRemoteConfig(
        schema_version=11,
        base=AgentBaseConfig(tool="opencode", executable=""),
    )
    with pytest.raises(ApplicationError):
        _validate_managed_config(bad_oc)


def test_standalone_yaml_supports_deepseek_harness(tmp_path: Path) -> None:
    project_dir = tmp_path / "src"
    work_dir = tmp_path / "work"
    workspace_dir = tmp_path / "ws"
    project_dir.mkdir()
    cfg_path = tmp_path / "task-agent.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "context": {
                    "project_dir": str(project_dir),
                    "work_dir": str(work_dir),
                    "workspace_dir": str(workspace_dir),
                },
                "serve": {
                    "tool": "deepseek_harness",
                    "dsh_profile": "sdk-minimal",
                    "dsh_executable": "",
                    "opencode_config": {
                        "provider": {
                            "myapi": {
                                "npm": "@ai-sdk/openai-compatible",
                                "options": {"baseURL": "http://127.0.0.1:9999/v1", "apiKey": "k"},
                                "models": {"m1": {}},
                            }
                        }
                    },
                },
                "model_pool": {
                    "models": [
                        {
                            "id": "myapi/m1",
                            "model": "myapi/m1",
                            "capability": "high",
                            "weight": 1,
                            "max_concurrency": 1,
                            "enabled": True,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_standalone_config(cfg_path)
    assert loaded.opencode.tool == "deepseek_harness"
    assert loaded.opencode.dsh_profile == "sdk-minimal"
    assert loaded.dsh_home == (workspace_dir / ".opendeephole-dsh-home").resolve()


# ---------------------------------------------------------------------------
# 8. Real end-to-end smoke tests against installed sdk-minimal runtime
# ---------------------------------------------------------------------------


def test_e2e_real_dsh_sdk_minimal_approval_skills_resume_and_disable_tools(tmp_path: Path) -> None:
    ok, _detail = check_dsh_runtime_available()
    if not ok:
        pytest.skip("deepseek-harness-sdk bundled runtime not installed")

    async def _run() -> None:
        await _run_e2e_dsh_scenario(tmp_path)

    asyncio.run(_run())


async def _run_e2e_dsh_scenario(tmp_path: Path) -> None:

    repo_dir = tmp_path / "repo"
    work_dir = tmp_path / "work"
    skills_dir = tmp_path / "skills"
    dsh_home = tmp_path / "dsh_home"
    for p in (repo_dir, work_dir, skills_dir, dsh_home):
        p.mkdir(parents=True, exist_ok=True)
    (repo_dir / "source.txt").write_text("READ_ONLY_SOURCE\n", encoding="utf-8")
    demo_skill = skills_dir / "demo-audit"
    demo_skill.mkdir()
    (demo_skill / "SKILL.md").write_text(
        "---\nname: demo-audit\ndescription: Demo audit skill\n---\nAlways report DEMO_OK.\n",
        encoding="utf-8",
    )

    allowed_work_file = work_dir / "result.txt"
    blocked_repo_file = repo_dir / "hacked.txt"
    allowed_cmd = "echo AUDIT_PASS_123"
    blocked_cmd = "echo SHOULD_NOT_RUN"

    received_requests: list[dict[str, Any]] = []
    scenario = {"mode": "tools_turn"}
    turn_step = {"count": 0}

    class MockOpenAIHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            received_requests.append(body)
            turn_step["count"] += 1
            step = turn_step["count"]

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()

            def emit_tool(call_id: str, name: str, args: dict[str, Any]) -> None:
                chunks = [
                    {
                        "id": f"c-{step}",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "mock-coder",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "role": "assistant",
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": call_id,
                                            "type": "function",
                                            "function": {"name": name, "arguments": json.dumps(args)},
                                        }
                                    ],
                                },
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": f"c-{step}",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "mock-coder",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                        "usage": {"prompt_tokens": 50, "completion_tokens": 12, "total_tokens": 62},
                    },
                ]
                for ch in chunks:
                    self.wfile.write(f"data: {json.dumps(ch)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def emit_text(text: str) -> None:
                chunks = [
                    {
                        "id": f"c-{step}",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "mock-coder",
                        "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}],
                    },
                    {
                        "id": f"c-{step}",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "mock-coder",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 60, "completion_tokens": 8, "total_tokens": 68},
                    },
                ]
                for ch in chunks:
                    self.wfile.write(f"data: {json.dumps(ch)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            if scenario["mode"] == "tools_turn":
                if step == 1:
                    # 1) Try blocked write to source repo -> must be rejected by approval policy
                    emit_tool("tc_1", "write", {"file_path": str(blocked_repo_file), "content": "bad"})
                elif step == 2:
                    # 2) Allowed write into work_dir -> must succeed and record OpenCodeFileWrite
                    emit_tool("tc_2", "write", {"file_path": str(allowed_work_file), "content": "good"})
                elif step == 3:
                    # 3) Disallowed bash command -> must be rejected
                    emit_tool("tc_3", "bash", {"command": blocked_cmd})
                elif step == 4:
                    # 4) Allowed required bash command -> must succeed and pass audit
                    emit_tool("tc_4", "bash", {"command": allowed_cmd})
                else:
                    emit_text('{"status": "ok"}')
            elif scenario["mode"] == "resume_turn":
                emit_text("RESUMED_OK")
            else:
                emit_text("TEXT_ONLY_OK")

    server = HTTPServer(("127.0.0.1", 0), MockOpenAIHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    providers = {
        "mock-provider": {
            "npm": "@ai-sdk/openai-compatible",
            "options": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": "sk-mock-secret"},
            "models": {"mock-coder": {"limit": {"context": 200000, "output": 32768}}},
        }
    }
    manager = DeepSeekHarnessManager()
    recorded_writes: list[OpenCodeFileWrite] = []
    recorded_lines: list[str] = []
    recorded_usages: list[Any] = []

    try:
        # Turn 1: full tool + approval + skill + bash audit flow
        result = await manager.run_prompt(
            prompt="/demo-audit analyze repo",
            directory=repo_dir,
            model="mock-provider/mock-coder",
            backend_options={
                "dsh_home": str(dsh_home),
                "dsh_profile": "sdk-minimal",
                "llm_providers": providers,
                "skill_roots": [str(skills_dir)],
                "writable_roots": [str(work_dir)],
            },
            allowed_bash_commands=(allowed_cmd,),
            required_bash_commands=(allowed_cmd,),
            required_bash_success_markers=((allowed_cmd, "AUDIT_PASS_123"),),
            on_file_write=recorded_writes.append,
            on_line=recorded_lines.append,
            on_token_usage=recorded_usages.append,
            timeout=60.0,
            idle_timeout=30.0,
        )
        assert result.text == '{"status": "ok"}'
        assert result.finish_reason == "stop"
        assert result.token_usage is not None
        assert result.token_usage.counters.total_tokens > 0
        assert not blocked_repo_file.exists()
        assert allowed_work_file.read_text(encoding="utf-8") == "good"
        assert any(w.path == str(allowed_work_file.resolve()) for w in recorded_writes)
        assert len(recorded_usages) >= 1
        # Verify skill tool was advertised in request tools
        first_tools = {t["function"]["name"] for t in received_requests[0].get("tools") or []}
        assert {"read", "write", "edit", "bash", "skill"}.issubset(first_tools)

        # Turn 2: resume same persisted session & verify session query/delete APIs
        scenario["mode"] = "resume_turn"
        resumed = await manager.run_prompt(
            prompt="continue in same session",
            directory=repo_dir,
            session_id=result.session_id,
            model="mock-provider/mock-coder",
            backend_options={
                "dsh_home": str(dsh_home),
                "dsh_profile": "sdk-minimal",
                "llm_providers": providers,
                "skill_roots": [str(skills_dir)],
                "writable_roots": [str(work_dir)],
            },
            timeout=60.0,
        )
        assert resumed.session_id == result.session_id
        assert resumed.text == "RESUMED_OK"
        session_info = await manager.get_session(
            result.session_id,
            backend_options={"dsh_home": str(dsh_home)},
        )
        assert session_info is not None and session_info["id"] == result.session_id
        messages = await manager.get_session_messages(
            result.session_id,
            backend_options={"dsh_home": str(dsh_home)},
        )
        assert any(
            m["info"]["role"] == "assistant"
            and any("RESUMED_OK" in p["text"] for p in m["parts"])
            for m in messages
        )
        assert await manager.delete_session(
            result.session_id,
            backend_options={"dsh_home": str(dsh_home)},
        ) is True

        # Turn 3: disable_all_tools=True advertises ZERO tools
        scenario["mode"] = "text_only"
        req_count_before = len(received_requests)
        text_only = await manager.run_prompt(
            prompt="just reply text",
            directory=repo_dir,
            model="mock-provider/mock-coder",
            backend_options={
                "dsh_home": str(dsh_home),
                "dsh_profile": "sdk-minimal",
                "llm_providers": providers,
                "skill_roots": [str(skills_dir)],
                "writable_roots": [str(work_dir)],
            },
            disable_all_tools=True,
            timeout=60.0,
        )
        assert text_only.text == "TEXT_ONLY_OK"
        text_only_req = received_requests[req_count_before]
        assert not (text_only_req.get("tools") or [])
    finally:
        await manager.shutdown()
        server.shutdown()


def test_task_service_and_agent_server_dispatch_to_dsh_without_serve_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deephole_client import server as agent_server
    from task_agent.serve_client import (
        OpenCodeModelInfo,
        OpenCodeModelListResult,
        OpenCodePromptResult,
    )
    from task_agent.task_service import (
        OpenCodeExecutionContext,
        OpenCodeTaskService,
        OpenCodeTaskSpec,
        bind_opencode_execution_context,
    )

    # Ensure OpenCode serve manager is never invoked when tool == deepseek_harness
    def _forbidden_serve_manager():
        raise AssertionError("OpenCode get_serve_manager must not be called for deepseek_harness")

    monkeypatch.setattr("task_agent.task_service.get_serve_manager", _forbidden_serve_manager)
    monkeypatch.setattr("task_agent.serve_client.get_serve_manager", _forbidden_serve_manager)

    seen_calls: list[dict[str, Any]] = []

    class _FakeDshManager(DeepSeekHarnessManager):
        async def run_prompt(self, **kwargs: Any) -> OpenCodePromptResult:
            seen_calls.append(kwargs)
            return OpenCodePromptResult(
                session_id="dsh-fake-1",
                message_id="msg-1",
                text='{"ok": true}',
                lines=['{"ok": true}'],
                model="mock/coder",
                finish_reason="stop",
            )

        async def list_models(self, **_kwargs: Any) -> OpenCodeModelListResult:
            return OpenCodeModelListResult(
                models=[
                    OpenCodeModelInfo(
                        id="mock/coder",
                        provider_id="mock",
                        model_id="coder",
                        name="Mock Coder",
                        limit_context=128000,
                        limit_output=8192,
                    )
                ]
            )

    fake_mgr = _FakeDshManager()
    fake_mgr.update_managed_mcp_configs({"knowledge_base": {"name": "kb"}})
    monkeypatch.setattr(
        "task_agent.task_service.get_runtime_manager",
        lambda tool: fake_mgr if tool == TOOL_DEEPSEEK_HARNESS else _forbidden_serve_manager(),
    )
    monkeypatch.setattr(
        "task_agent.runtime_backend.get_runtime_manager",
        lambda tool: fake_mgr if tool == TOOL_DEEPSEEK_HARNESS else _forbidden_serve_manager(),
    )

    runtime = OpenCodeSessionRuntime(
        tool=TOOL_DEEPSEEK_HARNESS,
        executable="",
        model="mock/coder",
        directory=tmp_path,
        config_workspace=tmp_path,
        config_content=json.dumps({
            "provider": {
                "mock": {
                    "npm": "@ai-sdk/openai-compatible",
                    "options": {"baseURL": "https://api.example.com/v1"},
                    "models": {"coder": {"limit": {"context": 128000, "output": 8192}}},
                }
            }
        }),
        backend_options={"dsh_profile": "sdk-minimal", "dsh_home": str(tmp_path / "dsh")},
    )
    cli_cfg = SimpleNamespace(
        tool=TOOL_DEEPSEEK_HARNESS,
        executable="",
        dsh_executable="",
        dsh_profile="sdk-minimal",
        timeout=60,
        idle_timeout=30,
        json_correction_timeout_seconds=30,
        validation_retry_timeout_seconds=30,
        max_retries=0,
        models=[
            SimpleNamespace(
                id="m1",
                model="mock/coder",
                enabled=True,
                capability="high",
                weight=1,
                max_concurrency=1,
                timeout=None,
                idle_timeout=None,
                max_retries=None,
                time_windows=[],
            )
        ],
    )
    import task_agent.host as host_mod
    from task_agent.host import OpenCodeHostBindings, configure_opencode

    fake_host_cfg = SimpleNamespace(opencode=cli_cfg)
    prev_state = (
        host_mod._bindings,
        host_mod._binding_source,
        host_mod._binding_identity,
        host_mod._binding_context,
    )
    configure_opencode(
        OpenCodeHostBindings(
            get_config=lambda: fake_host_cfg,
            get_workspace=lambda: tmp_path,
            build_session_runtime=lambda *_a, **_kw: runtime,
        )
    )
    monkeypatch.setattr(
        "deephole_client.opencode_integration.build_opencode_session_runtime",
        lambda *_a, **_kw: runtime,
    )

    service = OpenCodeTaskService()
    spec = OpenCodeTaskSpec(
        task_name="dsh-dispatch-smoke",
        prompt="hello",
        directory=tmp_path,
        timeout_seconds=60,
        idle_timeout_seconds=30,
    )

    async def _run_service() -> Any:
        with bind_opencode_execution_context(
            scan_id="scan-dsh-1",
            project_dir=tmp_path,
            work_dir=tmp_path,
        ):
            return await service.run_task(spec)

    try:
        response = asyncio.run(_run_service())
    finally:
        (
            host_mod._bindings,
            host_mod._binding_source,
            host_mod._binding_identity,
            host_mod._binding_context,
        ) = prev_state
    assert response.status == "success"
    assert response.text == '{"ok": true}'
    assert response.output_source.backend == TOOL_DEEPSEEK_HARNESS
    assert response.output_source.tool == TOOL_DEEPSEEK_HARNESS
    assert len(seen_calls) == 1
    assert seen_calls[0]["backend_options"]["dsh_profile"] == "sdk-minimal"

    # Also verify agent server handle_opencode_models & handle_mcp_status route cleanly to DSH
    prev_cfg = agent_server._config
    agent_server._config = SimpleNamespace(opencode=cli_cfg)
    try:
        models_resp = asyncio.run(agent_server.handle_opencode_models("req-dsh-1"))
        mcp_resp = asyncio.run(agent_server.handle_mcp_status("req-dsh-mcp"))
    finally:
        agent_server._config = prev_cfg

    assert models_resp["ok"] is True
    assert models_resp["models"][0]["id"] == "mock/coder"
    assert mcp_resp["targets"] == {"knowledge_base": {"name": "kb", "status": "configured"}}
