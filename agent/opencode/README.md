# OpenCode Agent component

`agent.opencode` is the self-contained OpenCode/nga Serve task framework used by the OpenDeepHole Agent. It owns the lazy Serve singleton, task queue, model leases, Session continuation, permissions, retries, event streaming and JSON result validation. It does not provide or start a separate CLI; model work still runs through the existing `opencode serve` or `nga serve` process.

Application stages use only the public task API:

```python
from agent.opencode import run_opencode_task

result = await run_opencode_task(
    task_name="candidate audit",
    task_type="audit",
    prompt="...",
    required_capability="high",
)
```

`task_type` is a documented string contract rather than an exported enum. Supported values are `audit`, `project_audit`, `sensitive_clear`, `report_audit`, `threat_analysis`, `threat_audit`, `fp_review`, `vulnerability_validation`, `git_history`, `variant_hunt`, `memory_api_discovery` and `skill_create`; unknown values are rejected before submission.

The host registers `OpenCodeHostBindings` once during startup. Registration supplies configuration, the shared workspace, resolved Serve process settings and optional MCP selection; it does not instantiate a manager or start Serve. The first `run_opencode_task()` call creates the shared task service and Serve manager on demand. Before sending the prompt, that manager starts Serve when absent, reuses a compatible process, or applies the existing restart/recovery behavior.

The directory has no imports from OpenDeepHole's `agent`, `backend`, `mcp_server` or `code_parser` packages. To extract it into another Python package, copy this directory, install `httpx`, register equivalent host bindings once, and keep task call sites on the public import above.
