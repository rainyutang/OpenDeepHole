"""Submit threat-analysis harness tasks through the task_agent framework."""

from __future__ import annotations

import asyncio
import json
import time
from os import PathLike
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal, Mapping, Sequence

from threat_analysis_harness.stages.base import SUCCEEDED, TaskJson, TaskResultJson
from threat_analysis_harness import validate_attack_tree as tree_validation
from threat_analysis_harness import validate_high_risk_modules as module_validation


TaskAgentCapability = Literal["low", "high"]
TaskAgentRun = Callable[..., Awaitable[Any]]

_DEFAULT_TASK_AGENT_TASK_TYPE = "threat_analysis"
_DEFAULT_REQUIRED_CAPABILITY: TaskAgentCapability = "high"
_FAILED = "failed"
_MODULE_FILE_TASK_TYPES = {"high_risk_module_map", "high_risk_module_merge"}


class TaskAgentSubmitter:
    """Synchronous ``SubmitTasks`` adapter backed by ``run_opencode_task``."""

    def __init__(
        self,
        *,
        config_path: str | PathLike[str] | None = None,
        task_agent_task_type: str = _DEFAULT_TASK_AGENT_TASK_TYPE,
        required_capability: TaskAgentCapability = _DEFAULT_REQUIRED_CAPABILITY,
        invalid_json_retry_count: int = 2,
        run_opencode_task: TaskAgentRun | None = None,
    ) -> None:
        self.config_path = config_path
        self.task_agent_task_type = str(task_agent_task_type or "").strip()
        self.required_capability = _normalize_capability(required_capability)
        self.invalid_json_retry_count = int(invalid_json_retry_count)
        if self.invalid_json_retry_count < 0:
            raise ValueError("invalid_json_retry_count cannot be negative")
        self._run_opencode_task = run_opencode_task

    def submit_tasks(
        self,
        tasks: Sequence[TaskJson],
        *,
        timeout: float | None = None,
    ) -> list[TaskResultJson]:
        """Run a batch of harness task dictionaries and return result dictionaries."""

        return _run_sync(self.submit_tasks_async(tasks, timeout=timeout))

    async def submit_tasks_async(
        self,
        tasks: Sequence[TaskJson],
        *,
        timeout: float | None = None,
    ) -> list[TaskResultJson]:
        coroutines = [self._run_one_task(task) for task in tasks]
        if not coroutines:
            return []
        batch = asyncio.gather(*coroutines)
        if timeout is None:
            return await batch
        return await asyncio.wait_for(batch, timeout=timeout)

    async def _run_one_task(self, task: TaskJson) -> TaskResultJson:
        started_at = time.time()
        output_path = Path(str(task["output_path"]))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        module_file_output = task.get("task_type") in _MODULE_FILE_TASK_TYPES
        file_output = module_file_output or task.get("task_type") == "attack_tree_by_asset"
        output_schema = _task_output_schema(task)
        validation_options: dict[str, Any] = {}
        if file_output:
            if not module_file_output and output_schema is None:
                raise ValueError("Attack tree file output requires a task schema")
            # Resume has already selected reusable files. A new task must not
            # succeed by reading a leftover output; same-Session repairs edit it.
            if not task.get("session_id"):
                output_path.unlink(missing_ok=True)
            if module_file_output:
                command = module_validation.validation_command(output_path.resolve())
            else:
                schema_path = output_path.with_suffix(output_path.suffix + ".schema.json").resolve()
                schema_path.write_text(json.dumps(output_schema, ensure_ascii=False, indent=2), encoding="utf-8")
                command = tree_validation.validation_command(output_path.resolve(), schema_path)

            async def validate_artifact() -> str | None:
                try:
                    if module_file_output:
                        await module_validation.validate_file_async(output_path.resolve())
                    else:
                        await tree_validation.validate_file_async(output_path.resolve(), schema_path)
                        # Check the host schema too; the model cannot edit this copy.
                        tree_validation.validate_file(output_path, output_schema)
                except Exception as exc:
                    return str(exc) or type(exc).__name__
                return None

            validation_options = {
                "readable_paths": (Path(tree_validation.__file__).resolve().parent,),
                "allowed_bash_commands": (command,),
                "bash_command_match_mode": "bound_python_script",
                "post_session_validator": validate_artifact,
                "post_session_validation_retry_count": 1,
            }
        prompt = build_task_agent_prompt(task)
        prompt_path = output_path.with_suffix(output_path.suffix + ".prompt.txt")
        raw_output_path = output_path.with_suffix(output_path.suffix + ".raw.txt")
        log_path = output_path.with_suffix(output_path.suffix + ".log")
        prompt_path.write_text(prompt, encoding="utf-8")

        runner = self._run_opencode_task
        if runner is None:
            from task_agent import run_opencode_task as runner

        try:
            result = await runner(
                task_name=str(task["task_id"]),
                task_type=str(task.get("task_agent_task_type") or self.task_agent_task_type),
                prompt=prompt,
                required_capability=_task_required_capability(
                    task,
                    default=self.required_capability,
                ),
                output_schema=None if file_output else output_schema,
                json_repair_output_prompt=None if file_output else task.get("json_repair_output_prompt"),
                invalid_json_retry_count=int(
                    task.get("invalid_json_retry_count", self.invalid_json_retry_count)
                ),
                session_id=task.get("session_id"),
                config_path=self.config_path,
                **validation_options,
            )
        except Exception as exc:
            finished_at = time.time()
            log_path.write_text(str(exc), encoding="utf-8")
            return _result_json(
                task,
                status=_FAILED,
                output_path=output_path,
                started_at=started_at,
                finished_at=finished_at,
                error=str(exc),
                returncode=1,
                log_path=log_path,
            )

        finished_at = time.time()
        raw_output_path.write_text(str(getattr(result, "text", "") or ""), encoding="utf-8")

        metadata = dict(task.get("metadata", {}))
        metadata["task_agent"] = {
            "session_id": str(getattr(result, "session_id", "") or ""),
            "task_type": str(task.get("task_agent_task_type") or self.task_agent_task_type),
            "status": str(getattr(result, "status", "") or ""),
        }
        model = str(getattr(result, "model", "") or "") or None

        status = str(getattr(result, "status", "") or "")
        if status != "success":
            error = str(getattr(result, "text", "") or f"task_agent status={status or 'unknown'}")
            log_path.write_text(error, encoding="utf-8")
            return _result_json(
                task,
                status=_FAILED,
                output_path=output_path,
                started_at=started_at,
                finished_at=finished_at,
                error=error,
                returncode=124 if status == "timeout" else 1,
                model=model,
                log_path=log_path,
                raw_output=str(getattr(result, "text", "") or ""),
                metadata=metadata,
            )

        output = getattr(result, "structured", None)
        if file_output:
            try:
                output = (
                    module_validation.validate_file(output_path) if module_file_output
                    else tree_validation.validate_file(output_path, output_schema)
                )
            except ValueError as exc:
                log_path.write_text(str(exc), encoding="utf-8")
                return _result_json(
                    task, status=_FAILED, output_path=output_path,
                    started_at=started_at, finished_at=finished_at, error=str(exc),
                    returncode=1, model=model, log_path=log_path,
                    raw_output=str(getattr(result, "text", "") or ""), metadata=metadata,
                )
        elif output_schema is not None and output is None:
            error = "task_agent returned success without schema-validated structured output"
            log_path.write_text(error, encoding="utf-8")
            return _result_json(
                task,
                status=_FAILED,
                output_path=output_path,
                started_at=started_at,
                finished_at=finished_at,
                error=error,
                returncode=1,
                model=model,
                log_path=log_path,
                raw_output=str(getattr(result, "text", "") or ""),
                metadata=metadata,
            )
        if not file_output and output_schema is None:
            output = _parse_json_or_text(str(getattr(result, "text", "") or ""))

        if not file_output:
            output_path.write_text(
                json.dumps(output, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        log_path.write_text(
            json.dumps(
                {
                    "task_id": str(task["task_id"]),
                    "task_type": str(task["task_type"]),
                    "task_agent": metadata["task_agent"],
                    "model": model,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return _result_json(
            task,
            status=SUCCEEDED,
            output_path=output_path,
            started_at=started_at,
            finished_at=finished_at,
            returncode=0,
            model=model,
            log_path=log_path,
            raw_output=str(getattr(result, "text", "") or ""),
            output=output,
            metadata=metadata,
        )


def submit_tasks(
    tasks: Sequence[TaskJson],
    *,
    timeout: float | None = None,
    config_path: str | PathLike[str] | None = None,
) -> list[TaskResultJson]:
    """Convenience function matching the harness ``SubmitTasks`` protocol."""

    return TaskAgentSubmitter(config_path=config_path).submit_tasks(tasks, timeout=timeout)


def build_task_agent_prompt(task: Mapping[str, Any]) -> str:
    """Build an initial skill invocation or a plain same-session continuation prompt."""

    runtime_prompt = str(task.get("runtime_prompt") or "").strip()
    if task.get("task_type") in _MODULE_FILE_TASK_TYPES:
        output_path = Path(str(task["output_path"])).resolve()
        command = module_validation.validation_command(output_path)
        runtime_prompt += (
            f"\n\n将高风险模块 JSON 数组写入：{output_path}\n"
            "字段格式遵循本 Skill 的输出要求。\n"
            f"写入后可执行以下命令校验文件：\n{command}\n"
        )
    if task.get("task_type") == "attack_tree_by_asset":
        output_path = Path(str(task["output_path"])).resolve()
        schema_path = output_path.with_suffix(output_path.suffix + ".schema.json")
        command = tree_validation.validation_command(output_path, schema_path)
        runtime_prompt += (
            f"\n\n攻击树文件输出要求（含当前 Session 的纠正）：\n"
            f"读取任务 Schema：{schema_path}\n"
            f"唯一模式库：{tree_validation.CATALOG_PATH}\n"
            f"将完整攻击树 JSON 写入：{output_path}\n"
            "pattern_id 与 pattern_name 必须成对原样匹配模式库，同一路径不得重复；"
            "无适用模式时允许空数组。只修改指定输出文件，不得修改 Schema 或模式库。"
            "聊天回复只需简短说明完成，不得用回复中的 JSON 代替文件。\n"
            f"写完后可执行以下命令自检：\n{command}\n"
            "自检命令必须逐字复制，不得改变参数或拼接其他命令。"
            "是否执行自检不作为完成条件；宿主会独立运行 Python 校验。"
            "校验失败时根据反馈在当前 Session 修正同一文件。"
        )
    if task.get("invoke_skill") is False:
        if not runtime_prompt:
            raise ValueError("task runtime_prompt is required when skill invocation is disabled")
        return runtime_prompt
    skill_name = _task_skill_name(task)
    if not runtime_prompt:
        return f"/{skill_name}"
    return f"/{skill_name}\n\n{runtime_prompt}"


def _run_sync(awaitable: Awaitable[Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()
    raise RuntimeError(
        "TaskAgentSubmitter.submit_tasks cannot run inside an active event loop; "
        "use submit_tasks_async instead"
    )


def _task_skill_name(task: Mapping[str, Any]) -> str:
    raw = str(task.get("skill_name") or "").strip()
    if not raw:
        raise ValueError("task skill_name is required")
    return raw


def _task_output_schema(task: Mapping[str, Any]) -> dict[str, Any] | None:
    schema = task.get("output_schema")
    if isinstance(schema, dict):
        return schema
    if schema is not None:
        raise TypeError("task output_schema must be a dict when provided")
    schema_path = task.get("output_schema_path")
    if schema_path is None:
        return None
    loaded = json.loads(Path(str(schema_path)).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError(f"task output_schema_path must contain a JSON object: {schema_path}")
    return loaded


def _task_required_capability(
    task: Mapping[str, Any],
    *,
    default: TaskAgentCapability,
) -> TaskAgentCapability:
    return _normalize_capability(task.get("required_capability", default))


def _normalize_capability(value: Any) -> TaskAgentCapability:
    normalized = str(value or "").strip().lower()
    if normalized not in {"low", "high"}:
        raise ValueError("task_agent required_capability must be 'low' or 'high'")
    return normalized  # type: ignore[return-value]


def _parse_json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _result_json(
    task: Mapping[str, Any],
    *,
    status: str,
    output_path: Path,
    started_at: float,
    finished_at: float,
    returncode: int,
    model: str | None = None,
    log_path: Path | None = None,
    error: str | None = None,
    raw_output: str | None = None,
    output: Any | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> TaskResultJson:
    return {
        "task_id": str(task["task_id"]),
        "task_type": str(task["task_type"]),
        "status": status,
        "output_path": str(output_path),
        "model": model,
        "log_path": None if log_path is None else str(log_path),
        "error": error,
        "started_at": started_at,
        "finished_at": finished_at,
        "returncode": returncode,
        "output": output,
        "raw_output": raw_output,
        "metadata": dict(task.get("metadata", {}) if metadata is None else metadata),
    }
