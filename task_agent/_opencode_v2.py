"""OpenCode 2.x protocol, authentication, version guard, and V2 plugin helpers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx

logger = logging.getLogger(f"opendeephole.{__name__}")

OPENCODE_V1 = "1"
OPENCODE_V2 = "2"
SUPPORTED_OPENCODE_VERSIONS = (OPENCODE_V1, OPENCODE_V2)

_SEMVER_RE = re.compile(
    r"(?:^|[^0-9A-Za-z._-])v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?(?=$|[^0-9A-Za-z._-])"
)
_RUNTIME_FOOTER_RE = re.compile(r"^\s*(?:bun|node(?:\.js)?)\s+v?\d+\.", re.IGNORECASE)


def normalize_opencode_version(value: object, *, default: str = OPENCODE_V1) -> str:
    """Normalize an OpenCode major-version selector to '1' or '2'."""
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"Unsupported OpenCode version: {value!r}; expected '1' or '2'")
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "1.x", "v1", "v1.x"}:
        return OPENCODE_V1
    if text in {"2", "2.x", "v2", "v2.x"}:
        return OPENCODE_V2
    raise ValueError(f"Unsupported OpenCode version: {value!r}; expected '1' or '2'")


def parse_opencode_major_version(version_output: object) -> tuple[str | None, str]:
    """Extract (major_version, matched_semver) from `<executable> --version` output.

    Ignores Bun/Node crash footers (e.g. `Bun v1.4.4`) and `0.0.0-*` dev builds so
    canary builds fall through to the health endpoint check instead of false-failing.
    """
    raw = str(version_output or "")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or _RUNTIME_FOOTER_RE.match(stripped):
            continue
        for match in _SEMVER_RE.finditer(stripped):
            major = match.group(1)
            semver = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
            if major == "0":
                return None, semver
            return major, semver
    return None, ""


def verify_opencode_executable_version(
    *,
    configured_version: str,
    executable: str,
    version_output: str,
    error_cls: type[RuntimeError],
) -> None:
    """Raise a non-port-retryable startup error if binary major version mismatches config."""
    expected = normalize_opencode_version(configured_version)
    detected_major, detected_semver = parse_opencode_major_version(version_output)
    if detected_major is None or detected_major == expected:
        return
    raise error_cls(
        f"OpenCode 版本不匹配：当前配置选择 OpenCode {expected}.x，"
        f"但可执行文件 {executable!r} 实际返回版本为 {detected_semver}（{detected_major}.x）。"
        f"请在客户端配置中将 OpenCode 版本切换为 {detected_major}.x，"
        f"或填写正确的 OpenCode {expected}.x 可执行文件路径。",
        retry_kind="config",
    )


FILE_WRITE_PLUGIN_V2_SOURCE = r'''import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const pluginDirectory = path.dirname(fileURLToPath(import.meta.url))
const bindingDirectory = path.join(pluginDirectory, "command-bindings")
const parents = new Map()
const childBindings = new Map()
const digest = (value) => crypto.createHash("sha256").update(String(value || "")).digest("hex")
const bindingPath = (sessionID) => path.join(bindingDirectory, `${digest(sessionID)}.json`)
const normalizedTool = (value) => String(value || "").trim().toLowerCase().replaceAll("-", "_")
const pathText = (value) => typeof value === "string" ? value.trim() : ""
const objectValue = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {}

const readDirectBinding = async (sessionID) => {
  try {
    const value = JSON.parse(await fs.readFile(bindingPath(sessionID), "utf8"))
    if (!value || ![1, 2].includes(value.version) || !Array.isArray(value.allowed_commands)) return null
    if (typeof value.audit_path !== "string" || !value.audit_path.trim()) return null
    return value
  } catch (error) {
    if (error?.code === "ENOENT") return null
    throw error
  }
}

const resolveBinding = async (sessionID) => {
  let current = String(sessionID || "")
  const visited = new Set()
  for (let depth = 0; current && depth < 32 && !visited.has(current); depth += 1) {
    visited.add(current)
    const binding = await readDirectBinding(current)
    if (binding) {
      if (current !== String(sessionID || "") && binding.binding_id
        && childBindings.get(String(sessionID || "")) !== binding.binding_id) {
        return { ...binding, allowed_commands: [], tool_rules: [], permission_rules: [] }
      }
      return binding
    }
    current = String(parents.get(current) || "")
  }
  return null
}

const commandText = (args) => pathText(args?.command) || pathText(args?.cmd)

const literalCommandArgs = (command, windows) => {
  if (/[\x00-\x08\x0a-\x1f]/.test(command)) return null
  const words = []
  let word = "", quote = "", active = false
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]
    if (windows && "$`%!".includes(char)) return null
    if (quote) {
      if (char === quote) quote = ""
      else if (quote === '"' && !windows && char === "\\") {
        if (index + 1 < command.length && '\\"$`'.includes(command[index + 1])) {
          word += command[++index]
        } else word += char
      } else if (quote === '"' && "$`".includes(char)) return null
      else word += char
    } else if (char === " " || char === "\t") {
      if (active) { words.push(word); word = ""; active = false }
    } else if (char === '"' || char === "'") {
      quote = char
      active = true
    } else if (char === "\\" && !windows) {
      if (++index === command.length) return null
      word += command[index]
      active = true
    } else if ("|&;<>(){}[]*?~$`#".includes(char)) return null
    else { word += char; active = true }
  }
  if (quote) return null
  if (active) words.push(word)
  return words
}

const absoluteCommandPath = (value, windows) => {
  const paths = windows ? path.win32 : path.posix
  if (!paths.isAbsolute(value)) return ""
  const normalized = paths.normalize(value)
  if (!windows) return normalized
  const root = paths.parse(normalized).root
  if (!root.includes(":") && !root.startsWith("\\\\")) return ""
  return normalized.toLowerCase()
}

const boundCommand = (binding, command) => {
  if (!binding || !command) return ""
  if (binding.allowed_commands.includes(command)) return command
  if (binding.bash_command_match_mode !== "bound_python_script") return ""
  const windows = binding.command_platform === "win32"
  const argv = literalCommandArgs(command, windows)
  if (!argv || argv.length < 2) return ""
  const pythonNames = ["python", "python3", "python.exe", "python3.exe"]
  const hostPython = absoluteCommandPath(pathText(binding.python_executable), windows)
  if (!pythonNames.includes(windows ? argv[0].toLowerCase() : argv[0])
    && !(hostPython && absoluteCommandPath(argv[0], windows) === hostPython)) return ""
  const script = absoluteCommandPath(argv[1], windows)
  if (!script) return ""
  const canonical = objectValue(binding.python_script_commands)[script]
  return typeof canonical === "string" && binding.allowed_commands.includes(canonical)
    ? canonical : ""
}

const wildcardMatch = (pattern, text) => {
  const expression = String(pattern || "").split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")
  return new RegExp(`^${expression}$`).test(String(text || ""))
}

const toolAllowed = (binding, tool) => {
  if (!Array.isArray(binding.tool_rules)) return false
  let allowed = false
  for (const [pattern, enabled] of binding.tool_rules) {
    if (wildcardMatch(pattern, tool)) allowed = enabled === true
  }
  return allowed
}

const permissionRuleOutcome = (binding, action, resource) => {
  if (!Array.isArray(binding?.permission_rules)) return ""
  const normalizedAction = normalizedTool(action)
  let outcome = ""
  for (const rule of binding.permission_rules) {
    if (!rule || typeof rule !== "object") continue
    const rulePerm = normalizedTool(rule.permission)
    const actionMatches = rulePerm === "*"
      || rulePerm === normalizedAction
      || (normalizedAction === "shell" && rulePerm === "bash")
      || (normalizedAction === "bash" && rulePerm === "shell")
      || (["write", "apply_patch", "patch"].includes(normalizedAction) && rulePerm === "edit")
    if (!actionMatches) continue
    const pattern = String(rule.pattern ?? "*")
    if (wildcardMatch(pattern, resource)) {
      outcome = String(rule.action || "")
    }
  }
  return outcome
}

const permissionDeniedError = (binding, reason) => {
  const validationHint = binding?.task_type === "threat_analysis"
    && binding.allowed_commands.length
    && (toolAllowed(binding, "bash") || toolAllowed(binding, "shell"))
      ? ` To validate the artifacts, run one of these exact commands:\n${binding.allowed_commands.join("\n")}`
      : ""
  return new Error(`Permission denied: ${reason}${validationHint}`)
}

const unboundCommandError = (binding, phase) => permissionDeniedError(
  binding, `Shell command is not bound to this OpenDeepHole task (${phase}).`,
)

const commandOutputText = (output, metadata, errorObj) => {
  const values = [
    typeof output === "string" ? output : output?.output,
    metadata.output,
    metadata.stdout,
    metadata.stderr,
    typeof errorObj === "string" ? errorObj : errorObj?.message,
  ].filter((value) => typeof value === "string" && value.length)
  return [...new Set(values)].join("\n")
}

const outputTail = (value, limit) => {
  const raw = Buffer.from(String(value || ""), "utf8")
  const size = Number.isFinite(Number(limit)) && Number(limit) > 0 ? Number(limit) : 0
  const truncated = size > 0 && raw.length > size
  return {
    output_tail: (truncated ? raw.subarray(raw.length - size) : raw).toString("utf8"),
    output_bytes: raw.length,
    output_truncated: truncated,
  }
}

const hasExactLine = (value, marker) => Boolean(marker) && String(value || "")
  .split(/\r?\n/)
  .some((line) => line.trim() === marker)

const appendAudit = async (binding, event) => {
  await fs.appendFile(
    binding.audit_path,
    `${JSON.stringify({ version: 1, time_ms: Date.now(), ...event })}\n`,
    { encoding: "utf8", mode: 0o600 },
  )
}

const writtenFiles = (tool, args, metadata, directory) => {
  const files = []
  const addFile = (rawPath, created = false) => {
    const value = pathText(rawPath)
    if (!value) return
    files.push({
      path: path.isAbsolute(value) ? path.normalize(value) : path.resolve(directory, value),
      created: Boolean(created),
    })
  }
  if (tool === "write" || tool === "edit") {
    const fileDiff = objectValue(metadata.filediff)
    const rawPath = pathText(metadata.filepath)
      || pathText(metadata.filePath)
      || pathText(fileDiff.file)
      || pathText(args.filePath)
      || pathText(args.file_path)
      || pathText(args.path)
    const created = tool === "write"
      ? metadata.exists === false
      : (args.oldString ?? args.old_string) === ""
    addFile(rawPath, created)
  } else if (["apply_patch", "patch"].includes(tool)) {
    const changes = Array.isArray(metadata.files) ? metadata.files : []
    for (const item of changes) {
      if (!item || typeof item !== "object") continue
      const changeType = String(item.type || "").trim().toLowerCase()
      if (changeType === "delete") continue
      const rawPath = changeType === "move"
        ? pathText(item.movePath) || pathText(item.move_path)
        : pathText(item.filePath) || pathText(item.file_path) || pathText(item.file)
      addFile(rawPath, changeType === "add")
    }
  }
  return [...new Map(files.map((item) => [item.path, item])).values()]
}

const stripInternalServeAuthEnv = (envObj) => {
  const next = { ...objectValue(envObj) }
  delete next.OPENCODE_SERVER_PASSWORD
  delete next.OPENCODE_SERVER_USERNAME
  delete next.OPENCODE_PASSWORD
  return next
}

const applyPrependedPath = (envObj, binding) => {
  const env = stripInternalServeAuthEnv(envObj)
  if (!binding || !Array.isArray(binding.path_prepend) || !binding.path_prepend.length) return env
  const win = process.platform === "win32" || binding.command_platform === "win32"
  const delim = win ? path.win32.delimiter : path.delimiter
  const envPathEntry = Object.entries(env).find(([key, val]) => key.toLowerCase() === "path" && pathText(val))
  const current = envPathEntry ? pathText(envPathEntry[1]) : (pathText(process.env.PATH) || pathText(process.env.Path))
  const currentEntries = current ? current.split(delim) : []
  const prepended = binding.path_prepend.filter((value) => typeof value === "string" && value.trim())
  const normalized = new Set(prepended.map((value) => win ? value.toLowerCase() : value))
  const retained = currentEntries.filter((value) => !normalized.has(win ? value.toLowerCase() : value))
  const joined = [...prepended, ...retained].join(delim)
  const cleaned = Object.fromEntries(Object.entries(env).filter(([key]) => key.toLowerCase() !== "path"))
  return win ? { ...cleaned, Path: joined, PATH: joined } : { ...cleaned, PATH: joined }
}

const extractSessionID = (first, second) => pathText(first?.sessionID)
  || pathText(first?.session?.id)
  || pathText(first?.sessionId)
  || pathText(second?.sessionID)

const handleEventEnvelope = async (raw) => {
  const event = raw?.event && typeof raw.event === "object" ? raw.event : raw
  const props = objectValue(event?.properties || event?.data || event)
  const info = objectValue(props.info || props.session)
  const sessionID = pathText(info.id) || pathText(info.sessionID) || pathText(props.sessionID)
  const parentID = pathText(info.parentID) || pathText(info.parentId) || pathText(props.parentID)
  const eventType = String(event?.type || event?.name || "")
  if (sessionID && parentID) {
    parents.set(sessionID, parentID)
    if (parents.size > 4096) parents.delete(parents.keys().next().value)
    if (eventType === "session.created" || eventType === "session.forked") {
      const binding = await resolveBinding(parentID)
      if (binding?.binding_id) childBindings.set(sessionID, binding.binding_id)
      if (childBindings.size > 4096) childBindings.delete(childBindings.keys().next().value)
    }
  }
  if (eventType === "session.deleted" && sessionID) {
    parents.delete(sessionID)
    childBindings.delete(sessionID)
  }
}

export default {
  id: "opendeephole-file-write-hook",
  async setup(ctx) {
    const directory = pathText(ctx?.directory) || pathText(ctx?.worktree) || process.cwd()

    if (typeof ctx?.event?.subscribe === "function") {
      await ctx.event.subscribe(handleEventEnvelope)
    } else if (typeof ctx?.event?.hook === "function") {
      await ctx.event.hook("event", handleEventEnvelope)
    }

    if (typeof ctx?.permission?.hook === "function") {
      await ctx.permission.hook("evaluate", async (event) => {
        if (!event || typeof event !== "object") return
        const sessionID = extractSessionID(event)
        const binding = sessionID ? await resolveBinding(sessionID) : null
        const action = normalizedTool(event.action || event.permission || event.tool)
        const resources = Array.isArray(event.resources) && event.resources.length
          ? event.resources.map((item) => String(item ?? ""))
          : [String(event.resource ?? event.pattern ?? "*")]

        if (action === "question") {
          event.effect = "deny"
          return
        }
        if (!binding) {
          if (event.effect === "ask") event.effect = "deny"
          return
        }
        if (action === "shell" || action === "bash") {
          const allBound = resources.length > 0
            && (toolAllowed(binding, "bash") || toolAllowed(binding, "shell"))
            && resources.every((cmd) => Boolean(boundCommand(binding, pathText(cmd))))
          event.effect = allBound ? "allow" : "deny"
          return
        }
        const outcomes = resources.map((res) => permissionRuleOutcome(binding, action, res)).filter(Boolean)
        if (outcomes.includes("deny")) {
          event.effect = "deny"
        } else if (outcomes.length === resources.length && outcomes.every((item) => item === "allow")) {
          event.effect = "allow"
        } else if (event.effect === "ask") {
          event.effect = "deny"
        }
      })
    }

    if (typeof ctx?.shell?.hook === "function") {
      await ctx.shell.hook("create.before", async (event) => {
        if (!event || typeof event !== "object") return
        const sessionID = extractSessionID(event)
        const binding = sessionID ? await resolveBinding(sessionID) : null
        event.env = applyPrependedPath(event.env || process.env, binding)
        if (typeof event.command === "string") {
          if (!binding) {
            throw permissionDeniedError(null, "This Session has no active OpenDeepHole task permission binding")
          }
          if (!toolAllowed(binding, "bash") && !toolAllowed(binding, "shell")) {
            throw permissionDeniedError(binding, "Tool is not allowed for this OpenDeepHole task")
          }
          const canonical = boundCommand(binding, pathText(event.command))
          if (!canonical) throw unboundCommandError(binding, "shell.create.before")
          event.command = canonical
        }
      })
    }

    if (typeof ctx?.tool?.hook === "function") {
      await ctx.tool.hook("execute.before", async (first, second) => {
        const sessionID = extractSessionID(first, second)
        const binding = await resolveBinding(sessionID)
        const rawToolName = String(first?.tool || "")
        if (!binding) {
          throw permissionDeniedError(null, "This Session has no active OpenDeepHole task permission binding")
        }
        if (!toolAllowed(binding, rawToolName)) {
          throw permissionDeniedError(binding, "Tool is not allowed for this OpenDeepHole task")
        }
        const tool = normalizedTool(rawToolName)
        const args = second?.args && typeof second.args === "object"
          ? second.args
          : first?.args && typeof first.args === "object"
            ? first.args
            : objectValue(first?.input)
        if (tool === "task" && pathText(args.task_id)
          && binding.binding_id && childBindings.get(args.task_id) !== binding.binding_id) {
          throw new Error("This child Session has no current task permission binding. Start a new subtask without task_id.")
        }
        if (!["bash", "shell"].includes(tool)) return
        const canonical = boundCommand(binding, commandText(args))
        if (!canonical) throw unboundCommandError(binding, "before")
        if (typeof args.command === "string") args.command = canonical
        if (typeof args.cmd === "string") args.cmd = canonical
      })

      await ctx.tool.hook("execute.after", async (first, second) => {
        const tool = normalizedTool(first?.tool)
        const sessionID = extractSessionID(first, second)
        const callID = pathText(first?.callID) || pathText(first?.id)
        const args = first?.args && typeof first.args === "object"
          ? first.args
          : objectValue(first?.input)
        const status = pathText(first?.status) || "completed"
        const resultTarget = second && typeof second === "object"
          ? second
          : first?.result && typeof first.result === "object"
            ? first.result
            : first
        const originalMetadata = objectValue(resultTarget?.metadata || first?.metadata)
        const binding = await resolveBinding(sessionID)

        if (["bash", "shell"].includes(tool)) {
          if (!binding) return
          const rawCmd = commandText(args)
          const canonical = boundCommand(binding, rawCmd) || rawCmd
          if (!binding.allowed_commands.includes(canonical)) {
            if (status === "error") return
            throw unboundCommandError(binding, "after")
          }
          const outputMetadata = objectValue(resultTarget?.structured)
          const nestedMetadata = objectValue(originalMetadata.structured)
          const rawExitCode = originalMetadata.exitCode ?? originalMetadata.exit_code
            ?? originalMetadata.exit ?? originalMetadata.code ?? nestedMetadata.exit
            ?? outputMetadata.exit ?? resultTarget?.exit
            ?? (status === "error" ? (first?.error?.exitCode ?? first?.error?.code) : undefined)
          const exitCode = rawExitCode !== undefined && rawExitCode !== null && rawExitCode !== ""
            && Number.isFinite(Number(rawExitCode))
              ? Number(rawExitCode)
              : null
          const commandOutput = commandOutputText(resultTarget, originalMetadata, first?.error)
          const marker = objectValue(binding.success_markers)[canonical]
          const timedOut = Boolean(
            originalMetadata.timeout ?? originalMetadata.timed_out ?? nestedMetadata.timeout
            ?? outputMetadata.timeout ?? resultTarget?.timeout
            ?? (status === "error" && /timed?\s*out/i.test(String(first?.error?.message || first?.error || "")))
          )
          const markerRequired = typeof marker === "string" && marker.length > 0
          const markerMatched = !timedOut && status !== "error" && hasExactLine(commandOutput, marker)
          const success = status !== "error" && !timedOut && (markerRequired
            ? markerMatched && (exitCode === null || exitCode === 0)
            : exitCode === 0)
          await appendAudit(binding, {
            kind: "command",
            session_id: sessionID,
            call_id: callID,
            command: canonical,
            exit_code: exitCode,
            timed_out: timedOut,
            success,
            success_source: success ? (exitCode === 0 ? "exit_code" : "output_marker") : "",
            ...(markerRequired ? { success_marker_matched: markerMatched } : {}),
            ...outputTail(commandOutput, binding.output_tail_bytes),
          })
          return
        }

        if (status === "error" || !["write", "edit", "apply_patch", "patch"].includes(tool)) return
        const files = writtenFiles(tool, args, originalMetadata, directory)
        if (!files.length) return
        const enrichedMetadata = {
          ...originalMetadata,
          opendeepholeFileWrites: {
            version: 1,
            sessionID,
            callID,
            files,
          },
        }
        try {
          if (resultTarget && typeof resultTarget === "object") {
            resultTarget.metadata = enrichedMetadata
          }
          if (first && typeof first === "object" && first !== resultTarget && "metadata" in first) {
            first.metadata = enrichedMetadata
          }
        } catch {
          // File-write observability must never change the tool call outcome.
        }
        if (!binding) return
        for (const file of files) {
          await appendAudit(binding, {
            kind: "file_write",
            session_id: sessionID,
            call_id: callID,
            path: file.path,
          })
        }
      })
    }
  },
}
'''

FILE_WRITE_PLUGIN_V2_HASH = hashlib.sha256(
    FILE_WRITE_PLUGIN_V2_SOURCE.encode("utf-8")
).hexdigest()[:16]

KNOWLEDGE_PROJECT_PLUGIN_V2_SOURCE = r'''import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const bindingDirectory = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "knowledge-bindings",
)
const parents = new Map()
const pathText = (value) => typeof value === "string" ? value.trim() : ""
const objectValue = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {}
const bindingPath = (sessionID) => path.join(
  bindingDirectory,
  `${crypto.createHash("sha256").update(String(sessionID || "")).digest("hex")}.json`,
)

const readDirectBinding = async (sessionID) => {
  try {
    const value = JSON.parse(await fs.readFile(bindingPath(sessionID), "utf8"))
    if (!value || ![1, 2].includes(value.version) || typeof value.project_id !== "string") return null
    if (!value.project_id.trim()) return null
    return value
  } catch (error) {
    if (error?.code === "ENOENT") return null
    throw error
  }
}

const resolveBinding = async (sessionID) => {
  let current = String(sessionID || "")
  const visited = new Set()
  for (let depth = 0; current && depth < 32 && !visited.has(current); depth += 1) {
    visited.add(current)
    const binding = await readDirectBinding(current)
    if (binding) return binding
    current = String(parents.get(current) || "")
  }
  return null
}

const handleEventEnvelope = async (raw) => {
  const event = raw?.event && typeof raw.event === "object" ? raw.event : raw
  const props = objectValue(event?.properties || event?.data || event)
  const info = objectValue(props.info || props.session)
  const sessionID = pathText(info.id) || pathText(info.sessionID) || pathText(props.sessionID)
  const parentID = pathText(info.parentID) || pathText(info.parentId) || pathText(props.parentID)
  const eventType = String(event?.type || event?.name || "")
  if (sessionID && parentID) {
    parents.set(sessionID, parentID)
    if (parents.size > 4096) parents.delete(parents.keys().next().value)
  }
  if (eventType === "session.deleted" && sessionID) parents.delete(sessionID)
}

export default {
  id: "opendeephole-knowledge-project-hook",
  async setup(ctx) {
    if (typeof ctx?.event?.subscribe === "function") {
      await ctx.event.subscribe(handleEventEnvelope)
    } else if (typeof ctx?.event?.hook === "function") {
      await ctx.event.hook("event", handleEventEnvelope)
    }
    if (typeof ctx?.tool?.hook === "function") {
      await ctx.tool.hook("execute.before", async (first, second) => {
        const sessionID = pathText(first?.sessionID)
          || pathText(first?.session?.id)
          || pathText(second?.sessionID)
        const binding = await resolveBinding(sessionID)
        if (!binding) return
        const tool = String(first?.tool || "")
        const blocked = Array.isArray(binding.blocked_tool_ids) ? binding.blocked_tool_ids : []
        if (blocked.includes(tool)) {
          throw new Error("Knowledge-base project management tools are platform-only")
        }
        const allowed = Array.isArray(binding.allowed_tool_ids) ? binding.allowed_tool_ids : []
        const prefixes = Array.isArray(binding.tool_id_prefixes) ? binding.tool_id_prefixes : []
        if (!allowed.includes(tool) && !prefixes.some((prefix) => tool.startsWith(prefix))) return
        const args = second?.args && typeof second.args === "object" && !Array.isArray(second.args)
          ? second.args
          : first?.args && typeof first.args === "object" && !Array.isArray(first.args)
            ? first.args
            : first?.input && typeof first.input === "object" && !Array.isArray(first.input)
              ? first.input
              : null
        if (!args) {
          throw new Error("Knowledge-base tool arguments must be an object")
        }
        args.project_id = binding.project_id
      })
    }
  },
}
'''

KNOWLEDGE_PROJECT_PLUGIN_V2_HASH = hashlib.sha256(
    KNOWLEDGE_PROJECT_PLUGIN_V2_SOURCE.encode("utf-8")
).hexdigest()[:16]


def api_path(opencode_version: str, v1_path: str, v2_path: str | None = None) -> str:
    """Return the version-appropriate primary endpoint path."""
    if normalize_opencode_version(opencode_version) == OPENCODE_V2:
        if v2_path is not None:
            return v2_path
        return f"/api{v1_path}" if not v1_path.startswith("/api/") else v1_path
    return v1_path


def health_probe_paths(opencode_version: str) -> tuple[str, ...]:
    if normalize_opencode_version(opencode_version) == OPENCODE_V2:
        return ("/api/health", "/global/health")
    return ("/global/health",)


def parse_health_response(response: httpx.Response) -> tuple[bool, str, str]:
    """Validate an OpenCode health HTTP response, rejecting HTML fallbacks.

    Returns (healthy, version, diagnostic_detail).
    """
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code != 200:
        return False, "", f"HTTP {status_code}"
    content_type = str(getattr(response, "headers", {}).get("content-type", "") or "").lower()
    if "text/html" in content_type:
        return False, "", f"HTTP 200, unexpected HTML response ({content_type})"
    try:
        payload = response.json()
    except Exception as exc:
        return False, "", f"响应不是有效 JSON：{type(exc).__name__}: {exc}"
    if not isinstance(payload, dict):
        return False, "", f"响应类型为 {type(payload).__name__}，预期为对象"
    version = str(payload.get("version") or "").strip()
    if payload.get("healthy") is True:
        return True, version, ""
    return False, version, f"healthy={payload.get('healthy')!r}，预期为 true"


async def discover_v2_openapi_paths(client: httpx.AsyncClient) -> frozenset[str]:
    """Fetch `/doc` or `/api/doc` once to discover supported OpenAPI route templates."""
    for doc_path in ("/api/doc", "/doc"):
        try:
            response = await client.get(doc_path, timeout=2.0)
            if response.status_code != 200:
                continue
            content_type = str(response.headers.get("content-type", "") or "").lower()
            if "text/html" in content_type:
                continue
            spec = response.json()
            paths = spec.get("paths") if isinstance(spec, dict) else None
            if isinstance(paths, dict) and paths:
                return frozenset(str(key) for key in paths)
        except Exception:
            continue
    return frozenset()


def v2_route_supported(discovered_paths: frozenset[str], *templates: str) -> str | None:
    """Return the first template present in discovered OpenAPI paths, if any."""
    if not discovered_paths:
        return None
    for template in templates:
        if template in discovered_paths:
            return template
    return None


def extract_provider_list_v2(data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Parse provider payloads across OpenCode 1.x and 2.x shapes."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)], True
    if not isinstance(data, dict):
        return [], False
    for key in ("all", "providers", "items", "data"):
        raw = data.get(key)
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)], True
        if isinstance(raw, dict):
            entries: list[dict[str, Any]] = []
            for provider_id, value in raw.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("id", str(provider_id))
                    entries.append(item)
            return entries, True
    return [], False


def normalize_message_envelope(raw: Any, fallback_session_id: str = "") -> dict[str, Any] | None:
    """Normalize both `{info, parts}` and flat `{id, role, parts, ...}` message shapes."""
    if not isinstance(raw, dict):
        return None
    if isinstance(raw.get("info"), dict):
        return raw
    role = raw.get("role")
    if isinstance(role, str) and role.strip():
        info = {
            key: value
            for key, value in raw.items()
            if key != "parts"
        }
        if fallback_session_id and not info.get("sessionID"):
            info["sessionID"] = fallback_session_id
        parts = raw.get("parts")
        return {
            "info": info,
            "parts": parts if isinstance(parts, list) else [],
        }
    return None


def normalize_message_list(raw: Any, fallback_session_id: str = "") -> list[dict[str, Any]] | None:
    """Normalize a `/message` response (list or `{messages: [...]}`) into `{info, parts}` items."""
    items: Any = raw
    if isinstance(raw, dict):
        for key in ("messages", "items", "data"):
            if isinstance(raw.get(key), list):
                items = raw[key]
                break
    if not isinstance(items, list):
        return None
    normalized: list[dict[str, Any]] = []
    for item in items:
        envelope = normalize_message_envelope(item, fallback_session_id=fallback_session_id)
        if envelope is not None:
            normalized.append(envelope)
    return normalized


async def auto_reject_v2_interactive_event(
    client: httpx.AsyncClient,
    *,
    event_type: str,
    props: dict[str, Any],
    session_id: str,
    params: dict[str, str],
    headers: dict[str, str],
) -> None:
    """Reject unexpected interactive prompts in OpenCode 2.x so unattended scans never hang."""
    request_id = str(
        props.get("id")
        or props.get("requestID")
        or (props.get("request") or {}).get("id")
        if isinstance(props.get("request"), dict)
        else props.get("id") or props.get("requestID") or ""
    ).strip()
    if not session_id or not request_id:
        return
    quoted_sid = quote(session_id, safe="")
    quoted_rid = quote(request_id, safe="")
    candidates: list[tuple[str, dict[str, Any]]] = []
    if event_type == "permission.asked":
        candidates.extend([
            (f"/api/session/{quoted_sid}/permission/{quoted_rid}/reply", {"reply": "reject", "effect": "deny", "action": "deny"}),
            (f"/api/permission/{quoted_rid}/reply", {"reply": "reject", "effect": "deny"}),
        ])
    elif event_type == "question.asked":
        candidates.extend([
            (f"/api/question/{quoted_rid}/reject", {}),
            (f"/api/session/{quoted_sid}/question/{quoted_rid}/reject", {}),
        ])
    elif event_type == "form.created":
        candidates.extend([
            (f"/api/session/{quoted_sid}/form/{quoted_rid}/cancel", {}),
            (f"/api/form/{quoted_rid}/cancel", {}),
        ])
    for path, body in candidates:
        try:
            resp = await client.post(path, params=params, headers=headers, json=body, timeout=2.0)
            if resp.status_code < 400:
                return
        except Exception:
            continue


async def submit_and_resolve_v2_prompt(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    prompt: str,
    payload: dict[str, Any],
    params: dict[str, str],
    headers: dict[str, str],
    discovered_paths: frozenset[str],
    baseline_message_id: str,
    event_state: Any,
    is_terminal_fn: Callable[[dict[str, Any]], bool],
    response_id_fn: Callable[[dict[str, Any]], str],
    assistant_error_fn: Callable[[dict[str, Any]], object | None],
    cancel_event: Any,
    poll_interval: float = 0.2,
    request_timeout: float = 60.0,
) -> httpx.Response:
    """Submit a prompt to OpenCode 2.x and synthesize a completed HTTP response if queued.

    Supports both:
    - Synchronous `/api/session/{id}/message` (or `/session/{id}/message`) returning `{info, parts}`
    - Asynchronous `/api/session/{id}/prompt` returning an immediate queue envelope while the
      assistant turn executes in the background and emits SSE events + `/message` records.
    """
    quoted_sid = quote(session_id, safe="")
    has_sync_message = v2_route_supported(
        discovered_paths,
        "/api/session/{sessionID}/message",
        "/api/session/:sessionID/message",
    )
    has_async_prompt = v2_route_supported(
        discovered_paths,
        "/api/session/{sessionID}/prompt",
        "/api/session/:sessionID/prompt",
    )
    model_spec = payload.get("model")
    if (
        isinstance(model_spec, dict)
        and v2_route_supported(
            discovered_paths,
            "/api/session/{sessionID}/model",
            "/api/session/:sessionID/model",
        )
    ):
        try:
            await client.post(
                f"/api/session/{quoted_sid}/model",
                params=params,
                headers=headers,
                json=model_spec,
                timeout=10.0,
            )
        except Exception:
            pass

    prompt_body = {
        **payload,
        "prompt": prompt,
    }
    if has_async_prompt and not has_sync_message:
        candidate_routes = [
            (f"/api/session/{quoted_sid}/prompt", prompt_body),
            (f"/api/session/{quoted_sid}/message", payload),
        ]
    elif has_sync_message and not has_async_prompt:
        candidate_routes = [
            (f"/api/session/{quoted_sid}/message", payload),
            (f"/api/session/{quoted_sid}/prompt", prompt_body),
        ]
    else:
        candidate_routes = [
            (f"/api/session/{quoted_sid}/prompt", prompt_body),
            (f"/api/session/{quoted_sid}/message", payload),
            (f"/session/{quoted_sid}/message", payload),
        ]

    response: httpx.Response | None = None
    used_path = ""
    for route_path, body in candidate_routes:
        used_path = route_path
        response = await client.post(
            route_path,
            params=params,
            headers=headers,
            json=body,
            timeout=request_timeout,
        )
        if response.status_code not in {404, 405}:
            break

    assert response is not None
    if response.status_code >= 400:
        return response

    # Check if the response itself is already a completed assistant message envelope.
    parsed: Any = None
    if response.content and response.content.strip():
        try:
            parsed = response.json()
        except ValueError:
            parsed = None
    normalized_direct = normalize_message_envelope(parsed, fallback_session_id=session_id)
    if (
        normalized_direct is not None
        and str(normalized_direct.get("info", {}).get("role") or "") == "assistant"
        and is_terminal_fn(normalized_direct)
    ):
        if normalized_direct is not parsed:
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                content=json.dumps(normalized_direct, ensure_ascii=False).encode("utf-8"),
                request=response.request,
            )
        return response

    # Asynchronous V2 prompt mode: wait for session completion via optional `/wait`,
    # SSE `session_terminal`, and `/api/session/{id}/message` history reconciliation.
    wait_route = v2_route_supported(
        discovered_paths,
        "/api/session/{sessionID}/wait",
        "/api/session/:sessionID/wait",
        "/api/experimental/session/{sessionID}/wait",
        "/api/experimental/session/:sessionID/wait",
    )
    wait_task: asyncio.Task | None = None
    if wait_route is not None:
        resolved_wait_path = (
            wait_route.replace("{sessionID}", quoted_sid).replace(":sessionID", quoted_sid)
        )
        wait_task = asyncio.create_task(
            client.post(
                resolved_wait_path,
                params=params,
                headers=headers,
                json={},
                timeout=request_timeout,
            )
        )

    history_paths = [
        f"/api/session/{quoted_sid}/message",
        f"/session/{quoted_sid}/message",
    ]
    session_paths = [
        f"/api/session/{quoted_sid}",
        f"/session/{quoted_sid}",
    ]
    poll_params = {**params, "limit": "200"}
    saw_busy_or_new_message = False
    idle_Observed_at: float | None = None

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError()

            terminal_event_seen = bool(
                event_state is not None and getattr(event_state, "session_terminal", False)
            )
            if wait_task is not None and wait_task.done():
                try:
                    wait_resp = wait_task.result()
                    if wait_resp.status_code < 400:
                        terminal_event_seen = True
                except Exception:
                    pass
                wait_task = None

            messages: list[dict[str, Any]] | None = None
            for hist_path in history_paths:
                try:
                    hist_resp = await client.get(hist_path, params=poll_params, headers=headers, timeout=10.0)
                    if hist_resp.status_code in {404, 405}:
                        continue
                    hist_resp.raise_for_status()
                    messages = normalize_message_list(hist_resp.json(), fallback_session_id=session_id)
                    history_paths = [hist_path]
                    break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

            new_assistants: list[dict[str, Any]] = []
            if messages is not None:
                assistants = [
                    msg for msg in messages
                    if str((msg.get("info") or {}).get("role") or "") == "assistant"
                ]
                if baseline_message_id:
                    baseline_idx = next(
                        (
                            idx for idx, msg in enumerate(assistants)
                            if response_id_fn(msg) == baseline_message_id
                        ),
                        None,
                    )
                    if baseline_idx is not None:
                        new_assistants = assistants[baseline_idx + 1:]
                else:
                    new_assistants = assistants

            if new_assistants:
                saw_busy_or_new_message = True
                # Surface any explicit assistant error immediately once that step finishes.
                for msg in new_assistants:
                    if assistant_error_fn(msg) is not None:
                        return httpx.Response(
                            status_code=200,
                            headers={"content-type": "application/json"},
                            content=json.dumps(msg, ensure_ascii=False).encode("utf-8"),
                            request=response.request,
                        )

                all_terminal = all(is_terminal_fn(msg) for msg in new_assistants)
                if all_terminal:
                    session_busy = False
                    if not terminal_event_seen:
                        for sess_path in session_paths:
                            try:
                                sess_resp = await client.get(
                                    sess_path, params=params, headers=headers, timeout=5.0,
                                )
                                if sess_resp.status_code in {404, 405}:
                                    continue
                                if sess_resp.status_code == 200:
                                    sess_data = sess_resp.json()
                                    status_val = (
                                        sess_data.get("status")
                                        if isinstance(sess_data, dict)
                                        else None
                                    )
                                    status_type = (
                                        str(status_val.get("type") or "")
                                        if isinstance(status_val, dict)
                                        else str(status_val or "")
                                    ).lower()
                                    if status_type in {"busy", "running", "retry"}:
                                        session_busy = True
                                    elif status_type in {"idle", "error", "completed"}:
                                        terminal_event_seen = True
                                    session_paths = [sess_path]
                                break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue

                    # Multi-step tool turns in v2 emit multiple assistant messages: only settle
                    # once session is idle/terminal OR no tool-call-only step is still running.
                    last_assistant = new_assistants[-1]
                    last_finish = str(
                        (last_assistant.get("info") or {}).get("finish") or ""
                    ).strip().lower()
                    tool_step_continuing = last_finish in {"tool-calls", "tool_calls", "tool_use"}
                    if terminal_event_seen or (not session_busy and not tool_step_continuing):
                        if terminal_event_seen or idle_Observed_at is not None:
                            final_envelope = _merge_multistep_text_if_needed(new_assistants)
                            return httpx.Response(
                                status_code=200,
                                headers={"content-type": "application/json"},
                                content=json.dumps(final_envelope, ensure_ascii=False).encode("utf-8"),
                                request=response.request,
                            )
                        idle_Observed_at = time.monotonic()
                    else:
                        idle_Observed_at = None
                else:
                    idle_Observed_at = None
            elif terminal_event_seen and saw_busy_or_new_message:
                break

            # If event_state recorded a fatal session.error before any assistant message row
            # was persisted, synthesize an error envelope rather than hanging until timeout.
            if (
                terminal_event_seen
                and not new_assistants
                and event_state is not None
                and getattr(event_state, "session_errors_emitted", None)
            ):
                err_text = next(iter(event_state.session_errors_emitted))
                synth = {
                    "info": {
                        "id": f"v2-error-{int(time.time() * 1000)}",
                        "sessionID": session_id,
                        "role": "assistant",
                        "error": {"name": "SessionError", "message": err_text},
                    },
                    "parts": [],
                }
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=json.dumps(synth, ensure_ascii=False).encode("utf-8"),
                    request=response.request,
                )

            await asyncio.sleep(poll_interval)
    finally:
        if wait_task is not None and not wait_task.done():
            wait_task.cancel()

    logger.debug("OpenCode v2 prompt on %s finished without new assistant message", used_path)
    return response


def _merge_multistep_text_if_needed(assistants: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the final assistant message, falling back to the last non-empty text step if needed."""
    last = assistants[-1]
    parts = last.get("parts")
    has_text = isinstance(parts, list) and any(
        isinstance(part, dict)
        and part.get("type") == "text"
        and str(part.get("text") or "").strip()
        for part in parts
    )
    if has_text or len(assistants) == 1:
        return last
    for earlier in reversed(assistants[:-1]):
        earlier_parts = earlier.get("parts")
        if not isinstance(earlier_parts, list):
            continue
        text_parts = [
            part for part in earlier_parts
            if isinstance(part, dict)
            and part.get("type") == "text"
            and str(part.get("text") or "").strip()
        ]
        if text_parts:
            merged = dict(last)
            merged["parts"] = [
                *text_parts,
                *(parts if isinstance(parts, list) else []),
            ]
            return merged
    return last
