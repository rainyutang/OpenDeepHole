"""OpenCode 2.x protocol, authentication, version guard, and V2 plugin helpers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
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
const bindingRoot = path.basename(pluginDirectory) === ".opendeephole-plugins"
  ? pluginDirectory
  : path.dirname(pluginDirectory)
const bindingDirectory = path.join(bindingRoot, "command-bindings")
const parents = new Map()
const childBindings = new Map()
const pendingShellBindings = new Map()
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

const lookupParentFromSessionApi = async (ctx, sessionID) => {
  if (!sessionID || typeof ctx?.session?.get !== "function") return ""
  for (const arg of [{ sessionID }, { id: sessionID }, sessionID]) {
    try {
      const info = await ctx.session.get(arg)
      const data = objectValue(info?.data || info)
      const parentID = pathText(data.parentID) || pathText(data.parentId)
      if (parentID) {
        parents.set(sessionID, parentID)
        if (parents.size > 4096) parents.delete(parents.keys().next().value)
        return parentID
      }
      if (pathText(data.id)) return ""
    } catch {
      // Try next calling convention.
    }
  }
  return ""
}

const resolveBinding = async (sessionID, ctx = null) => {
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
    let nextParent = String(parents.get(current) || "")
    if (!nextParent && ctx) {
      nextParent = await lookupParentFromSessionApi(ctx, current)
    }
    current = nextParent
  }
  return null
}

const rememberPendingShellBinding = (command, binding) => {
  const key = pathText(command)
  if (!key || !binding) return
  const now = Date.now()
  pendingShellBindings.set(key, { binding, ts: now })
  if (pendingShellBindings.size > 256) {
    for (const [entryKey, entry] of pendingShellBindings.entries()) {
      if (now - entry.ts > 60_000 || pendingShellBindings.size > 256) {
        pendingShellBindings.delete(entryKey)
      }
    }
  }
}

const lookupPendingShellBinding = (command) => {
  const key = pathText(command)
  if (!key) return null
  const entry = pendingShellBindings.get(key)
  if (!entry) return null
  if (Date.now() - entry.ts > 60_000) {
    pendingShellBindings.delete(key)
    return null
  }
  return entry.binding
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
  const evaluate = (name) => {
    let matched = false
    let allowed = false
    for (const [pattern, enabled] of binding.tool_rules) {
      if (wildcardMatch(pattern, name)) {
        matched = true
        allowed = enabled === true
      }
    }
    return { matched, allowed }
  }
  const direct = evaluate(tool)
  if (direct.matched) return direct.allowed
  const norm = normalizedTool(tool)
  if (norm === "shell") return evaluate("bash").allowed
  if (norm === "bash") return evaluate("shell").allowed
  return false
}

const resourceCandidates = (resource, directory) => {
  const raw = String(resource ?? "")
  const items = new Set([raw])
  if (raw.includes("\\")) items.add(raw.replaceAll("\\", "/"))
  if (directory && raw && raw !== "*" && !path.isAbsolute(raw)) {
    const resolved = path.resolve(directory, raw)
    items.add(resolved)
    if (resolved.includes("\\")) items.add(resolved.replaceAll("\\", "/"))
  }
  return [...items]
}

const permissionRuleOutcome = (binding, action, resource, directory = "") => {
  if (!Array.isArray(binding?.permission_rules)) return ""
  const normalizedAction = normalizedTool(action)
  const candidates = resourceCandidates(resource, directory)
  let outcome = ""
  for (const rule of binding.permission_rules) {
    if (!rule || typeof rule !== "object") continue
    const rulePerm = normalizedTool(rule.permission ?? rule.action)
    const actionMatches = rulePerm === "*"
      || rulePerm === normalizedAction
      || (normalizedAction === "shell" && rulePerm === "bash")
      || (normalizedAction === "bash" && rulePerm === "shell")
      || (["write", "apply_patch", "patch"].includes(normalizedAction) && rulePerm === "edit")
    if (!actionMatches) continue
    const rawPattern = String(rule.pattern ?? rule.resource ?? "*")
    const patternVariants = rawPattern.includes("\\")
      ? [rawPattern, rawPattern.replaceAll("\\", "/")]
      : [rawPattern]
    if (patternVariants.some((pat) => candidates.some((cand) => wildcardMatch(pat, cand)))) {
      outcome = String(rule.effect ?? rule.action ?? "")
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

const contentText = (items) => {
  if (!Array.isArray(items)) return ""
  return items
    .filter((item) => item && typeof item === "object" && typeof item.text === "string" && item.text.length)
    .map((item) => item.text)
    .join("\n")
}

const commandOutputText = (output, metadata, errorObj) => {
  const outputObj = objectValue(output?.output)
  const values = [
    typeof output === "string" ? output : null,
    typeof output?.output === "string" ? output.output : null,
    typeof outputObj.output === "string" ? outputObj.output : null,
    contentText(output?.content),
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

const writtenFiles = (tool, args, metadata, directory, resultTarget = null) => {
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
    const outputSummary = typeof resultTarget?.output === "string"
      ? resultTarget.output
      : contentText(resultTarget?.content)
    const created = tool === "write"
      ? (metadata.exists === false || /^created file successfully/i.test(outputSummary.trim()))
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

const handleEventEnvelope = async (raw, ctx = null) => {
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
      const binding = await resolveBinding(parentID, ctx)
      if (binding?.binding_id) childBindings.set(sessionID, binding.binding_id)
      if (childBindings.size > 4096) childBindings.delete(childBindings.keys().next().value)
    }
  }
  if (eventType === "session.deleted" && sessionID) {
    parents.delete(sessionID)
    childBindings.delete(sessionID)
  }
}

const subscribeEvents = async (ctx) => {
  const handler = (raw) => handleEventEnvelope(raw, ctx)
  if (typeof ctx?.event?.subscribe === "function") {
    const arg = Object.assign(handler, {
      types: ["session.created", "session.forked", "session.deleted"],
    })
    const result = await ctx.event.subscribe(arg)
    if (result && typeof result[Symbol.asyncIterator] === "function") {
      ;(async () => {
        for await (const ev of result) {
          try { await handler(ev) } catch {}
        }
      })().catch(() => {})
    }
  } else if (typeof ctx?.event?.hook === "function") {
    await ctx.event.hook("event", handler)
  }
}

export default {
  id: "opendeephole-file-write-hook",
  async setup(ctx) {
    const directory = pathText(ctx?.location?.directory)
      || pathText(ctx?.location?.project?.directory)
      || pathText(ctx?.directory)
      || pathText(ctx?.worktree)
      || process.cwd()

    await subscribeEvents(ctx)

    if (typeof ctx?.permission?.hook === "function") {
      await ctx.permission.hook("evaluate", async (event) => {
        if (!event || typeof event !== "object") return
        const sessionID = extractSessionID(event)
        const binding = sessionID ? await resolveBinding(sessionID, ctx) : null
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
        const outcomes = resources
          .map((res) => permissionRuleOutcome(binding, action, res, directory))
          .filter(Boolean)
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
        if (sessionID) {
          const binding = await resolveBinding(sessionID, ctx)
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
          return
        }
        // OpenCode 2.3.x omits sessionID from shell.create.before; tool.execute.before
        // and permission.evaluate already enforce session-scoped command bindings.
        const pendingBinding = lookupPendingShellBinding(event.command)
        event.env = applyPrependedPath(event.env || process.env, pendingBinding)
      })
    }

    if (typeof ctx?.tool?.hook === "function") {
      await ctx.tool.hook("execute.before", async (first, second) => {
        const sessionID = extractSessionID(first, second)
        const binding = await resolveBinding(sessionID, ctx)
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
        rememberPendingShellBinding(canonical, binding)
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
        const binding = await resolveBinding(sessionID, ctx)

        if (["bash", "shell"].includes(tool)) {
          if (!binding) return
          const rawCmd = commandText(args)
          const canonical = boundCommand(binding, rawCmd) || rawCmd
          if (!binding.allowed_commands.includes(canonical)) {
            if (status === "error") return
            throw unboundCommandError(binding, "after")
          }
          const outputObj = objectValue(resultTarget?.output)
          const outputMetadata = objectValue(resultTarget?.structured)
          const nestedMetadata = objectValue(originalMetadata.structured)
          const rawExitCode = originalMetadata.exitCode ?? originalMetadata.exit_code
            ?? originalMetadata.exit ?? originalMetadata.code
            ?? outputObj.exitCode ?? outputObj.exit
            ?? nestedMetadata.exit ?? outputMetadata.exit ?? resultTarget?.exit
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
        const files = writtenFiles(tool, args, originalMetadata, directory, resultTarget)
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

const pluginDirectory = path.dirname(fileURLToPath(import.meta.url))
const bindingRoot = path.basename(pluginDirectory) === ".opendeephole-plugins"
  ? pluginDirectory
  : path.dirname(pluginDirectory)
const bindingDirectory = path.join(bindingRoot, "knowledge-bindings")
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

const lookupParentFromSessionApi = async (ctx, sessionID) => {
  if (!sessionID || typeof ctx?.session?.get !== "function") return ""
  for (const arg of [{ sessionID }, { id: sessionID }, sessionID]) {
    try {
      const info = await ctx.session.get(arg)
      const data = objectValue(info?.data || info)
      const parentID = pathText(data.parentID) || pathText(data.parentId)
      if (parentID) {
        parents.set(sessionID, parentID)
        if (parents.size > 4096) parents.delete(parents.keys().next().value)
        return parentID
      }
      if (pathText(data.id)) return ""
    } catch {
      // Try next calling convention.
    }
  }
  return ""
}

const resolveBinding = async (sessionID, ctx = null) => {
  let current = String(sessionID || "")
  const visited = new Set()
  for (let depth = 0; current && depth < 32 && !visited.has(current); depth += 1) {
    visited.add(current)
    const binding = await readDirectBinding(current)
    if (binding) return binding
    let nextParent = String(parents.get(current) || "")
    if (!nextParent && ctx) {
      nextParent = await lookupParentFromSessionApi(ctx, current)
    }
    current = nextParent
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

const subscribeEvents = async (ctx) => {
  if (typeof ctx?.event?.subscribe === "function") {
    const arg = Object.assign(handleEventEnvelope, {
      types: ["session.created", "session.forked", "session.deleted"],
    })
    const result = await ctx.event.subscribe(arg)
    if (result && typeof result[Symbol.asyncIterator] === "function") {
      ;(async () => {
        for await (const ev of result) {
          try { await handleEventEnvelope(ev) } catch {}
        }
      })().catch(() => {})
    }
  } else if (typeof ctx?.event?.hook === "function") {
    await ctx.event.hook("event", handleEventEnvelope)
  }
}

export default {
  id: "opendeephole-knowledge-project-hook",
  async setup(ctx) {
    await subscribeEvents(ctx)
    if (typeof ctx?.tool?.hook === "function") {
      await ctx.tool.hook("execute.before", async (first, second) => {
        const sessionID = pathText(first?.sessionID)
          || pathText(first?.session?.id)
          || pathText(second?.sessionID)
        const binding = await resolveBinding(sessionID, ctx)
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
        return ("/api/info", "/api/health", "/global/health")
    return ("/global/health",)


def is_html_fallback_response(response: object) -> bool:
    """Return True when `opencode serve` fell through to its SPA HTML shell."""
    headers = getattr(response, "headers", None)
    content_type = ""
    if hasattr(headers, "get"):
        content_type = str(headers.get("content-type", "") or "").lower()
    return "text/html" in content_type


def is_route_miss_response(response: object) -> bool:
    """Return True when an HTTP response indicates an unmatched API route.

    OpenCode 2.x `serve` mounts a web UI catch-all that returns HTTP 200 with
    `text/html` on unknown GET paths instead of HTTP 404.
    """
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code in {404, 405}:
        return True
    return is_html_fallback_response(response)


def _is_valid_v2_server_info(payload: dict[str, Any], version: str) -> bool:
    """Check whether a JSON object matches OpenCode 2.x `ServerInfo` (`/api/info`)."""
    if version:
        return True
    pid = payload.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool):
        return True
    if isinstance(payload.get("urls"), list):
        return True
    if isinstance(payload.get("paths"), dict):
        return True
    return False


def parse_health_response(
    response: httpx.Response,
    *,
    opencode_version: str = OPENCODE_V1,
) -> tuple[bool, str, str]:
    """Validate an OpenCode health/info HTTP response, rejecting HTML fallbacks.

    Supports both:
    - `{healthy: true, version?: "..."}` (`/global/health`, `/api/health`)
    - OpenCode 2.x `ServerInfo` `{version: "2.x.y", pid: ..., ...}` (`GET /api/info`)

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
    if "healthy" in payload:
        return False, version, f"healthy={payload.get('healthy')!r}，预期为 true"
    if (
        normalize_opencode_version(opencode_version) == OPENCODE_V2
        and _is_valid_v2_server_info(payload, version)
    ):
        return True, version, ""
    return False, version, f"healthy={payload.get('healthy')!r}，预期为 true"


_PATH_PARAM_RE = re.compile(r"(?:\{[^/{}]+\}|:[A-Za-z0-9_]+)")


def _canonical_route_pattern(template: str) -> str:
    return _PATH_PARAM_RE.sub("{*}", str(template or "").strip())


def _fill_route_param(template: str, value: str) -> str:
    return _PATH_PARAM_RE.sub(value, template, count=1)


@dataclass(frozen=True)
class V2OpenApiSpec:
    """Parsed OpenAPI 3.x document from `/doc` or `/api/doc` on OpenCode 2.x."""

    paths: frozenset[str] = field(default_factory=frozenset)
    raw_spec: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def match_route(self, method: str | None, *templates: str) -> str | None:
        raw_paths = self.raw_spec.get("paths") if isinstance(self.raw_spec, dict) else None
        if not self.paths:
            return None
        wanted_method = str(method or "").strip().lower()
        canonical_map: dict[str, list[str]] = {}
        for existing in self.paths:
            canonical_map.setdefault(_canonical_route_pattern(existing), []).append(existing)

        for template in templates:
            candidates = (
                [template]
                if template in self.paths
                else canonical_map.get(_canonical_route_pattern(template), [])
            )
            for matched in candidates:
                if not wanted_method or not isinstance(raw_paths, dict):
                    return matched
                item = raw_paths.get(matched)
                # Empty `{}` path objects (used in lightweight test specs) match any method;
                # populated OpenAPI path items must expose the requested HTTP verb.
                if not isinstance(item, dict) or not item or wanted_method in item:
                    return matched
        return None

    def request_schema(self, method: str, *templates: str) -> dict[str, Any] | None:
        raw_paths = self.raw_spec.get("paths") if isinstance(self.raw_spec, dict) else None
        if not isinstance(raw_paths, dict):
            return None
        matched = self.match_route(method, *templates)
        if not matched:
            return None
        item = raw_paths.get(matched)
        if not isinstance(item, dict):
            return None
        op = item.get(method.lower())
        if not isinstance(op, dict):
            return None
        req_body = self._deref(op.get("requestBody"))
        if not isinstance(req_body, dict):
            return None
        content = req_body.get("content")
        if not isinstance(content, dict):
            return None
        for media_type in ("application/json", "*/*"):
            media = content.get(media_type)
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                return self._deref(media["schema"])
        for media in content.values():
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                return self._deref(media["schema"])
        return None

    def _deref(self, node: Any, depth: int = 0) -> Any:
        if depth > 12 or not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            target: Any = self.raw_spec
            for part in ref[2:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict) and key in target:
                    target = target[key]
                else:
                    return node
            return self._deref(target, depth + 1)
        return node

    def object_properties(self, schema: Any, depth: int = 0) -> dict[str, Any] | None:
        if depth > 8:
            return None
        resolved = self._deref(schema, depth)
        if not isinstance(resolved, dict):
            return None
        props = resolved.get("properties")
        if isinstance(props, dict):
            return {str(k): self._deref(v, depth + 1) for k, v in props.items()}
        merged: dict[str, Any] = {}
        found = False
        for keyword in ("allOf", "anyOf", "oneOf"):
            variants = resolved.get(keyword)
            if isinstance(variants, list):
                for variant in variants:
                    sub = self.object_properties(variant, depth + 1)
                    if sub is not None:
                        found = True
                        merged.update(sub)
        return merged if found else None

    def schema_accepts_type(self, schema: Any, expected_type: str, depth: int = 0) -> bool:
        if depth > 8:
            return False
        resolved = self._deref(schema, depth)
        if not isinstance(resolved, dict):
            return False
        raw_type = resolved.get("type")
        if raw_type == expected_type:
            return True
        if isinstance(raw_type, list) and expected_type in raw_type:
            return True
        if expected_type == "object" and isinstance(resolved.get("properties"), dict):
            return True
        if expected_type == "array" and isinstance(resolved.get("items"), dict):
            return True
        for keyword in ("anyOf", "oneOf", "allOf"):
            variants = resolved.get(keyword)
            if isinstance(variants, list) and any(
                self.schema_accepts_type(v, expected_type, depth + 1) for v in variants
            ):
                return True
        return False


def _fill_route_params(template: str, *values: str) -> str:
    rendered = template
    for value in values:
        rendered = _PATH_PARAM_RE.sub(value, rendered, count=1)
    return rendered


_V2_ENVELOPE_WRAPPER_KEYS = frozenset({
    "data",
    "cursor",
    "location",
    "next",
    "previous",
    "total",
    "meta",
})


def unwrap_v2_data(payload: Any) -> Any:
    """Unwrap OpenCode 2.3+ `{data: ..., cursor?, location?}` envelopes safely."""
    if not isinstance(payload, dict) or "data" not in payload:
        return payload
    data = payload.get("data")
    if data is None:
        return payload
    if any(key in payload for key in ("info", "role", "name", "error")):
        return payload
    if set(payload.keys()).issubset(_V2_ENVELOPE_WRAPPER_KEYS):
        return data
    if "id" not in payload and "type" not in payload and isinstance(data, (dict, list)):
        return data
    return payload


def normalize_v2_error(error: Any) -> Any:
    """Normalize OpenCode 2.3 `{type, message, status, response}` errors to `{name, message, data}`."""
    if not isinstance(error, dict):
        return error
    if "name" in error and ("data" in error or "type" not in error):
        return error
    err_type = str(error.get("type") or "").strip()
    message = str(error.get("message") or "").strip()
    status = error.get("status")
    response_obj = error.get("response") if isinstance(error.get("response"), dict) else {}
    resp_body = response_obj.get("body")
    type_name_map = {
        "api": "APIError",
        "auth": "ProviderAuthError",
        "context_overflow": "ContextOverflowError",
        "context-overflow": "ContextOverflowError",
        "aborted": "MessageAbortedError",
        "interrupted": "MessageAbortedError",
        "output_length": "MessageOutputLengthError",
        "output-length": "MessageOutputLengthError",
        "structured_output": "StructuredOutputError",
        "structured-output": "StructuredOutputError",
        "content_filter": "ContentFilterError",
        "content-filter": "ContentFilterError",
    }
    name = str(
        error.get("name")
        or type_name_map.get(err_type.lower())
        or (err_type if err_type else "UnknownError")
    )
    data: dict[str, Any] = {}
    if isinstance(error.get("data"), dict):
        data.update(error["data"])
    if message and "message" not in data:
        data["message"] = message
    if status is not None and "statusCode" not in data:
        data["statusCode"] = status
    if resp_body is not None and "responseBody" not in data:
        data["responseBody"] = resp_body
    if error.get("retryAfterMs") is not None and "retryAfterMs" not in data:
        data["retryAfterMs"] = error["retryAfterMs"]
    normalized: dict[str, Any] = {
        "name": name,
        "message": message or str(data.get("message") or ""),
    }
    if data:
        normalized["data"] = data
    if err_type:
        normalized["type"] = err_type
    return normalized


def _relative_resource_for_directory(resource: str, directory: Path | str | None) -> str | None:
    """Return a directory-relative pattern when `resource` lies under `directory`."""
    if not directory or not resource or resource == "*":
        return None
    dir_str = str(directory).strip()
    if not dir_str:
        return None
    dir_posix = dir_str.replace("\\", "/").rstrip("/")
    res_posix = resource.replace("\\", "/")
    if not dir_posix:
        return None
    # Match case-insensitively on Windows drive paths (e.g. C:/...) and exact on POSIX.
    is_win = len(dir_posix) >= 2 and dir_posix[1] == ":"
    cmp_dir = dir_posix.lower() if is_win else dir_posix
    cmp_res = res_posix.lower() if is_win else res_posix
    if cmp_res == cmp_dir:
        return "*"
    prefix = f"{cmp_dir}/"
    if cmp_res.startswith(prefix):
        rel = res_posix[len(dir_posix) + 1:].lstrip("/")
        return rel or "*"
    return None


def translate_v1_permissions_to_v2(
    rules: Any,
    *,
    directory: Path | str | None = None,
) -> list[dict[str, str]]:
    """Translate V1 `{permission, pattern, action}` rules into V2.3 `{action, resource, effect}`."""
    if not isinstance(rules, list):
        return []
    translated: list[dict[str, str]] = []
    seen_entries: set[tuple[str, str, str]] = set()

    def _append(action: str, resource: str, effect: str) -> None:
        entry = {"action": action, "resource": resource, "effect": effect}
        key = (action, resource, effect)
        # Preserve override order if the same (action, resource) reappears with a different effect,
        # while avoiding duplicate identical rules right next to each other.
        if translated and translated[-1] == entry:
            return
        if key in seen_entries and not any(
            existing["action"] == action and existing["resource"] == resource and existing["effect"] != effect
            for existing in translated
        ):
            return
        seen_entries.add(key)
        translated.append(entry)

    for raw in rules:
        if not isinstance(raw, dict):
            continue
        if "effect" in raw and "resource" in raw and "permission" not in raw:
            action = str(raw.get("action") or "*").strip() or "*"
            if action == "bash":
                action = "shell"
            resource = str(raw.get("resource") if raw.get("resource") is not None else "*")
            effect = str(raw.get("effect") or "deny").strip().lower()
        else:
            perm = str(raw.get("permission") or raw.get("action") or "*").strip() or "*"
            if perm == "bash":
                action = "shell"
            elif perm in {"write", "apply_patch", "patch"}:
                action = "edit"
            else:
                action = perm
            resource = str(raw.get("pattern") if raw.get("pattern") is not None else "*")
            effect = str(raw.get("action") or raw.get("effect") or "deny").strip().lower()
        if effect not in {"allow", "deny", "ask"}:
            effect = "deny"
        _append(action, resource, effect)
        if directory is not None and action in {"edit", "read", "external_directory"}:
            rel = _relative_resource_for_directory(resource, directory)
            if rel and rel != resource:
                _append(action, rel, effect)
    return translated


def translate_v2_permissions_to_v1(rules: Any) -> list[dict[str, str]]:
    """Translate V2.3 `{action, resource, effect}` rules back into V1 `{permission, pattern, action}`."""
    if not isinstance(rules, list):
        return []
    translated: list[dict[str, str]] = []
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        if "permission" in raw and "pattern" in raw and "effect" not in raw:
            translated.append({
                "permission": str(raw.get("permission") or "*"),
                "pattern": str(raw.get("pattern") if raw.get("pattern") is not None else "*"),
                "action": str(raw.get("action") or "deny"),
            })
            continue
        perm = str(raw.get("action") or "*").strip() or "*"
        pattern = str(raw.get("resource") if raw.get("resource") is not None else "*")
        effect = str(raw.get("effect") or "deny").strip().lower()
        if effect not in {"allow", "deny", "ask"}:
            effect = "deny"
        translated.append({
            "permission": perm,
            "pattern": pattern,
            "action": effect,
        })
    return translated


def build_v2_mcp_put_config(
    config: dict[str, Any],
    *,
    disabled: bool | None = None,
) -> dict[str, Any]:
    """Translate an OpenDeepHole MCP config dict into strict OpenCode 2.3 PUT schema."""
    mcp_type = str(config.get("type") or "").strip().lower()
    if not mcp_type:
        mcp_type = "remote" if config.get("url") else "local"
    result: dict[str, Any] = {"type": mcp_type}
    if mcp_type == "remote":
        if config.get("url"):
            result["url"] = str(config["url"])
        if isinstance(config.get("headers"), dict):
            result["headers"] = {str(k): str(v) for k, v in config["headers"].items()}
        if "oauth" in config and (config["oauth"] is False or isinstance(config["oauth"], dict)):
            result["oauth"] = config["oauth"]
    else:
        command = config.get("command")
        if isinstance(command, list):
            result["command"] = [str(item) for item in command]
        elif isinstance(command, str) and command.strip():
            result["command"] = [command.strip()]
        if isinstance(config.get("cwd"), str) and config["cwd"].strip():
            result["cwd"] = config["cwd"].strip()
        if isinstance(config.get("environment"), dict):
            result["environment"] = {str(k): str(v) for k, v in config["environment"].items()}

    if disabled is not None:
        result["disabled"] = bool(disabled)
    elif "disabled" in config:
        result["disabled"] = bool(config["disabled"])
    elif "enabled" in config:
        result["disabled"] = not bool(config["enabled"])

    raw_timeout = config.get("timeout")
    if isinstance(raw_timeout, dict):
        timeout_obj: dict[str, int] = {}
        for key in ("startup", "catalog", "execution"):
            val = raw_timeout.get(key)
            if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                timeout_obj[key] = int(val)
        if timeout_obj:
            result["timeout"] = timeout_obj
    elif isinstance(raw_timeout, (int, float)) and not isinstance(raw_timeout, bool) and raw_timeout > 0:
        ms = int(raw_timeout)
        result["timeout"] = {"startup": ms, "catalog": ms, "execution": ms}

    if isinstance(config.get("codemode"), bool):
        result["codemode"] = config["codemode"]
    if isinstance(config.get("protocol"), str) and config["protocol"] in {"legacy", "auto", "2026-07-28"}:
        result["protocol"] = config["protocol"]
    if isinstance(config.get("pool"), bool):
        result["pool"] = config["pool"]
    return result


def extract_mcp_status_map_v2(value: Any) -> dict[str, Any]:
    """Normalize MCP status payloads across 1.x map and 2.3 `{location, data: [{name, status}]}` shapes."""
    unwrapped = unwrap_v2_data(value)
    if isinstance(unwrapped, list):
        mapped: dict[str, Any] = {}
        for item in unwrapped:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            status = item.get("status")
            if isinstance(status, dict):
                mapped[name] = status
            elif isinstance(status, str):
                mapped[name] = {"status": status}
        return mapped
    if isinstance(unwrapped, dict):
        nested = unwrapped.get("status")
        if isinstance(nested, dict):
            return nested
        return unwrapped
    return {}


def extract_config_providers_v2(config_data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Extract provider definitions from OpenCode 2.x `GET /api/config` dict or document list."""
    merged: list[dict[str, Any]] = []
    any_valid = False
    documents: list[dict[str, Any]] = []
    if isinstance(config_data, dict):
        documents.append(config_data)
    elif isinstance(config_data, list):
        for item in config_data:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "document" and isinstance(item.get("info"), dict):
                documents.append(item["info"])
            else:
                documents.append(item)
    for doc in documents:
        for cfg_key in ("provider", "providers"):
            raw_prov = doc.get(cfg_key)
            if isinstance(raw_prov, (dict, list)):
                extracted, valid = extract_provider_list_v2({"providers": raw_prov})
                if valid:
                    any_valid = True
                    merged.extend(extracted)
    if any_valid:
        return merged, True
    return extract_provider_list_v2(config_data)


async def discover_v2_openapi_spec(client: httpx.AsyncClient) -> V2OpenApiSpec:
    """Fetch `/openapi.json`, `/api/openapi.json`, `/doc`, or `/api/doc` once to discover OpenCode 2.x routes."""
    for doc_path in ("/openapi.json", "/api/openapi.json", "/doc", "/api/doc"):
        try:
            response = await client.get(doc_path, timeout=2.0)
            if response.status_code != 200 or is_html_fallback_response(response):
                continue
            spec = response.json()
            paths = spec.get("paths") if isinstance(spec, dict) else None
            if isinstance(paths, dict) and paths:
                return V2OpenApiSpec(
                    paths=frozenset(str(key) for key in paths),
                    raw_spec=spec,
                )
        except Exception:
            continue
    return V2OpenApiSpec()


async def discover_v2_openapi_paths(client: httpx.AsyncClient) -> frozenset[str]:
    """Fetch OpenAPI spec once to discover supported OpenAPI route templates."""
    return (await discover_v2_openapi_spec(client)).paths


def v2_route_supported(discovered_paths: frozenset[str], *templates: str) -> str | None:
    """Return the first template present in discovered OpenAPI paths, if any."""
    if not discovered_paths:
        return None
    canonical_map: dict[str, str] = {}
    for existing in discovered_paths:
        canonical_map.setdefault(_canonical_route_pattern(existing), existing)
    for template in templates:
        if template in discovered_paths:
            return template
        matched = canonical_map.get(_canonical_route_pattern(template))
        if matched is not None:
            return matched
    return None


def extract_model_list_v2(data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Parse OpenCode 2.x `GET /api/model` catalog payloads into normalized model dicts."""
    items: Any = data
    if isinstance(data, dict):
        for key in ("models", "items", "data", "all"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    if not isinstance(items, list):
        return [], False
    if items and not any(isinstance(item, dict) for item in items):
        return [], False

    parsed_all: list[tuple[dict[str, Any], bool]] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        provider_id = str(
            raw.get("providerID")
            or raw.get("provider_id")
            or raw.get("provider")
            or ""
        ).strip()
        local_id = str(raw.get("modelID") or raw.get("model_id") or raw.get("id") or "").strip()
        if not provider_id and "/" in local_id:
            provider_id, local_id = local_id.split("/", 1)
            provider_id = provider_id.strip()
            local_id = local_id.strip()
        elif provider_id and local_id.startswith(f"{provider_id}/"):
            local_id = local_id[len(provider_id) + 1:].strip()
        if not provider_id or not local_id:
            continue
        status_text = str(raw.get("status") or "").strip().lower()
        explicitly_disabled = raw.get("enabled") is False or status_text in {"disabled", "inactive"}
        limit = raw.get("limit") if isinstance(raw.get("limit"), dict) else {}
        normalized_entry = {
            "id": f"{provider_id}/{local_id}",
            "provider_id": provider_id,
            "model_id": local_id,
            "name": str(raw.get("name") or raw.get("label") or ""),
            "limit": limit,
        }
        parsed_all.append((normalized_entry, not explicitly_disabled))

    enabled_entries = [entry for entry, is_enabled in parsed_all if is_enabled]
    if enabled_entries:
        return enabled_entries, True
    return [entry for entry, _ in parsed_all], True


def extract_provider_list_v2(data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Parse provider payloads across OpenCode 1.x and 2.x shapes.

    Note: OpenCode 2.3 `GET /api/provider` may return an array of provider ID
    strings (`["opencode", "openai"]`) without embedded model definitions; in
    that case `valid=False` so callers continue to `/api/model` or `/api/config`.
    """
    if isinstance(data, list):
        dicts = [item for item in data if isinstance(item, dict)]
        if data and not dicts:
            return [], False
        return dicts, True
    if not isinstance(data, dict):
        return [], False
    for key in ("all", "providers", "provider", "items", "data"):
        raw = data.get(key)
        if isinstance(raw, list):
            dicts = [item for item in raw if isinstance(item, dict)]
            if raw and not dicts:
                continue
            return dicts, True
        if isinstance(raw, dict):
            entries: list[dict[str, Any]] = []
            for provider_id, value in raw.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("id", str(provider_id))
                    entries.append(item)
            return entries, True
    return [], False


def _v2_tool_content_to_output(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    texts: list[str] = []
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str) and item["text"]:
            texts.append(item["text"])
        elif isinstance(item, str) and item:
            texts.append(item)
    return "\n".join(texts)


def _normalize_v2_content_parts(content: Any, *, message_id: str = "") -> list[dict[str, Any]]:
    if not isinstance(content, list):
        return []
    parts: list[dict[str, Any]] = []
    for index, item in enumerate(content):
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "").strip()
        if item_type in {"text", "reasoning"}:
            part: dict[str, Any] = {
                "id": str(item.get("id") or f"{message_id or 'part'}:{item_type}:{index}"),
                "type": item_type,
                "text": str(item.get("text") or ""),
            }
            if message_id:
                part["messageID"] = message_id
            parts.append(part)
        elif item_type == "tool":
            call_id = str(item.get("id") or item.get("callID") or f"call:{index}")
            tool_name = str(item.get("name") or item.get("tool") or "")
            raw_state = item.get("state") if isinstance(item.get("state"), dict) else {}
            raw_status = str(raw_state.get("status") or "").strip().lower()
            status = "pending" if raw_status == "streaming" else (raw_status or "pending")
            norm_state: dict[str, Any] = {
                "status": status,
                "input": raw_state.get("input") if isinstance(raw_state.get("input"), dict) else {},
            }
            if isinstance(raw_state.get("metadata"), dict):
                norm_state["metadata"] = dict(raw_state["metadata"])
            if isinstance(raw_state.get("output"), str):
                norm_state["output"] = raw_state["output"]
            elif raw_state.get("content") is not None:
                norm_state["output"] = _v2_tool_content_to_output(raw_state.get("content"))
            if raw_state.get("error") is not None:
                norm_state["error"] = normalize_v2_error(raw_state.get("error"))
            if isinstance(item.get("time"), dict):
                norm_state["time"] = dict(item["time"])
            tool_part: dict[str, Any] = {
                "id": call_id,
                "callID": call_id,
                "type": "tool",
                "tool": tool_name,
                "state": norm_state,
            }
            if message_id:
                tool_part["messageID"] = message_id
            parts.append(tool_part)
        else:
            parts.append(dict(item))
    return parts


def normalize_message_envelope(raw: Any, fallback_session_id: str = "") -> dict[str, Any] | None:
    """Normalize 1.x `{info, parts}`, flat `{id, role, parts}`, and 2.3 `{id, type, content}` messages."""
    unwrapped = unwrap_v2_data(raw)
    if not isinstance(unwrapped, dict):
        return None
    if isinstance(unwrapped.get("info"), dict):
        return unwrapped
    role = unwrapped.get("role")
    if isinstance(role, str) and role.strip():
        info = {
            key: value
            for key, value in unwrapped.items()
            if key != "parts"
        }
        if fallback_session_id and not info.get("sessionID"):
            info["sessionID"] = fallback_session_id
        if info.get("error") is not None:
            info["error"] = normalize_v2_error(info["error"])
        parts = unwrapped.get("parts")
        return {
            "info": info,
            "parts": parts if isinstance(parts, list) else [],
        }

    msg_type = str(unwrapped.get("type") or "").strip().lower()
    if not msg_type:
        return None
    msg_id = str(unwrapped.get("id") or "").strip()
    session_id = str(unwrapped.get("sessionID") or fallback_session_id or "").strip()

    if msg_type == "assistant":
        info = {
            "id": msg_id,
            "sessionID": session_id,
            "role": "assistant",
            "type": "assistant",
        }
        if unwrapped.get("agent"):
            info["agent"] = str(unwrapped["agent"])
        model_obj = unwrapped.get("model")
        if isinstance(model_obj, dict):
            provider_id = str(model_obj.get("providerID") or "").strip()
            model_id = str(model_obj.get("id") or model_obj.get("modelID") or "").strip()
            if provider_id:
                info["providerID"] = provider_id
            if model_id:
                info["modelID"] = model_id
            info["model"] = dict(model_obj)
        for field_name in ("time", "finish", "rawFinish", "cost", "tokens", "retry", "snapshot", "metadata"):
            if field_name in unwrapped and unwrapped[field_name] is not None:
                info[field_name] = unwrapped[field_name]
        if unwrapped.get("error") is not None:
            info["error"] = normalize_v2_error(unwrapped["error"])
        parts = _normalize_v2_content_parts(unwrapped.get("content"), message_id=msg_id)
        return {"info": info, "parts": parts}

    if msg_type == "user":
        info = {
            "id": msg_id,
            "sessionID": session_id,
            "role": "user",
            "type": "user",
        }
        for field_name in ("time", "metadata"):
            if field_name in unwrapped and unwrapped[field_name] is not None:
                info[field_name] = unwrapped[field_name]
        text = str(unwrapped.get("text") or "")
        parts = [{"type": "text", "text": text, **({"messageID": msg_id} if msg_id else {})}] if text else []
        return {"info": info, "parts": parts}

    if msg_type == "idle":
        info = {
            "id": msg_id,
            "sessionID": session_id,
            "role": "idle",
            "type": "idle",
            "outcome": str(unwrapped.get("outcome") or "").strip().lower(),
        }
        if unwrapped.get("time") is not None:
            info["time"] = unwrapped["time"]
        if unwrapped.get("error") is not None:
            info["error"] = normalize_v2_error(unwrapped["error"])
        return {"info": info, "parts": []}

    if msg_type in {
        "system",
        "synthetic",
        "skill",
        "shell",
        "agent-switched",
        "model-switched",
        "location-switched",
        "compaction",
    }:
        info = {
            "id": msg_id,
            "sessionID": session_id,
            "role": "system" if msg_type in {"system", "synthetic"} else msg_type,
            "type": msg_type,
        }
        if unwrapped.get("time") is not None:
            info["time"] = unwrapped["time"]
        if unwrapped.get("error") is not None:
            info["error"] = normalize_v2_error(unwrapped["error"])
        text = str(unwrapped.get("text") or "")
        parts = [{"type": "text", "text": text, **({"messageID": msg_id} if msg_id else {})}] if text else []
        return {"info": info, "parts": parts}

    return None


def _cursor_indicates_desc(cursor: Any) -> bool:
    if not isinstance(cursor, dict):
        return False
    for key in ("previous", "next"):
        token = cursor.get(key)
        if not isinstance(token, str) or not token.strip():
            continue
        padded = token.strip() + "=" * (-len(token.strip()) % 4)
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                decoded = json.loads(decoder(padded.encode("ascii")).decode("utf-8"))
                if isinstance(decoded, dict):
                    order = str(decoded.get("order") or "").strip().lower()
                    if order == "desc":
                        return True
                    if order == "asc":
                        return False
            except Exception:
                continue
    return False


def _created_timestamp(message: dict[str, Any]) -> float | None:
    info = message.get("info")
    if not isinstance(info, dict):
        return None
    msg_time = info.get("time")
    if isinstance(msg_time, dict):
        created = msg_time.get("created")
        if isinstance(created, (int, float)) and not isinstance(created, bool):
            return float(created)
    return None


def normalize_message_list(raw: Any, fallback_session_id: str = "") -> list[dict[str, Any]] | None:
    """Normalize a `/message` response into chronological oldest-to-newest `{info, parts}` items."""
    items: Any = raw
    is_desc = False
    if isinstance(raw, dict):
        is_desc = _cursor_indicates_desc(raw.get("cursor"))
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
    if not is_desc and len(normalized) >= 2:
        first_ts = _created_timestamp(normalized[0])
        last_ts = _created_timestamp(normalized[-1])
        if first_ts is not None and last_ts is not None and first_ts > last_ts:
            is_desc = True
    if is_desc:
        normalized.reverse()
    return normalized


async def auto_reject_v2_interactive_event(
    client: httpx.AsyncClient,
    *,
    event_type: str,
    props: dict[str, Any],
    session_id: str,
    params: dict[str, str],
    headers: dict[str, str],
    openapi_spec: V2OpenApiSpec | None = None,
) -> None:
    """Reject unexpected interactive prompts in OpenCode 2.x so unattended scans never hang."""
    request_obj = props.get("request") if isinstance(props.get("request"), dict) else {}
    form_obj = props.get("form") if isinstance(props.get("form"), dict) else {}
    request_id = str(
        props.get("id")
        or props.get("requestID")
        or request_obj.get("id")
        or form_obj.get("id")
        or ""
    ).strip()
    if not session_id or not request_id:
        return
    quoted_sid = quote(session_id, safe="")
    quoted_rid = quote(request_id, safe="")
    candidates: list[tuple[str, str, dict[str, Any] | None]] = []
    if event_type in {"permission.asked", "permission.ask"}:
        perm_path = f"/api/session/{quoted_sid}/permission/{quoted_rid}/reply"
        perm_schema = (
            openapi_spec.request_schema(
                "post",
                "/api/session/{sessionID}/permission/{requestID}/reply",
                "/api/session/{id}/permission/{requestID}/reply",
            )
            if openapi_spec is not None
            else None
        )
        perm_props = (
            openapi_spec.object_properties(perm_schema)
            if (openapi_spec is not None and perm_schema is not None)
            else None
        )
        if perm_props is not None and "decision" in perm_props and "effect" not in perm_props:
            candidates.append(("POST", perm_path, {"decision": "reject"}))
        else:
            candidates.extend([
                ("POST", perm_path, {"decision": "reject", "reply": "reject", "effect": "deny", "action": "deny"}),
                ("POST", perm_path, {"decision": "reject"}),
                ("POST", f"/api/permission/{quoted_rid}/reply", {"decision": "reject", "reply": "reject", "effect": "deny"}),
            ])
    elif event_type in {"question.asked", "question.ask"}:
        candidates.extend([
            ("POST", f"/api/question/{quoted_rid}/reject", {}),
            ("POST", f"/api/session/{quoted_sid}/question/{quoted_rid}/reject", {}),
        ])
    elif event_type in {"form.created", "session.form.created"}:
        candidates.extend([
            ("DELETE", f"/api/session/{quoted_sid}/form/{quoted_rid}", None),
            ("POST", f"/api/session/{quoted_sid}/form/{quoted_rid}/cancel", {}),
            ("POST", f"/api/form/{quoted_rid}/cancel", {}),
        ])
    for method, path, body in candidates:
        try:
            if method == "DELETE":
                resp = await client.delete(path, params=params, headers=headers, timeout=2.0)
            else:
                resp = await client.post(path, params=params, headers=headers, json=body, timeout=2.0)
            if resp.status_code < 400 and not is_html_fallback_response(resp):
                return
        except Exception:
            continue


def _format_v2_model_value(
    model_spec: Any,
    model_schema: Any,
    openapi_spec: V2OpenApiSpec | None,
) -> Any:
    if not isinstance(model_spec, dict):
        return model_spec
    provider_id = str(model_spec.get("providerID") or "").strip()
    model_id = str(model_spec.get("modelID") or model_spec.get("id") or "").strip()
    if openapi_spec is not None and model_schema is not None:
        if openapi_spec.schema_accepts_type(model_schema, "string") and not openapi_spec.schema_accepts_type(model_schema, "object"):
            return f"{provider_id}/{model_id}" if provider_id else model_id
        props = openapi_spec.object_properties(model_schema)
        if props is not None:
            if "id" in props and "modelID" not in props:
                return {"providerID": provider_id, "id": model_id}
            if "modelID" in props:
                return {"providerID": provider_id, "modelID": model_id}
    return {"providerID": provider_id, "modelID": model_id}


def build_v2_session_create_bodies(
    *,
    title: str,
    directory: Path | str | None,
    permissions: Any = None,
    model_spec: dict[str, str] | None = None,
    agent: str | None = None,
    openapi_spec: V2OpenApiSpec | None = None,
) -> list[dict[str, Any]]:
    """Build ordered `POST /api/session` candidate bodies respecting Effect Schema validation."""
    clean_title = str(title or "").strip() or "DeepHole 2.0 task"
    dir_str = str(directory) if directory is not None else ""
    schema = openapi_spec.request_schema("post", "/api/session") if openapi_spec is not None else None
    props = openapi_spec.object_properties(schema) if (openapi_spec is not None and schema is not None) else None

    candidates: list[dict[str, Any]] = []
    if props is not None:
        guided: dict[str, Any] = {}
        if "title" in props or not props:
            guided["title"] = clean_title
        if dir_str:
            if "location" in props:
                guided["location"] = {"directory": dir_str}
            elif "directory" in props:
                guided["directory"] = dir_str
        if permissions is not None:
            if "permissions" in props:
                guided["permissions"] = translate_v1_permissions_to_v2(permissions, directory=directory)
            elif "permission" in props:
                guided["permission"] = permissions
        if isinstance(model_spec, dict) and "model" in props:
            guided["model"] = _format_v2_model_value(model_spec, props.get("model"), openapi_spec)
        if agent and "agent" in props:
            guided["agent"] = str(agent)
        candidates.append(guided)
        if dir_str and "location" in props:
            fallback_loc = {"title": clean_title, "location": {"directory": dir_str}}
            if fallback_loc not in candidates:
                candidates.append(fallback_loc)
    else:
        # Without an OpenAPI request schema, prefer strict V2-safe payloads before legacy fields.
        if dir_str:
            v23_like: dict[str, Any] = {"title": clean_title, "location": {"directory": dir_str}}
            if permissions is not None:
                v23_like["permissions"] = translate_v1_permissions_to_v2(permissions, directory=directory)
            candidates.append(v23_like)
            if permissions is not None:
                candidates.append({"title": clean_title, "location": {"directory": dir_str}})
        if dir_str or permissions is not None:
            legacy_like: dict[str, Any] = {"title": clean_title}
            if dir_str:
                legacy_like["directory"] = dir_str
            if permissions is not None:
                legacy_like["permission"] = permissions
            if legacy_like not in candidates:
                candidates.append(legacy_like)

    minimal = {"title": clean_title}
    if minimal not in candidates:
        candidates.append(minimal)
    return candidates


async def create_v2_session(
    client: httpx.AsyncClient,
    *,
    session_base: str,
    title: str,
    directory: Path | str | None,
    permissions: Any,
    model_spec: dict[str, str] | None,
    params: dict[str, str],
    headers: dict[str, str],
    agent: str | None = None,
    openapi_spec: V2OpenApiSpec | None = None,
) -> httpx.Response:
    """Create a V2 session, retrying with stricter minimal bodies if Effect Schema returns 400/422."""
    bodies = build_v2_session_create_bodies(
        title=title,
        directory=directory,
        permissions=permissions,
        model_spec=model_spec,
        agent=agent,
        openapi_spec=openapi_spec,
    )
    response: httpx.Response | None = None
    for idx, body in enumerate(bodies):
        response = await client.post(
            session_base,
            params=params,
            headers=headers,
            json=body,
        )
        if response.status_code not in {400, 422} or idx == len(bodies) - 1:
            break
    assert response is not None
    return response


def _build_v2_prompt_bodies_for_route(
    *,
    route_template: str,
    prompt: str,
    payload: dict[str, Any],
    openapi_spec: V2OpenApiSpec | None,
    system_injected_separately: bool = False,
) -> list[dict[str, Any]]:
    """Build ordered JSON bodies for a V2 prompt/message endpoint."""
    system_text = "" if system_injected_separately else str(payload.get("system") or "").strip()
    effective_prompt = f"{system_text}\n\n{prompt}" if system_text else prompt
    effective_parts = [{"type": "text", "text": effective_prompt}]
    raw_parts = payload.get("parts") if isinstance(payload.get("parts"), list) else [{"type": "text", "text": prompt}]

    schema = (
        openapi_spec.request_schema("post", route_template)
        if openapi_spec is not None
        else None
    )
    props = (
        openapi_spec.object_properties(schema)
        if (openapi_spec is not None and schema is not None)
        else None
    )

    bodies: list[dict[str, Any]] = []
    if props is not None:
        guided: dict[str, Any] = {}
        has_system_prop = "system" in props
        chosen_text = prompt if (has_system_prop or system_injected_separately) else effective_prompt
        chosen_parts = raw_parts if (has_system_prop or system_injected_separately) else effective_parts
        if has_system_prop and system_text:
            guided["system"] = system_text
        if "agent" in props and payload.get("agent"):
            guided["agent"] = payload["agent"]
        if "model" in props and payload.get("model") is not None:
            guided["model"] = _format_v2_model_value(payload["model"], props.get("model"), openapi_spec)
        if "format" in props and payload.get("format") is not None:
            guided["format"] = payload["format"]

        if "parts" in props:
            guided["parts"] = chosen_parts
        elif "prompt" in props:
            prompt_schema = props.get("prompt")
            if openapi_spec is not None and openapi_spec.schema_accepts_type(prompt_schema, "array"):
                guided["prompt"] = chosen_parts
            elif (
                openapi_spec is not None
                and openapi_spec.schema_accepts_type(prompt_schema, "object")
                and not openapi_spec.schema_accepts_type(prompt_schema, "string")
            ):
                guided["prompt"] = {"parts": chosen_parts}
            else:
                guided["prompt"] = chosen_text
        elif "text" in props:
            guided["text"] = chosen_text
        else:
            guided["parts"] = chosen_parts
        bodies.append(guided)

    is_prompt_endpoint = route_template.endswith("/prompt") or route_template.endswith("/prompt_async")
    if is_prompt_endpoint:
        # When no OpenAPI request schema is exposed (e.g. lightweight mock servers),
        # keep `{**payload, "prompt": prompt}` first, then fall back to strict Effect
        # Schema variants on HTTP 400/422.
        if props is None:
            bodies.append({**payload, "prompt": prompt})
        strict_parts: dict[str, Any] = {"parts": effective_parts}
        if payload.get("agent"):
            strict_parts["agent"] = payload["agent"]
        if isinstance(payload.get("model"), dict):
            strict_parts["model"] = payload["model"]
        if payload.get("format") is not None:
            strict_parts["format"] = payload["format"]
        for candidate in (
            {"text": effective_prompt},
            strict_parts,
            {"parts": effective_parts},
            {"prompt": effective_parts},
            {"prompt": effective_prompt},
        ):
            if candidate not in bodies:
                bodies.append(candidate)
    else:
        if payload not in bodies:
            bodies.append(payload)
        minimal_parts = {"parts": effective_parts}
        if minimal_parts not in bodies:
            bodies.append(minimal_parts)
    return bodies


def _step_finish_reason(message: dict[str, Any]) -> str:
    info = message.get("info")
    if isinstance(info, dict):
        finish = str(info.get("finish") or "").strip().lower()
        if finish:
            return finish
    parts = message.get("parts")
    if isinstance(parts, list):
        for part in reversed(parts):
            if isinstance(part, dict) and part.get("type") == "step-finish":
                reason = str(part.get("reason") or part.get("finish") or "stop").strip().lower()
                return reason or "stop"
    return ""


def _has_active_tool_parts(message: dict[str, Any]) -> bool:
    parts = message.get("parts")
    if not isinstance(parts, list):
        return False
    for part in parts:
        if not isinstance(part, dict) or part.get("type") != "tool":
            continue
        state = part.get("state")
        status = str(state.get("status") or "").strip().lower() if isinstance(state, dict) else ""
        if status in {"pending", "running"}:
            return True
    return False


def _session_snapshot_busy_state(raw_session: Any) -> tuple[bool, bool]:
    """Return `(is_busy, is_idle)` from a V2 `GET /api/session/{id}` response."""
    sess_data = unwrap_v2_data(raw_session)
    if not isinstance(sess_data, dict):
        return False, False
    status_val = sess_data.get("status")
    if status_val is not None:
        status_type = (
            str(status_val.get("type") or "")
            if isinstance(status_val, dict)
            else str(status_val or "")
        ).lower()
        if status_type in {"busy", "running", "retry"}:
            return True, False
        if status_type in {"idle", "error", "completed"}:
            return False, True
    time_obj = sess_data.get("time") if isinstance(sess_data.get("time"), dict) else {}
    busy_ts = time_obj.get("busy")
    idle_ts = time_obj.get("idle")
    if isinstance(busy_ts, (int, float)) and not isinstance(busy_ts, bool):
        if isinstance(idle_ts, (int, float)) and not isinstance(idle_ts, bool):
            if busy_ts > idle_ts:
                return True, False
            return False, True
        return True, False
    if isinstance(idle_ts, (int, float)) and not isinstance(idle_ts, bool):
        return False, True
    outcome = str(sess_data.get("outcome") or "").strip().lower()
    if outcome in {"succeeded", "failed", "interrupted"}:
        return False, True
    return False, False


async def submit_and_resolve_v2_prompt(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    prompt: str,
    payload: dict[str, Any],
    params: dict[str, str],
    headers: dict[str, str],
    discovered_paths: frozenset[str],
    openapi_spec: V2OpenApiSpec | None = None,
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
    - Asynchronous `/api/session/{id}/prompt` returning an immediate queue/user-message envelope
      while the assistant turn executes in the background and emits SSE events + `/message` records.
    """
    spec = openapi_spec if openapi_spec is not None else V2OpenApiSpec(paths=discovered_paths)
    quoted_sid = quote(session_id, safe="")
    sync_message_template = spec.match_route(
        "post",
        "/api/session/{sessionID}/message",
        "/api/session/:sessionID/message",
    )
    async_prompt_template = spec.match_route(
        "post",
        "/api/session/{sessionID}/prompt",
        "/api/session/:sessionID/prompt",
        "/api/session/{sessionID}/prompt_async",
        "/api/session/:sessionID/prompt_async",
    )
    model_route_template = spec.match_route(
        "post",
        "/api/session/{sessionID}/model",
        "/api/session/:sessionID/model",
    )
    model_spec = payload.get("model")
    if isinstance(model_spec, dict) and model_route_template is not None:
        model_schema = spec.request_schema("post", model_route_template)
        outer_props = (
            spec.object_properties(model_schema)
            if model_schema is not None
            else None
        )
        if outer_props is not None and "model" in outer_props:
            model_body: dict[str, Any] = {
                "model": _format_v2_model_value(model_spec, outer_props.get("model"), spec)
            }
        else:
            formatted_model = _format_v2_model_value(model_spec, model_schema, spec)
            model_body = (
                formatted_model
                if isinstance(formatted_model, dict)
                else {"model": formatted_model}
            )
        try:
            await client.post(
                _fill_route_param(model_route_template, quoted_sid),
                params=params,
                headers=headers,
                json=model_body,
                timeout=10.0,
            )
        except Exception:
            pass

    agent_route_template = spec.match_route(
        "post",
        "/api/session/{sessionID}/agent",
        "/api/session/:sessionID/agent",
    )
    agent_name = str(payload.get("agent") or "").strip()
    if agent_name and agent_route_template is not None:
        try:
            await client.post(
                _fill_route_param(agent_route_template, quoted_sid),
                params=params,
                headers=headers,
                json={"agent": agent_name},
                timeout=10.0,
            )
        except Exception:
            pass

    system_text = str(payload.get("system") or "").strip()
    system_injected_separately = False
    instructions_put_template = spec.match_route(
        "put",
        "/api/experimental/session/{sessionID}/instructions/entries/{key}",
        "/api/experimental/session/:sessionID/instructions/entries/:key",
    )
    if instructions_put_template is not None:
        inst_path = _fill_route_params(
            instructions_put_template,
            quoted_sid,
            "opendeephole_system",
        )
        if system_text:
            try:
                inst_resp = await client.put(
                    inst_path,
                    params=params,
                    headers=headers,
                    json={"value": system_text},
                    timeout=10.0,
                )
                if inst_resp.status_code < 400 and not is_html_fallback_response(inst_resp):
                    system_injected_separately = True
            except Exception:
                pass
        else:
            instructions_del_template = spec.match_route(
                "delete",
                "/api/experimental/session/{sessionID}/instructions/entries/{key}",
                "/api/experimental/session/:sessionID/instructions/entries/:key",
            )
            if instructions_del_template is not None:
                try:
                    await client.delete(
                        _fill_route_params(
                            instructions_del_template,
                            quoted_sid,
                            "opendeephole_system",
                        ),
                        params=params,
                        headers=headers,
                        timeout=5.0,
                    )
                except Exception:
                    pass

    if async_prompt_template and not sync_message_template:
        route_templates = [
            async_prompt_template,
            "/api/session/{sessionID}/message",
        ]
    elif sync_message_template and not async_prompt_template:
        route_templates = [
            sync_message_template,
            "/api/session/{sessionID}/prompt",
        ]
    else:
        route_templates = [
            async_prompt_template or "/api/session/{sessionID}/prompt",
            sync_message_template or "/api/session/{sessionID}/message",
            "/session/{sessionID}/message",
        ]

    response: httpx.Response | None = None
    used_path = ""
    for route_idx, route_template in enumerate(route_templates):
        route_path = _fill_route_param(route_template, quoted_sid)
        used_path = route_path
        bodies = _build_v2_prompt_bodies_for_route(
            route_template=route_template,
            prompt=prompt,
            payload=payload,
            openapi_spec=spec if spec.raw_spec else None,
            system_injected_separately=system_injected_separately,
        )
        for body_idx, body in enumerate(bodies):
            response = await client.post(
                route_path,
                params=params,
                headers=headers,
                json=body,
                timeout=request_timeout,
            )
            if response.status_code in {400, 422} and body_idx < len(bodies) - 1:
                continue
            break
        assert response is not None
        if not is_route_miss_response(response) or route_idx == len(route_templates) - 1:
            break

    assert response is not None
    if response.status_code >= 400:
        return response

    # Check if the response itself is already a completed assistant message envelope,
    # or capture the newly created user message ID in OpenCode 2.3 async prompt mode.
    parsed: Any = None
    if response.content and response.content.strip() and not is_html_fallback_response(response):
        try:
            parsed = response.json()
        except ValueError:
            parsed = None
    submitted_user_msg_id = ""
    normalized_direct = normalize_message_envelope(parsed, fallback_session_id=session_id)
    if normalized_direct is not None:
        direct_role = str(normalized_direct.get("info", {}).get("role") or "")
        if direct_role == "assistant" and is_terminal_fn(normalized_direct):
            if normalized_direct is not parsed:
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=json.dumps(normalized_direct, ensure_ascii=False).encode("utf-8"),
                    request=getattr(response, "request", None),
                )
            return response
        if direct_role == "user":
            submitted_user_msg_id = response_id_fn(normalized_direct)

    # Asynchronous V2 prompt mode: wait for session completion via optional `/wait`,
    # SSE `session_terminal`, and `/api/session/{id}/message` history reconciliation.
    wait_route = spec.match_route(
        "post",
        "/api/session/{sessionID}/wait",
        "/api/session/:sessionID/wait",
        "/api/experimental/session/{sessionID}/wait",
        "/api/experimental/session/:sessionID/wait",
    )
    wait_task: asyncio.Task | None = None
    if wait_route is not None:
        resolved_wait_path = _fill_route_param(wait_route, quoted_sid)
        wait_has_body = spec.request_schema("post", wait_route) is not None
        wait_kwargs: dict[str, Any] = {
            "params": params,
            "headers": headers,
            "timeout": request_timeout,
        }
        if wait_has_body:
            wait_kwargs["json"] = {}
        wait_task = asyncio.create_task(
            client.post(resolved_wait_path, **wait_kwargs)
        )

    active_route = spec.match_route("get", "/api/session/active")
    history_paths = [
        f"/api/session/{quoted_sid}/message",
        f"/api/session/{quoted_sid}/messages",
        f"/session/{quoted_sid}/message",
    ]
    session_paths = [
        f"/api/session/{quoted_sid}",
        f"/session/{quoted_sid}",
    ]
    poll_params = {**params, "limit": "200"}
    saw_busy_or_new_message = False
    idle_observed_at: float | None = None

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
                    if wait_resp.status_code < 400 and not is_html_fallback_response(wait_resp):
                        terminal_event_seen = True
                except Exception:
                    pass
                wait_task = None

            messages: list[dict[str, Any]] | None = None
            for hist_path in history_paths:
                try:
                    hist_resp = await client.get(hist_path, params=poll_params, headers=headers, timeout=10.0)
                    if is_route_miss_response(hist_resp):
                        continue
                    hist_resp.raise_for_status()
                    messages = normalize_message_list(hist_resp.json(), fallback_session_id=session_id)
                    if messages is not None:
                        history_paths = [hist_path]
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

            new_assistants: list[dict[str, Any]] = []
            turn_idle_record: dict[str, Any] | None = None
            if messages is not None:
                turn_slice = messages
                if submitted_user_msg_id:
                    user_idx = next(
                        (
                            idx for idx, msg in enumerate(messages)
                            if response_id_fn(msg) == submitted_user_msg_id
                        ),
                        None,
                    )
                    if user_idx is not None:
                        turn_slice = messages[user_idx + 1:]
                elif baseline_message_id:
                    base_idx = next(
                        (
                            idx for idx, msg in enumerate(messages)
                            if response_id_fn(msg) == baseline_message_id
                        ),
                        None,
                    )
                    if base_idx is not None:
                        turn_slice = messages[base_idx + 1:]

                for msg in turn_slice:
                    role = str((msg.get("info") or {}).get("role") or "")
                    if role == "assistant":
                        new_assistants.append(msg)
                        turn_idle_record = None
                    elif role == "idle":
                        turn_idle_record = msg

                # If submitted_user_msg_id was not present in the slice, fall back to
                # assistant-only baseline slicing so mocks omitting user rows still work.
                if not submitted_user_msg_id and baseline_message_id and not new_assistants:
                    assistants = [
                        msg for msg in messages
                        if str((msg.get("info") or {}).get("role") or "") == "assistant"
                    ]
                    baseline_idx = next(
                        (
                            idx for idx, msg in enumerate(assistants)
                            if response_id_fn(msg) == baseline_message_id
                        ),
                        None,
                    )
                    if baseline_idx is not None:
                        new_assistants = assistants[baseline_idx + 1:]

                if turn_idle_record is not None:
                    terminal_event_seen = True

            if new_assistants:
                saw_busy_or_new_message = True
                # Surface any explicit assistant error immediately once that step finishes.
                for msg in new_assistants:
                    if assistant_error_fn(msg) is not None:
                        return httpx.Response(
                            status_code=200,
                            headers={"content-type": "application/json"},
                            content=json.dumps(msg, ensure_ascii=False).encode("utf-8"),
                            request=getattr(response, "request", None),
                        )

                session_busy = False
                if not terminal_event_seen and active_route is not None:
                    try:
                        active_resp = await client.get(
                            active_route, params=params, headers=headers, timeout=5.0,
                        )
                        if active_resp.status_code == 200 and not is_html_fallback_response(active_resp):
                            active_map = unwrap_v2_data(active_resp.json())
                            if isinstance(active_map, dict) and session_id in active_map:
                                session_busy = True
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass

                if not terminal_event_seen and not session_busy:
                    for sess_path in session_paths:
                        try:
                            sess_resp = await client.get(
                                sess_path, params=params, headers=headers, timeout=5.0,
                            )
                            if is_route_miss_response(sess_resp):
                                continue
                            if sess_resp.status_code == 200:
                                is_busy, is_idle = _session_snapshot_busy_state(sess_resp.json())
                                if is_busy:
                                    session_busy = True
                                elif is_idle:
                                    terminal_event_seen = True
                                session_paths = [sess_path]
                            break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue

                all_terminal = all(
                    is_terminal_fn(msg) or bool(_step_finish_reason(msg))
                    for msg in new_assistants
                )
                last_assistant = new_assistants[-1]
                last_finish = _step_finish_reason(last_assistant)
                tool_step_continuing = (
                    last_finish in {"tool-calls", "tool_calls", "tool_use"}
                    or _has_active_tool_parts(last_assistant)
                )
                # In OpenCode 2.3, assistant rows may omit `time.completed` / `info.finish`
                # even after the session transitions back to `idle`. Treat `terminal_event_seen`
                # with no active tool calls as settled.
                if (all_terminal or terminal_event_seen) and (
                    terminal_event_seen or (not session_busy and not tool_step_continuing)
                ) and not (tool_step_continuing and not terminal_event_seen):
                    if terminal_event_seen or idle_observed_at is not None:
                        final_envelope = _merge_multistep_text_if_needed(new_assistants)
                        return httpx.Response(
                            status_code=200,
                            headers={"content-type": "application/json"},
                            content=json.dumps(final_envelope, ensure_ascii=False).encode("utf-8"),
                            request=getattr(response, "request", None),
                        )
                    idle_observed_at = time.monotonic()
                else:
                    idle_observed_at = None
            elif terminal_event_seen and turn_idle_record is not None:
                idle_info = turn_idle_record.get("info") if isinstance(turn_idle_record.get("info"), dict) else {}
                idle_err = idle_info.get("error")
                if idle_err is not None:
                    synth = {
                        "info": {
                            "id": str(idle_info.get("id") or f"v2-error-{int(time.time() * 1000)}"),
                            "sessionID": session_id,
                            "role": "assistant",
                            "error": normalize_v2_error(idle_err),
                        },
                        "parts": [],
                    }
                    return httpx.Response(
                        status_code=200,
                        headers={"content-type": "application/json"},
                        content=json.dumps(synth, ensure_ascii=False).encode("utf-8"),
                        request=getattr(response, "request", None),
                    )
                if saw_busy_or_new_message:
                    break
            elif terminal_event_seen and saw_busy_or_new_message:
                break

            # If event_state recorded a fatal session.error before any assistant message row
            # was persisted, synthesize an error envelope rather than hanging until timeout.
            if (
                terminal_event_seen
                and not new_assistants
                and event_state is not None
                and (
                    getattr(event_state, "last_session_error", None) is not None
                    or getattr(event_state, "session_errors_emitted", None)
                )
            ):
                raw_error = getattr(event_state, "last_session_error", None)
                if isinstance(raw_error, dict):
                    synth_error: object = normalize_v2_error(raw_error)
                else:
                    err_text = (
                        next(iter(event_state.session_errors_emitted))
                        if getattr(event_state, "session_errors_emitted", None)
                        else str(raw_error or "unknown")
                    )
                    synth_error = {"name": "SessionError", "message": err_text}
                synth = {
                    "info": {
                        "id": f"v2-error-{int(time.time() * 1000)}",
                        "sessionID": session_id,
                        "role": "assistant",
                        "error": synth_error,
                    },
                    "parts": [],
                }
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=json.dumps(synth, ensure_ascii=False).encode("utf-8"),
                    request=getattr(response, "request", None),
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
