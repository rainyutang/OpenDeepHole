/**
 * Lightweight Cordis pre-execute tool gate for OpenDeepHole DeepSeek Harness runs.
 *
 * Delegates policy-controlled tools (file mutations & bash commands) to DeepSeek
 * Harness's native `@deepseek-ai/dsh-user-approval` -> JSON-RPC `approval/request`
 * channel so Python enforces OpenDeepHole's exact write-root and bash-allowlist rules.
 */

export const name = "odh-tool-gate";
export const inject = ["tools"];

function normalizeArgs(exec) {
  if (exec && typeof exec === "object") {
    const candidate = exec.input ?? exec.args ?? exec.arguments;
    if (candidate && typeof candidate === "object") {
      return candidate;
    }
    if (typeof candidate === "string") {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === "object") {
          return parsed;
        }
      } catch {
        return { raw: candidate };
      }
    }
  }
  return {};
}

export function apply(ctx, config = {}) {
  const denyAll = Boolean(config.denyAll);
  const askTools = new Set(Array.isArray(config.askTools) ? config.askTools : []);
  const denyTools = new Set(Array.isArray(config.denyTools) ? config.denyTools : []);

  ctx.on("tools/pre-execute", async (exec, next) => {
    const toolName = String(exec?.name ?? "").trim();
    if (denyAll || denyTools.has(toolName)) {
      return {
        kind: "deny",
        reason: "Blocked by OpenDeepHole task tool policy",
      };
    }
    if (askTools.has(toolName)) {
      const payload = JSON.stringify({
        tool: toolName,
        args: normalizeArgs(exec),
      });
      return {
        kind: "ask",
        reason: payload,
      };
    }
    return next();
  });
}
