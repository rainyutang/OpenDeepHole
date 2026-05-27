---
name: skill-creator
description: Create concise, production-ready Codex/OpenCode skills from a user-provided name, description, and task input.
---

# Skill Creator

Create a single focused skill directory concept for the requested task. Keep the generated `SKILL.md` concise and operational.

## Output Rules

- Output only the requested JSON object when the caller asks for JSON.
- Do not create files directly unless explicitly asked by the caller.
- Do not include auxiliary files such as README, install guides, changelogs, or quick references.
- Prefer one required `SKILL.md`; include `SCENARIOS.md` text only when it materially helps users understand when to select the skill.

## SKILL.md Requirements

- Include YAML frontmatter with `name` and `description`.
- The body should contain only the procedural guidance the AI needs at scan time.
- Avoid generic security advice; tailor the workflow to the supplied description and input.
- For OpenDeepHole project-level audit skills, instruct the AI to inspect the target code, identify concrete file/function/line evidence, and call `submit_result`.
- If multiple issues are found, require one `submit_result` call per issue.
- If no issue is found, require one `submit_result` call with `confirmed=false`.

## Quality Bar

- Make trigger conditions, evidence requirements, false-positive exclusions, and result submission rules explicit.
- Keep examples short and domain-specific.
- Do not invent static analyzer behavior or Semgrep rules unless the caller asks for analyzer generation.
