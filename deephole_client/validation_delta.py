"""Incremental wire format for validation bodies; works with legacy snapshots."""

import json


TEXT_FIELDS = ("validation_code", "validation_output", "intermediate_output", "final_output")


def _key(parts):
    return json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validation_change_batches(changes):
    """Keep large artifacts bounded without truncating a Unicode character."""
    batch, size, fields = [], 0, set()
    for change in changes:
        content = change["content"]
        positions = range(0, len(content), 128 * 1024) if change["operation"] != "alias" and content else (0,)
        for offset in positions:
            part = content[offset:offset + 128 * 1024] if change["operation"] != "alias" else content
            item = {**change, "content": part, "operation": "append" if offset else change["operation"]}
            cost = len(_key(item).encode())
            if batch and (size + cost > 1024 * 1024 or len(batch) >= 500 or change["field"] in fields):
                yield batch
                batch, size, fields = [], 0, set()
            batch.append(item)
            fields.add(change["field"])
            size += cost
    if batch or not changes:
        yield batch


def validation_delta(payload, previous=None):
    previous = previous or {}
    fields = {key: payload.get(key) or "" for key in TEXT_FIELDS}
    state = {key: value for key, value in payload.items() if key not in TEXT_FIELDS}
    state["output_sections"] = []
    for item in payload.get("output_sections") or []:
        fields[_key(["section", item.get("title", "")])] = str(item.get("content") or "")
        state["output_sections"].append({key: value for key, value in item.items() if key != "content"})
    state["artifacts"] = []
    for item in payload.get("artifacts") or []:
        key = _key(["artifact", item.get("name", ""), item.get("kind", "")])
        fields[key] = str(item.get("content") or "")
        state["artifacts"].append({key: value for key, value in item.items() if key != "content"})
        if fields["validation_code"] and fields["validation_code"] == fields[key]:
            fields["validation_code"] = {"alias": key}
    combined = "".join(str(item.get("content") or "") for item in payload.get("output_sections") or [])[-120000:]
    if combined and fields["intermediate_output"] == combined:
        fields["intermediate_output"] = {"alias": "@sections"}
    if fields["validation_output"] and fields["validation_output"] == fields["final_output"]:
        fields["validation_output"] = {"alias": "final_output"}
    changes = []
    for key, value in fields.items():
        old = previous.get(key, "")
        if value == old:
            continue
        if isinstance(value, dict):
            changes.append({"field": key, "operation": "alias", "content": value["alias"]})
        elif isinstance(old, str) and old and value.startswith(old):
            changes.append({"field": key, "operation": "append", "content": value[len(old):]})
        else:
            changes.append({"field": key, "operation": "set", "content": value})
    return state, changes, fields
