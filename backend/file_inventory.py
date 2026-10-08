"""The independent, program-generated inventory contract (no model artifacts)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


MAX_INVENTORY_ENTRIES = 200_000


class FileInventoryEntry(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    kind: Literal["file", "directory"]

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        if value != "." and (
            value.startswith("/") or "\0" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("inventory paths must be normalized relative POSIX paths")
        return value


class FileInventoryIssue(BaseModel):
    path: str
    reason: str


class ScanFileInventory(BaseModel):
    schema_version: Literal[1] = 1
    snapshot_id: str = Field(min_length=1, max_length=100)
    status: Literal["collecting", "complete", "partial", "failed", "cancelled"]
    project_path: str = Field(min_length=1, max_length=4096)
    scan_root: str = Field(min_length=1, max_length=4096)
    captured_at: str
    entries: list[FileInventoryEntry] = Field(default_factory=list, max_length=MAX_INVENTORY_ENTRIES)
    issues: list[FileInventoryIssue] = Field(default_factory=list, max_length=100)
    issue_count: int = Field(default=0, ge=0)
    excluded_paths: list[str] = Field(default_factory=list)
    error_message: str = ""

    @field_validator("captured_at")
    @classmethod
    def utc_timestamp(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("captured_at must include a timezone")
        return parsed.astimezone(timezone.utc).isoformat()

    @model_validator(mode="after")
    def valid_tree(self) -> ScanFileInventory:
        paths = {entry.path: entry.kind for entry in self.entries}
        if len(paths) != len(self.entries):
            raise ValueError("duplicate inventory paths")
        if self.status in {"complete", "partial"} and paths.get(".") != "directory":
            raise ValueError("inventory must contain its root directory")
        for path in paths:
            if path == ".":
                continue
            parent = path.rsplit("/", 1)[0] if "/" in path else "."
            if paths.get(parent) != "directory":
                raise ValueError(f"missing inventory parent: {parent}")
        if self.status == "complete" and (self.issue_count or self.issues):
            raise ValueError("an incomplete inventory cannot be marked complete")
        return self


class FileInventoryUpload(BaseModel):
    agent_session_id: str = ""
    execution_revision: int = Field(default=0, ge=0)
    inventory: ScanFileInventory
