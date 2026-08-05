"""Validation for the method-independent threat-analysis artifact contract."""

from __future__ import annotations

from typing import Any


REQUIRED_THREAT_ANALYSIS_ARTIFACTS = (
    "value_asset_path",
    "attack_tree_path",
    "high_risk_modules_path",
)


def parse_threat_analysis_data(data: dict[str, Any]) -> dict[str, Any]:
    """Validate the shared envelope and the three UI/audit JSON roots."""
    if not isinstance(data, dict):
        raise TypeError("threat analysis payload must be a dict")
    entrypoint_result = data.get("entrypoint_result")
    artifacts = data.get("artifacts")
    if not isinstance(entrypoint_result, dict):
        raise TypeError("threat analysis entrypoint_result must be a dict")
    if entrypoint_result.get("result") is not True:
        raise ValueError("threat analysis entrypoint_result.result must be true")
    if not isinstance(artifacts, dict) or not artifacts:
        raise TypeError("threat analysis artifacts must be a non-empty dict")
    missing = [
        key
        for key in REQUIRED_THREAT_ANALYSIS_ARTIFACTS
        if key not in entrypoint_result or key not in artifacts
    ]
    if missing:
        raise ValueError(
            "threat analysis payload is missing required artifact(s): "
            + ", ".join(missing)
        )
    for key, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            raise TypeError(f"threat analysis artifact {key!r} must be a dict")
        if not isinstance(artifact.get("path"), str) or not artifact["path"]:
            raise TypeError(f"threat analysis artifact {key!r} path must be a string")
        if "content" not in artifact:
            raise ValueError(f"threat analysis artifact {key!r} is missing content")
    if not isinstance(artifacts["value_asset_path"]["content"], list):
        raise TypeError("value_asset_path content must be a JSON array")
    attack_tree_content = artifacts["attack_tree_path"]["content"]
    if (
        not isinstance(attack_tree_content, dict)
        or not isinstance(attack_tree_content.get("attack_trees"), list)
    ):
        raise TypeError(
            "attack_tree_path content must be an object with an attack_trees array"
        )
    if not isinstance(artifacts["high_risk_modules_path"]["content"], list):
        raise TypeError("high_risk_modules_path content must be a JSON array")
    return data


__all__ = [
    "REQUIRED_THREAT_ANALYSIS_ARTIFACTS",
    "parse_threat_analysis_data",
]
