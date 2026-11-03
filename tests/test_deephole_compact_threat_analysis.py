from __future__ import annotations

from deephole_client.threat_analysis import THREAT_ANALYSIS_METHODS_DIR


ORIGINAL_ROOT = THREAT_ANALYSIS_METHODS_DIR / "deephole_threat_analysis"
COMPACT_ROOT = THREAT_ANALYSIS_METHODS_DIR / "deephole_compact_threat_analysis"
SKILL_PREFIX = "deephole-compact-"


def _method_files(root):
    return {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def test_compact_method_preserves_original_implementation_and_prompts():
    original_files = _method_files(ORIGINAL_ROOT)
    compact_files = {
        relative.replace(SKILL_PREFIX, ""): path
        for relative, path in _method_files(COMPACT_ROOT).items()
    }
    assert compact_files.keys() == original_files.keys()
    for relative, original in original_files.items():
        if relative == "method.yaml":
            continue
        # The clone may change Skill identities, but not business behavior.
        assert compact_files[relative].read_bytes().replace(
            SKILL_PREFIX.encode(), b""
        ) == original.read_bytes(), relative
