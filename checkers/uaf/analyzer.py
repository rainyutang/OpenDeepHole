"""OOB (Out-of-Bounds) static analyzer.

TODO: Replace placeholder with tree-sitter / joern implementation.
"""

from pathlib import Path

from backend.analyzers.base import BaseAnalyzer, Candidate


class Analyzer(BaseAnalyzer):
    """Detect candidate out-of-bounds access locations in C/C++ code."""

    vuln_type = "uaf"

    def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
        """Find candidate OOB locations.

        TODO: Implement with tree-sitter / joern.
        Currently returns empty list as placeholder.
        """
        return []
