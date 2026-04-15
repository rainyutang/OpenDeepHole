"""OOB (Out-of-Bounds) static analyzer.

TODO: Replace placeholder with tree-sitter / joern implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    """Detect candidate out-of-bounds access locations in C/C++ code."""

    vuln_type = "oob"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        """Find candidate OOB locations.

        TODO: Implement with tree-sitter / joern.
        Currently returns empty list as placeholder.
        """
        return []
