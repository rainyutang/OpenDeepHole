"""Base class for static vulnerability analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from backend.models import Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase

__all__ = ["BaseAnalyzer", "Candidate"]


class BaseAnalyzer(ABC):
    """Abstract base for checker static analyzers.

    Subclasses must set ``vuln_type`` and implement ``find_candidates()``.
    The ``db`` parameter is optional: if a code index has been built for the
    project, it is passed in so analyzers can query parsed structures instead
    of re-parsing from scratch. If the index is not yet available (e.g. still
    building) ``db`` will be ``None``.
    """

    vuln_type: str

    @abstractmethod
    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        """Return candidate vulnerability locations in *project_path*.

        Args:
            project_path: Absolute path to the extracted project directory.
            db: Optional pre-built code index for this project.

        Returns:
            List of :class:`Candidate` objects describing potential issues.
        """
