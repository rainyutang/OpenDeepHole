"""Base class for static vulnerability analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
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

    ``find_candidates`` may return a list (batch mode) or a generator
    (streaming mode). In streaming mode, the scan loop can start LLM
    analysis on each candidate as it is yielded.
    """

    vuln_type: str

    # 可选的文件级进度回调: on_file_progress(scanned_files, total_files)
    # 扫描管线在调用 find_candidates 前设置，完成后清除。
    on_file_progress: Callable[[int, int], None] | None = None

    @abstractmethod
    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterable[Candidate]:
        """Return candidate vulnerability locations in *project_path*.

        Args:
            project_path: Absolute path to the extracted project directory.
            db: Optional pre-built code index for this project.

        Returns:
            Iterable of :class:`Candidate` objects. May be a list or a
            generator for streaming analysis.
        """
