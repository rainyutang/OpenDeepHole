"""HTTP client for pushing scan progress and results to the web server."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from backend.models import FeedbackEntry, ScanEvent, Vulnerability


class Reporter:
    """Sends scan events and final results to the web server."""

    def __init__(self, server_url: str, dry_run: bool = False) -> None:
        self.server_url = server_url.rstrip("/")
        self.dry_run = dry_run
        self._client = httpx.AsyncClient(timeout=30.0)

    async def register_scan(self, project_name: str, scan_items: list[str]) -> str:
        """Register a new scan with the server, returns scan_id."""
        if self.dry_run:
            import uuid
            return uuid.uuid4().hex
        resp = await self._client.post(
            f"{self.server_url}/api/agent/scan",
            json={"project_name": project_name, "scan_items": scan_items},
        )
        resp.raise_for_status()
        return resp.json()["scan_id"]

    async def send_event(self, scan_id: str, event: ScanEvent) -> None:
        """Push a progress event to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/event",
                json=event.model_dump(),
                timeout=10.0,
            )
        except Exception:
            pass

    async def finish_scan(
        self,
        scan_id: str,
        vulnerabilities: list[Vulnerability],
        status: str,
        total_candidates: int,
        processed_candidates: int,
        error_message: Optional[str] = None,
    ) -> None:
        """Push final scan results. Retries up to 3 times on failure."""
        if self.dry_run:
            confirmed = sum(1 for v in vulnerabilities if v.confirmed)
            print(f"\n--- Dry-run results: {confirmed}/{len(vulnerabilities)} confirmed ---")
            for v in vulnerabilities:
                marker = "[VULN]" if v.confirmed else "[  FP]"
                print(f"  {marker} {v.vuln_type.upper()} {v.file}:{v.line} ({v.function})")
                if v.confirmed:
                    print(f"         {v.description}")
            return

        payload = {
            "vulnerabilities": [v.model_dump() for v in vulnerabilities],
            "status": status,
            "total_candidates": total_candidates,
            "processed_candidates": processed_candidates,
            "error_message": error_message,
        }
        for attempt in range(3):
            try:
                resp = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/finish",
                    json=payload,
                    timeout=60.0,
                )
                resp.raise_for_status()
                return
            except Exception as e:
                if attempt == 2:
                    print(f"Warning: failed to deliver results to server after 3 attempts: {e}")
                    return
                await asyncio.sleep(2**attempt)

    async def get_feedback(self, vuln_types: list[str]) -> list[FeedbackEntry]:
        """Fetch false-positive feedback entries from the server for SKILL enrichment."""
        if self.dry_run or not vuln_types:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/feedback",
                params={"vuln_types": ",".join(vuln_types)},
                timeout=10.0,
            )
            resp.raise_for_status()
            return [FeedbackEntry(**item) for item in resp.json()]
        except Exception:
            return []

    async def close(self) -> None:
        await self._client.aclose()
