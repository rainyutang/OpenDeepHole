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

    # ---------------------------------------------------------------------------
    # Agent registration / heartbeat
    # ---------------------------------------------------------------------------

    async def register_agent(self, port: int, name: str) -> tuple[str, dict | None]:
        """Register with server, return (agent_id, remote_config | None)."""
        resp = await self._client.post(
            f"{self.server_url}/api/agent/register",
            json={"port": port, "name": name},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["agent_id"], data.get("config")

    async def fetch_config(self, agent_id: str) -> dict | None:
        """Fetch the latest server-managed config for this agent."""
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/{agent_id}/config",
                timeout=5.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    async def heartbeat(self, agent_id: str) -> None:
        """Send heartbeat (best-effort)."""
        try:
            await self._client.put(
                f"{self.server_url}/api/agent/heartbeat/{agent_id}",
                timeout=5.0,
            )
        except Exception:
            pass

    async def unregister_agent(self, agent_id: str) -> None:
        """Unregister on shutdown (best-effort)."""
        try:
            await self._client.delete(
                f"{self.server_url}/api/agent/{agent_id}",
                timeout=5.0,
            )
        except Exception:
            pass

    # ---------------------------------------------------------------------------
    # Scan events / results
    # ---------------------------------------------------------------------------

    async def report_vulnerability(self, scan_id: str, vuln: Vulnerability) -> None:
        """Push a single vulnerability result immediately after it is audited."""
        if self.dry_run:
            marker = "[VULN]" if vuln.confirmed else "[  FP]"
            print(f"  {marker} {vuln.vuln_type.upper()} {vuln.file}:{vuln.line} ({vuln.function})")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                json=vuln.model_dump(),
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload vulnerability result: {e}")

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

    async def report_processed_key(
        self, scan_id: str, file: str, line: int, function: str, vuln_type: str
    ) -> None:
        """Report a successfully processed candidate key (fire-and-forget)."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                json={"file": file, "line": line, "function": function, "vuln_type": vuln_type},
                timeout=5.0,
            )
        except Exception:
            pass

    async def get_processed_keys(self, scan_id: str) -> set[tuple[str, int, str, str]]:
        """Fetch already-processed candidate keys for resume (skip these on restart)."""
        if self.dry_run:
            return set()
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                timeout=10.0,
            )
            resp.raise_for_status()
            return {
                (item["file"], int(item["line"]), item["function"], item["vuln_type"])
                for item in resp.json()
            }
        except Exception:
            return set()

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
