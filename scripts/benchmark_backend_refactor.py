#!/usr/bin/env python3
"""Reproducible Scan/Agent ASGI benchmark against an isolated checkout.

Runs real routers, serialization, persistence and the asynchronous store executor.
The controlled Agent only answers protocol messages; it never invokes an LLM.
Use a fresh process and --source for each baseline/refactor sample. Results are
synthetic local measurements, not estimates of production scan throughput.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextlib import nullcontext
import json
import importlib.util
import io
import zipfile
import logging
import math
import os
import platform
from pathlib import Path
import resource
import statistics
import sys
import tempfile
import time
from typing import Callable


def percentile(values: list[float], q: float) -> float:
    return sorted(values)[max(0, math.ceil(q * len(values)) - 1)] if values else 0.0


def peak_rss_kib() -> int:
    # On Linux getrusage can retain the launcher's pre-exec high-water mark.
    # /proc describes this executable's address space and avoids that artifact.
    status = Path("/proc/self/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value / 1024 if sys.platform == "darwin" else value)


def delta_counter(after: dict, before: dict) -> dict:
    return {k: after.get(k, 0) - before.get(k, 0) for k in after.keys() | before.keys()
            if after.get(k, 0) != before.get(k, 0)}


def make_app(store=None, *, auth_mode="sync"):
    from fastapi import FastAPI
    from backend.api import scan, agent
    from backend.auth import get_current_user
    from backend.models import User
    from backend.runtime_metrics import RequestMetricsMiddleware
    app = FastAPI()
    if importlib.util.find_spec("backend.application") is not None:
        from backend.application import BackendRuntime
        app.state.backend_runtime = BackendRuntime(store=store)
    app.include_router(scan.router)
    app.include_router(agent.router)
    app.include_router(agent.public_router)
    if auth_mode == "async":
        async def current_user():
            return User(user_id="owner", username="bench", role="admin")
        app.dependency_overrides[get_current_user] = current_user
    else:
        app.dependency_overrides[get_current_user] = lambda: User(user_id="owner", username="bench", role="admin")
    app.add_middleware(RequestMetricsMiddleware)
    return app


def seed(store, task_count: int):
    from backend.models import ScanMeta, ScanStatus
    stamp = "2026-09-07T00:00:00+00:00"
    for i in range(100):
        scan_id = f"bench-{i:03}"
        store.save_scan(
            ScanStatus(scan_id=scan_id, created_at=stamp, status="complete", progress=1,
                       total_candidates=0, processed_candidates=0, vulnerabilities=[]),
            ScanMeta(scan_items=[], created_at=stamp, scan_name=scan_id, user_id="owner"),
        )
    store.save_scan(
        ScanStatus(scan_id="live", created_at=stamp, status="auditing", progress=0,
                   total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at=stamp, scan_name="live", user_id="owner"),
    )
    # Event ingestion can finalize static analysis. Keep candidate ingestion on
    # its own active scan so it measures writes, not finalized-report discard.
    store.save_scan(
        ScanStatus(scan_id="candidate-live", created_at=stamp, status="analyzing", progress=0,
                   total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at=stamp, scan_name="candidate-live", user_id="owner"),
    )
    # Bulk setup is outside timed regions. Metadata and task body remain separate.
    with store._lock:
        rows = []
        for i in range(task_count):
            metadata = json.dumps({"task_id": f"task-{i:06}", "scope_id": "bench-000", "revision": 1,
                                   "outcome": "success", "finished_at": stamp})
            body = json.dumps({"task_id": f"task-{i:06}", "prompt": "x" * 1024})
            rows.append((f"record-{i:06}", "bench-000", f"task-{i:06}", 1, metadata, body, stamp))
        store._conn.executemany(
            "INSERT INTO scan_task_versions (record_id, scan_id, task_id, revision, metadata_json, task_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
        )
        store._conn.executemany(
            "INSERT INTO scan_task_current (scan_id, task_id, revision, record_id) VALUES (?, ?, ?, ?)",
            [(r[1], r[2], r[3], r[0]) for r in rows],
        )
        store._conn.execute("UPDATE scans SET history_version = 1")
        store._conn.commit()


async def measure(name: str, operation: Callable, *, concurrency: int, samples: int,
                  warmup: int, rounds: int, profile_path: Path | None = None) -> dict:
    from backend.runtime_metrics import runtime_metrics
    for i in range(warmup):
        await operation(i)
    profiler = None
    if profile_path is not None:
        import cProfile
        profiler = cProfile.Profile()
    results = []
    for _round in range(rounds):
        latencies, lag = [], []
        stop = asyncio.Event()

        async def monitor():
            while not stop.is_set():
                started = time.perf_counter()
                await asyncio.sleep(0.005)
                lag.append(max(0.0, (time.perf_counter() - started - 0.005) * 1000))

        ticker = asyncio.create_task(monitor())
        before = runtime_metrics.snapshot()
        if profiler is not None:
            profiler.enable()
        started, cpu = time.perf_counter(), time.process_time()
        counts = Counter()
        sem = asyncio.Semaphore(concurrency)

        async def one(i):
            async with sem:
                tick = time.perf_counter()
                outcome = await operation(i)
                latencies.append((time.perf_counter() - tick) * 1000)
                counts[str(outcome)] += 1

        await asyncio.gather(*(one(i) for i in range(samples)))
        seconds, cpu_seconds = time.perf_counter() - started, time.process_time() - cpu
        if profiler is not None:
            profiler.disable()
        stop.set()
        await ticker
        after = runtime_metrics.snapshot()
        results.append({
            "p50_ms": percentile(latencies, .50), "p95_ms": percentile(latencies, .95),
            "throughput_per_second": samples / seconds, "wall_seconds": seconds,
            "cpu_ms_per_operation": cpu_seconds * 1000 / samples,
            "event_loop_lag_p95_ms": percentile(lag, .95),
            "store_calls": after["store"]["total"] - before["store"]["total"],
            "store_operations": delta_counter(after["store"]["by_operation"], before["store"]["by_operation"]),
            "store_recent_execution_ms": after["store"]["execution_ms"],
            "store_recent_queue_ms": after["store"]["queue_ms"],
            "outcomes": dict(counts),
        })
    fields = ("p50_ms", "p95_ms", "throughput_per_second", "cpu_ms_per_operation", "event_loop_lag_p95_ms", "store_calls")
    result = {"name": name, "concurrency": concurrency, "samples_per_round": samples,
              "warmup": warmup, "rounds": results,
              "median": {key: statistics.median(row[key] for row in results) for key in fields},
              "peak_rss_kib": peak_rss_kib()}
    if profiler is not None:
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profiler.dump_stats(str(profile_path))
    print(json.dumps({"scenario": name, "concurrency": concurrency, **result["median"]}), flush=True)
    return result


class ControlledAgent:
    """Actual ASGI WebSocket connection, with deterministic protocol responses."""
    def __init__(self, app, *, publish_acks=False, hello=None):
        self.app = app
        self.publish_acks = publish_acks
        self.hello = hello or {}
        self.incoming = asyncio.Queue()
        self.welcome = asyncio.get_running_loop().create_future()
        self.heartbeat_acks = asyncio.Queue()
        self.command_counts = Counter()
        self.task = None

    async def connect(self):
        await self.incoming.put({"type": "websocket.connect"})
        await self.message({"type": "hello", "name": "bench-agent", "machine_name": "bench-host",
                            "active_scans": [], "protocol_versions": [1, 2], **self.hello})
        scope = {"type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "scheme": "ws", "path": "/api/agent/ws", "raw_path": b"/api/agent/ws",
                 "root_path": "", "query_string": b"", "headers": [],
                 "client": ("127.0.0.1", 9999), "server": ("bench", 80), "subprotocols": []}
        self.task = asyncio.create_task(self.app(scope, self.incoming.get, self.receive))
        return await asyncio.wait_for(self.welcome, 20)

    async def message(self, value):
        await self.incoming.put({"type": "websocket.receive", "text": json.dumps(value)})

    async def receive(self, event):
        if event["type"] == "websocket.close":
            if not self.welcome.done():
                self.welcome.set_exception(RuntimeError(f"Agent rejected: {event}"))
            return
        if event["type"] != "websocket.send":
            return
        message = json.loads(event.get("text") or event["bytes"])
        kind = message.get("type", "")
        self.command_counts[kind] += 1
        if kind == "welcome":
            self.welcome.set_result(message)
        elif kind == "heartbeat_ack":
            await self.heartbeat_acks.put(None)
        elif kind == "opencode_models":
            await self.message({"type": "opencode_models_result", "request_id": message["request_id"],
                                "ok": True, "models": []})
            if self.publish_acks:
                from backend.sse import publish
                publish("bench-cross", "benchmark_ack", {"request_id": message["request_id"]})
        else:
            raise RuntimeError(f"Unexpected controlled Agent command: {kind}")

    async def heartbeat(self, _i):
        await self.message({"type": "heartbeat"})
        await asyncio.wait_for(self.heartbeat_acks.get(), 5)
        return "ack"

    async def close(self):
        await self.incoming.put({"type": "websocket.disconnect", "code": 1000})
        await asyncio.wait_for(self.task, 10)


async def benchmark(args, store):
    import httpx
    from backend.store.async_ops import shutdown_store_executor
    app = make_app(store, auth_mode=args.auth_mode)
    tasks_before = set(asyncio.all_tasks())
    result = {"source": str(args.source.resolve()), "python": sys.version, "database": args.database,
              "seed": {"scans": 102, "tasks": args.tasks, "task_body_bytes": 1024}, "measurements": []}
    extra = {}
    # Current applications expose an explicit runtime scope; the pre-refactor
    # checkout uses the existing store singleton. This is setup, never timed.
    from backend import store as store_module
    store_module._store = store
    agent = None
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bench") as client:
            async def request(method, url, **kwargs):
                response = await client.request(method, url, **kwargs)
                if response.status_code != 200:
                    raise RuntimeError(f"{method} {url}: {response.status_code} {response.text[:500]}")
                payload = response.json()
                if url == "/api/v2/scans?limit=50":
                    assert len(payload["items"]) == 50
                elif "/tasks?" in url:
                    assert len(payload["items"]) == min(50, args.tasks)
                    assert all("prompt" not in item for item in payload["items"])
                elif url.endswith("/overview"):
                    assert payload["scan_id"] == "bench-000" and payload["status"] == "complete"
                    assert payload["vulnerabilities"] == []
                elif url.endswith("/events"):
                    assert payload == {"ok": True, "count": 10}
                elif url.endswith("/candidates"):
                    assert payload == {"ok": True, "offset": 0, "count": 10, "total": 10}
                elif url.endswith("/opencode/models"):
                    assert payload == {"ok": True, "message": "", "models": []}
                return response.status_code
            events = [{"timestamp": "2026-09-07T00:00:00+00:00", "phase": "auditing", "message": f"event {i}"} for i in range(10)]
            candidates = [{"file": f"src/f{i}.c", "line": i + 1, "function": f"f{i}", "vuln_type": "npd", "description": "candidate"} for i in range(10)]
            operations = {
                "scan_list": lambda i: request("GET", "/api/v2/scans?limit=50"),
                "scan_overview": lambda i: request("GET", "/api/v2/scans/bench-000/overview"),
                "task_page": lambda i: request("GET", "/api/v2/scans/bench-000/tasks?limit=50"),
                "batch_events_10": lambda i: request("POST", "/api/agent/v2/scan/live/events", json={"events": events}),
                "batch_candidates_10": lambda i: request("POST", "/api/agent/v2/scan/candidate-live/candidates", json={"offset": 0, "candidates": candidates, "reset": False, "final": False, "total": 10}),
            }
            mixed_overview, mixed_events = operations["scan_overview"], operations["batch_events_10"]
            async def mixed(i):
                return await (mixed_overview(i) if i % 2 else mixed_events(i))
            operations["mixed_overview_events"] = mixed
            if args.mode in {"all", "ws"}:
                agent = ControlledAgent(app)
                welcome = await agent.connect()
                operations["local_rpc_models"] = lambda i: request("GET", f"/api/agent/{welcome['agent_id']}/opencode/models")
                operations["heartbeat"] = agent.heartbeat
            if args.mode == "ws":
                operations = {key: value for key, value in operations.items() if key in {"local_rpc_models", "heartbeat"}}
            if args.scenarios:
                missing = set(args.scenarios) - operations.keys()
                if missing:
                    raise ValueError(f"Unavailable scenarios: {sorted(missing)}")
                operations = {name: operations[name] for name in args.scenarios}
            for name, operation in operations.items():
                for concurrency in args.concurrency:
                    result["measurements"].append(await measure(name, operation, concurrency=concurrency,
                        samples=args.samples, warmup=args.warmup, rounds=args.rounds, profile_path=args.profile_output))
            if agent:
                extra["agent_commands"] = dict(agent.command_counts)
                await agent.close()
                agent = None
    finally:
        if agent:
            await agent.close()
        pending = set(asyncio.all_tasks()) - tasks_before
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await shutdown_store_executor()
    result.update(extra)
    result["peak_rss_kib"] = peak_rss_kib()
    return result


def runtime_scope(app):
    if hasattr(app.state, "backend_runtime"):
        from backend.application import use_runtime
        return use_runtime(app.state.backend_runtime)
    return nullcontext()


async def worker(args, store):
    """Independent process owning the real Agent WebSocket and durable runtime."""
    from backend import store as store_module
    from backend.distributed import WORKER_ID, run_distributed_runtime
    from backend.sse import configure_distributed_sse
    from backend.store.async_ops import run_store_call, shutdown_store_executor
    store_module._store = store
    app = make_app(store, auth_mode=args.auth_mode)
    with runtime_scope(app):
        await run_store_call(store, "register_worker", WORKER_ID)
        configure_distributed_sse(store, WORKER_ID)
        distributed = asyncio.create_task(run_distributed_runtime(store))
        agent = ControlledAgent(app, publish_acks=True)
        welcome = await agent.connect()
        print(json.dumps({"ready": welcome["agent_id"], "worker": WORKER_ID}), flush=True)
        try:
            await asyncio.to_thread(sys.stdin.readline)
        finally:
            await agent.close()
            distributed.cancel()
            await asyncio.gather(distributed, return_exceptions=True)
            if hasattr(app.state, "backend_runtime"):
                await app.state.backend_runtime.close()
            await shutdown_store_executor()
            print(json.dumps({"worker_cpu_seconds": time.process_time(), "worker_peak_rss_kib": peak_rss_kib()}), flush=True)


async def cross_worker(args, store):
    """HTTP request on worker A, WS command/reply on B, durable SSE back to A."""
    import httpx
    from backend import store as store_module
    from backend.distributed import WORKER_ID, run_distributed_runtime
    from backend.sse import configure_distributed_sse, subscribe, unsubscribe
    from backend.store.async_ops import run_store_call, shutdown_store_executor
    store_module._store = store
    app = make_app(store, auth_mode=args.auth_mode)
    result = {"source": str(args.source.resolve()), "python": sys.version, "database": "postgres",
              "workers": 2, "measurements": []}
    with runtime_scope(app):
        await run_store_call(store, "register_worker", WORKER_ID)
        configure_distributed_sse(store, WORKER_ID)
        distributed = asyncio.create_task(run_distributed_runtime(store))
        queue = subscribe("bench-cross")
        remote = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).resolve()),
            "--source", str(args.source.resolve()), "--mode", "worker", "--database", "postgres",
            "--dsn", args.dsn, "--auth-mode", args.auth_mode, "--output", str(args.output), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            readiness = await asyncio.wait_for(remote.stdout.readline(), 30)
            if not readiness:
                raise RuntimeError((await remote.stderr.read()).decode())
            ready = json.loads(readiness)
            seen = set()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bench") as client:
                async def operation(i):
                    response = await client.get(f"/api/agent/{ready['ready']}/opencode/models")
                    if response.status_code != 200:
                        raise RuntimeError(f"Remote RPC: {response.status_code} {response.text}")
                    assert response.json() == {"ok": True, "message": "", "models": []}
                    event = await asyncio.wait_for(queue.get(), 10)
                    if event.get("event") != "benchmark_ack":
                        raise RuntimeError(f"Unexpected stream event: {event}")
                    request_id = event["data"]["request_id"]
                    if request_id in seen:
                        raise RuntimeError("Duplicate durable SSE acknowledgement")
                    seen.add(request_id)
                    return "rpc+sse"
                for concurrency in args.concurrency:
                    result["measurements"].append(await measure("cross_worker_rpc_sse", operation,
                        concurrency=concurrency, samples=args.samples, warmup=args.warmup, rounds=args.rounds))
            result["unique_acknowledgements"] = len(seen)
        finally:
            remote.stdin.write(b"stop\n")
            await remote.stdin.drain()
            try:
                await asyncio.wait_for(remote.wait(), 20)
            except asyncio.TimeoutError:
                remote.kill()
                await remote.wait()
                raise
            if remote.returncode:
                raise RuntimeError((await remote.stderr.read()).decode())
            statistics_line = await remote.stdout.readline()
            if statistics_line:
                result["remote_worker"] = json.loads(statistics_line)
            unsubscribe("bench-cross", queue)
            distributed.cancel()
            await asyncio.gather(distributed, return_exceptions=True)
            await shutdown_store_executor()
    result["peak_rss_kib"] = peak_rss_kib()
    return result


async def reconnection(args, store):
    from backend import store as store_module
    from backend.models import ScanMeta, ScanStatus, VulnerabilityValidation
    from backend.store.async_ops import shutdown_store_executor
    store_module._store = store
    app = make_app(store, auth_mode=args.auth_mode)
    tasks_before = set(asyncio.all_tasks())
    inventories = asyncio.Queue()
    agent_keys = set()
    agent_count = args.agents or max(args.concurrency)
    for index in range(agent_count):
        session = f"benchmark-process-session-{index}"
        name = f"reconnect-agent-{index}"
        hello = {"name": name, "machine_name": f"reconnect-host-{index}", "agent_session_id": session}
        initial = ControlledAgent(app, hello=hello)
        welcome = await initial.connect()
        assert welcome["agent_key"] not in agent_keys
        agent_keys.add(welcome["agent_key"])
        stamp = "2026-09-07T00:00:00+00:00"
        scan_id, review_id = f"reconnect-scan-{index}", f"reconnect-review-{index}"
        store.save_scan(ScanStatus(scan_id=scan_id, created_at=stamp, status="auditing", progress=0,
            total_candidates=0, processed_candidates=0, vulnerabilities=[]), ScanMeta(scan_items=[],
            created_at=stamp, scan_name=scan_id, agent_id=welcome["agent_id"], agent_key=welcome["agent_key"], agent_name=name))
        revision = store.begin_scan_execution(scan_id, agent_id=welcome["agent_id"], agent_session_id=session)
        store.create_fp_review_job(review_id, scan_id, 1, stamp)
        fp_revision = store.begin_fp_review_execution(review_id, agent_session_id=session)
        store.upsert_vulnerability_validation(scan_id, VulnerabilityValidation(vuln_index=0, status="pending", running=True))
        validation_revision = store.begin_validation_execution(scan_id, 0, agent_session_id=session)
        await initial.close()
        hello.update({"active_scans": [{"scan_id": scan_id, "execution_revision": revision}],
            "active_fp_reviews": [{"scan_id": scan_id, "review_id": review_id, "execution_revision": fp_revision, "item_running": True}],
            "active_validations": [{"scan_id": scan_id, "vuln_index": 0, "execution_revision": validation_revision}]})
        await inventories.put(hello)
    result = {"source": str(args.source.resolve()), "python": sys.version, "database": args.database,
              "active_work_per_agent": {"scans": 1, "fp_reviews": 1, "validations": 1},
              "agents": agent_count, "measurements": []}
    async def operation(i):
        # Each in-flight reconnect belongs to a different Agent process identity.
        hello = await inventories.get()
        agent = ControlledAgent(app, hello=hello)
        try:
            value = await agent.connect()
            assert value["scan_executions"] == hello["active_scans"]
            await agent.heartbeat(i)
            return "adopted+ack"
        finally:
            await agent.close()
            await inventories.put(hello)
    try:
        for concurrency in args.concurrency:
            result["measurements"].append(await measure("active_reconnect", operation, concurrency=concurrency,
                samples=args.samples, warmup=args.warmup, rounds=args.rounds))
    finally:
        pending = set(asyncio.all_tasks()) - tasks_before
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await shutdown_store_executor()
    result["peak_rss_kib"] = peak_rss_kib()
    return result


async def packaging(args, store):
    import httpx
    from backend import store as store_module
    from backend.store.async_ops import shutdown_store_executor
    store_module._store = store
    app = make_app(store, auth_mode=args.auth_mode)
    result = {"source": str(args.source.resolve()), "python": sys.version, "measurements": {}}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bench") as client:
            for name, url in (("runtime_manifest", "/api/agent/runtime/manifest"), ("agent_zip", "/api/agent/download")):
                timings, cpu = [], []
                for i in range(args.rounds + 1):
                    started, cpu_started = time.perf_counter(), time.process_time()
                    response = await client.get(url)
                    if response.status_code != 200:
                        raise RuntimeError(f"{url}: {response.status_code} {response.text[:500]}")
                    timings.append((time.perf_counter() - started) * 1000)
                    cpu.append((time.process_time() - cpu_started) * 1000)
                details = {}
                if name == "agent_zip":
                    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                        details = {"archive_entries": len(archive.infolist()), "uncompressed_bytes": sum(info.file_size for info in archive.infolist())}
                else:
                    payload = response.json()
                    details = {"hash_scope": payload["hash_scope"], "manifest_files": len(payload["manifest"]["files"])}
                result["measurements"][name] = {"first_ms": timings[0], "repeat_median_ms": statistics.median(timings[1:]),
                    "repeat_p95_ms": percentile(timings[1:], .95), "cpu_median_ms": statistics.median(cpu[1:]),
                    "response_bytes": len(response.content), "timings_ms": timings, **details}
                print(json.dumps({name: result["measurements"][name]}), flush=True)
    finally:
        await shutdown_store_executor()
    result["peak_rss_kib"] = peak_rss_kib()
    return result


def contract():
    from fastapi import FastAPI
    from backend.api import scan, agent, integration, sharing
    app = FastAPI()
    for router in (scan.router, agent.router, agent.public_router, integration.router, sharing.router):
        app.include_router(router)
    routes = []
    for registered in app.routes:
        # FastAPI 0.141 defers included routers. Resolve their effective paths
        # only for inspection; application routing itself is left untouched.
        candidates = registered.effective_route_contexts() if hasattr(registered, "effective_route_contexts") else (registered,)
        for route in candidates:
            original = getattr(route, "original_route", route)
            path = route.path or original.path
            if path.startswith(("/openapi", "/docs", "/redoc")):
                continue
            routes.append({"path": path, "methods": sorted(getattr(route, "methods", [])),
                           "name": route.name or original.name, "class": type(original).__name__})
    return {"routes": routes, "openapi": app.openapi()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("all", "http", "ws", "contract", "cross-worker", "worker", "package", "reconnect"), default="all")
    parser.add_argument("--database", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--dsn", default="", help="Fresh disposable database only, required for PostgreSQL")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--tasks", type=int, default=10000)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--scenarios", nargs="+", help="Optional selected HTTP/WS scenarios for repeat checks")
    parser.add_argument("--agents", type=int, help="Reconnect inventory size (default: maximum concurrency)")
    parser.add_argument("--profile-output", type=Path, help="Diagnostic cProfile of one selected HTTP/WS scenario; timings are not comparable")
    parser.add_argument("--auth-mode", choices=("sync", "async"), default="sync", help="Fixed test identity dependency; production dependency is async")
    args = parser.parse_args()
    if min(args.samples, args.rounds, args.tasks, *args.concurrency) < 1 or args.warmup < 0:
        parser.error("Counts must be positive; warmup may be zero")
    if args.agents is not None and args.agents < max(args.concurrency):
        parser.error("--agents must be at least the maximum concurrency")
    if args.profile_output and (len(args.concurrency) != 1 or len(args.scenarios or []) != 1):
        parser.error("Profiling requires exactly one selected scenario and concurrency")
    sys.path.insert(0, str(args.source.resolve()))
    logging.disable(logging.CRITICAL)
    if args.mode == "contract":
        result = contract()
    else:
        with tempfile.TemporaryDirectory(prefix="odh-refactor-bench-") as directory:
            if args.database == "postgres":
                if not args.dsn:
                    parser.error("--dsn is required with --database postgres")
                import psycopg
                with psycopg.connect(args.dsn) as connection:
                    if args.mode != "worker" and connection.execute("SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() LIMIT 1").fetchone():
                        raise RuntimeError("Benchmark target must be an empty disposable database")
                from backend.store.postgres import PostgresScanStore
                store = PostgresScanStore(args.dsn, pool_min_size=1, pool_max_size=4)
            else:
                from backend.store.sqlite import SqliteScanStore
                store = SqliteScanStore(Path(directory) / "scans.db")
            try:
                if args.mode == "worker":
                    asyncio.run(worker(args, store))
                    return
                seed(store, args.tasks)
                if args.mode == "cross-worker":
                    workload = cross_worker
                elif args.mode == "package":
                    workload = packaging
                elif args.mode == "reconnect":
                    workload = reconnection
                else:
                    workload = benchmark
                result = asyncio.run(workload(args, store))
            finally:
                store.close()
    import fastapi, pydantic
    if args.mode != "contract":
        result["auth_mode"] = args.auth_mode
        result["environment"] = {"platform": platform.platform(), "python": sys.version.split()[0],
            "fastapi": fastapi.__version__, "pydantic": pydantic.__version__, "logical_cpus": os.cpu_count()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
