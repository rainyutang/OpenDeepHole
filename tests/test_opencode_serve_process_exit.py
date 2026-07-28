import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


_PROBE_SCRIPT = r"""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

from task_agent import serve_client


async def main():
    marker_path = Path(sys.argv[1])
    grandchild_path = Path(sys.argv[2])
    mode = sys.argv[3]
    child_code = (
        "import subprocess, sys, time; "
        "from pathlib import Path; "
        "grandchild = subprocess.Popen("
        "[sys.executable, '-c', 'import time; time.sleep(300)'], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "Path(sys.argv[1]).write_text(str(grandchild.pid), encoding='utf-8'); "
        "time.sleep(300)"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(grandchild_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    serve_client._register_owned_serve_process(child, marker_path)
    marker_path.write_text(json.dumps({"pid": child.pid}), encoding="utf-8")
    for _ in range(200):
        if grandchild_path.exists():
            break
        await asyncio.sleep(0.01)
    grandchild_pid = int(grandchild_path.read_text(encoding="utf-8"))
    print(f"{child.pid} {grandchild_pid}", flush=True)
    if mode == "wait":
        await asyncio.Event().wait()


asyncio.run(main())
"""


def _pid_is_alive(pid: int) -> bool:
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        fields = stat_path.read_text(encoding="utf-8").split()
    except FileNotFoundError:
        return False
    except OSError:
        fields = []
    if len(fields) > 2 and fields[2] == "Z":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_tree_exit(pids: tuple[int, ...], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(_pid_is_alive(pid) for pid in pids):
            return True
        time.sleep(0.05)
    return not any(_pid_is_alive(pid) for pid in pids)


def _start_probe(tmp_path: Path, mode: str) -> tuple[subprocess.Popen, tuple[int, int], Path]:
    marker_path = tmp_path / f"serve-{mode}.json"
    grandchild_path = tmp_path / f"grandchild-{mode}.txt"
    repo_root = Path(__file__).resolve().parents[1]
    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _PROBE_SCRIPT,
            str(marker_path),
            str(grandchild_path),
            mode,
        ],
        cwd=str(repo_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert parent.stdout is not None
    line = parent.stdout.readline().strip()
    if not line:
        _, stderr = parent.communicate(timeout=10)
        pytest.fail(f"Serve cleanup probe did not start: {stderr}")
    child_pid, grandchild_pid = (int(value) for value in line.split())
    return parent, (child_pid, grandchild_pid), marker_path


def _force_stop_probe(parent: subprocess.Popen, process_tree: tuple[int, int]) -> None:
    if parent.poll() is None:
        parent.kill()
        parent.wait(timeout=5)
    child_pid = process_tree[0]
    if any(_pid_is_alive(pid) for pid in process_tree):
        try:
            os.killpg(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group integration test")
def test_owned_serve_tree_stops_on_normal_interpreter_exit(tmp_path: Path) -> None:
    parent, process_tree, marker_path = _start_probe(tmp_path, "return")
    try:
        _, stderr = parent.communicate(timeout=15)
        assert parent.returncode == 0, stderr
        assert _wait_for_process_tree_exit(process_tree)
        assert not marker_path.exists()
    finally:
        _force_stop_probe(parent, process_tree)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal integration test")
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_owned_serve_tree_stops_before_signal_exit(tmp_path: Path, signum: int) -> None:
    parent, process_tree, marker_path = _start_probe(tmp_path, "wait")
    try:
        os.kill(parent.pid, signum)
        parent.communicate(timeout=15)
        assert parent.returncode != 0
        assert _wait_for_process_tree_exit(process_tree)
        assert not marker_path.exists()
    finally:
        _force_stop_probe(parent, process_tree)
