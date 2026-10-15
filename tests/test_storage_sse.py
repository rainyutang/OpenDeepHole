from backend import sse


def test_pool_notifications_keep_live_task_identity_without_bodies():
    queued = {"task_id": "queued", "request_id": "queued", "revision": 2,
              "queued_at": "2026-10-15T00:00:00Z", "prompt_length": 100000,
              "prompt": "x" * 100000, "session_events": [{"content": "y" * 100000}]}
    planned = {"planned_task_id": "planned", "planned_at": "2026-10-15T00:00:00Z"}
    active = {**queued, "task_id": "running", "execution_kind": "scan", "execution_id": "s",
              "execution_revision": 3, "agent_session_id": "agent", "serve_session_id": "session"}
    payload = {"opencode_pool": {"queued_tasks": [queued], "planned_tasks": [planned],
                                "models": [{"id": "m", "active_tasks": [active]}]}}
    event, data = sse.storage_notification("scan_status", payload)
    assert event == "scan_status"
    pool = data["opencode_pool"]
    assert pool["planned_tasks"] == [planned]
    for actual, original in ((pool["queued_tasks"][0], queued), (pool["models"][0]["active_tasks"][0], active)):
        assert actual == {key: value for key, value in original.items() if key not in {"prompt", "session_events"}}
    assert payload["opencode_pool"]["queued_tasks"][0]["prompt"] == "x" * 100000
    # Local delivery can project an already-projected durable notification.
    assert sse.storage_notification(event, data) == (event, data)


def test_durable_notifications_strip_bodies_and_overflow_requests_resync():
    queue = sse.subscribe("storage-sse")
    try:
        sse.configure_distributed_sse(None, "")
        sse.publish("storage-sse", "scan_vulnerability", {"index": 42, "vulnerability": {"vulnerability_report": "body" * 100000}})
        assert queue.get_nowait()["data"] == {"resource": "vulnerabilities", "index": 42}
        for _ in range(201):
            sse.publish_local("storage-sse", "scan_event", {"event": {"message": "status"}})
        assert queue.get_nowait()["event"] == "resync_required"
    finally:
        sse.unsubscribe("storage-sse", queue)


def test_distributed_event_is_not_visible_before_durable_commit():
    class Store:
        distributed = True
    queue = sse.subscribe("storage-sse")
    try:
        sse.configure_distributed_sse(Store(), "w")
        sse.publish("storage-sse", "scan_finish", {"status": "complete"})
        assert queue.empty()
        assert sse._distributed_event_queue.qsize() == 1
    finally:
        sse.configure_distributed_sse(None, "")
        sse.unsubscribe("storage-sse", queue)
