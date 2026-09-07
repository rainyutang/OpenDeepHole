from backend import sse


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
