"""Public Scan/Agent contracts captured before the service extraction.

These digests cover the complete JSON schemas (including defaults, errors and
operation IDs) and ordered route names/paths/methods from commit 8158fbf. An
intentional API change must be reviewed and regenerate the contract explicitly:
  python3 scripts/benchmark_backend_refactor.py --mode contract --output contract.json
"""
import hashlib
import json

from scripts.benchmark_backend_refactor import contract


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_scan_agent_openapi_preserves_pre_refactor_contract():
    # Both installed validation environments were captured from the same HEAD:
    # Python 3.12/FastAPI 0.135.3 and cached Python 3.10/FastAPI 0.141.1.
    assert _digest(contract()["openapi"]) in {
        "48c0a60c2897b2342bd9d2e01ad237ec45b8c8b22f5e745500a8ca4d0767e63c",
        "5b1b3964e9a297be9c45b5655509bc8444e49b476e6193b786d219c5bdbdead9",
    }


def test_scan_agent_routes_preserve_order_names_and_methods():
    routes = [{key: row[key] for key in ("path", "methods", "name")} for row in contract()["routes"]]
    assert len(routes) == 209
    assert _digest(routes) == "87da3131922f388c9b5df395a980c8d1f29e91bbb48a87f3397880408b3d573d"


def test_scan_and_agent_reports_keep_historical_route_protection():
    from backend.api import scan, agent
    from backend.report_routes import HistoricalReportRoute
    for router in (scan.router, agent.router):
        for route in router.routes:
            if getattr(route, "methods", None):
                assert isinstance(route, HistoricalReportRoute), route.path
