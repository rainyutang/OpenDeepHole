import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.frontend import FrontendStaticFiles


@pytest.fixture
def client(tmp_path):
    (tmp_path / "index.html").write_text("<html>browser application</html>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("window.app = true", encoding="utf-8")
    app = FastAPI()

    @app.get("/api/example")
    def example():
        return {"ok": True}

    app.mount("/", FrontendStaticFiles(directory=tmp_path, html=True))
    with TestClient(app) as value:
        yield value


@pytest.mark.parametrize("path", [
    "/", "/login", "/register", "/scans/new", "/scans/s", "/scans/s/issues",
    "/scans/s/mining?engine=threat_audit", "/scans/s/threat?view=attackTrees",
    "/agents/download", "/agents/config?agent=a", "/checkers", "/dashboard", "/admin/users",
    "/shared-scan/s/overview?token=share", "/public-scan/s/fp-review?token=integration",
])
def test_page_paths_load_the_application(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "browser application" in response.text


def test_head_page_request_and_unknown_browser_route(client):
    response = client.head("/scans/s/overview")
    assert response.status_code == 200
    assert response.content == b""
    assert client.get("/unknown-page", headers={"Accept": "text/html"}).status_code == 200
    assert client.get("/scans/s/unknown", headers={"Accept": "text/html"}).status_code == 200


@pytest.mark.parametrize("path", ["/api/missing", "/api", "/assets/missing.js", "/assets/missing", "/missing.css", "/scans/s/missing.js"])
def test_missing_apis_and_assets_do_not_load_html(client, path):
    response = client.get(path, headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert "browser application" not in response.text


def test_existing_resources_and_methods_keep_their_response(client):
    assert client.get("/api/example").json() == {"ok": True}
    response = client.get("/assets/app.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert client.post("/scans/s/overview").status_code == 405


def test_custom_404_document_does_not_disable_page_fallback(tmp_path):
    (tmp_path / "index.html").write_text("application", encoding="utf-8")
    (tmp_path / "404.html").write_text("missing resource", encoding="utf-8")
    app = FastAPI()
    app.mount("/", FrontendStaticFiles(directory=tmp_path, html=True))
    with TestClient(app) as value:
        assert value.get("/scans/s/overview").text == "application"
        response = value.get("/assets/missing.js")
        assert response.status_code == 404
        assert response.text == "missing resource"
