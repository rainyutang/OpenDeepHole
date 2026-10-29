"""Serve the browser application without hiding API or asset errors."""

import re
from pathlib import PurePosixPath

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope


_PAGE_PATH = re.compile(
    r"^(?:login|register|dashboard|checkers|admin/users|agents/(?:download|config)"
    r"|(?:scans|shared-scan|public-scan)/[^/]+(?:/(?:overview|index|static|threat|mining|validation|fp-review|issues))?)/?$"
)


class FrontendStaticFiles(StaticFiles):
    def _is_page_request(self, path: str, scope: Scope) -> bool:
        if scope["method"] not in {"GET", "HEAD"}:
            return False
        path = path.strip("/")
        if path.split("/", 1)[0] in {"api", "assets"} or PurePosixPath(path).suffix:
            return False
        return bool(_PAGE_PATH.fullmatch(path)) or "text/html" in Headers(scope=scope).get("accept", "")

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or not self._is_page_request(path, scope):
                raise
        else:
            if response.status_code != 404 or not self._is_page_request(path, scope):
                return response
        return await super().get_response("index.html", scope)
