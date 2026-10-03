"""对外投递管理 HTTP 接口：鉴权、权限矩阵与管理动作。"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from psdline.console.server import ConsoleServer


def _call(base, method, path, token=None, body=None):
    data = json.dumps(body if body is not None else {}).encode()
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_dispatch_admin_auth_matrix(platform):
    server = ConsoleServer(platform, port=0)
    base = server.start()
    try:
        admin = platform.dispatch.issue_token("root", "admin")["token_once"]
        auditor = platform.dispatch.issue_token("ro", "auditor")["token_once"]
        ops = platform.dispatch.issue_token("op", "ops")["token_once"]

        status, _ = _call(base, "GET", "/api/dispatch/status")
        assert status == 401

        status, payload = _call(base, "GET", "/api/dispatch/health")
        assert status == 200

        status, payload = _call(base, "GET", "/api/dispatch/status", token=auditor)
        assert status == 200 and "head_seq" in payload

        status, _ = _call(base, "POST", "/api/dispatch/subscribers", token=auditor,
                          body={"name": "x", "callback": "http://127.0.0.1:1/cb"})
        assert status == 403

        status, _ = _call(base, "POST", "/api/dispatch/tokens", token=ops,
                          body={"label": "t", "scope": "ops"})
        assert status == 403

        status, payload = _call(base, "POST", "/api/dispatch/subscribers", token=admin,
                                body={"name": "ext", "callback": "http://127.0.0.1:1/cb",
                                      "topics": ["door"]})
        assert status == 200 and payload["secret_once"]
        sub_id = payload["subscriber"]["id"]

        status, payload = _call(base, "GET", "/api/dispatch/subscribers", token=ops)
        assert status == 200 and any(item["id"] == sub_id for item in payload["subscribers"])

        status, payload = _call(base, "POST", f"/api/dispatch/subscribers/{sub_id}/pause",
                                token=ops)
        assert status == 200 and payload["subscriber"]["status"] == "paused"

        status, payload = _call(base, "POST", f"/api/dispatch/subscribers/{sub_id}/revoke",
                                token=ops)
        assert status == 403

        status, payload = _call(base, "GET", "/api/dispatch/dead", token=auditor)
        assert status == 200 and payload["dead"] == []
    finally:
        server.stop()


def test_dispatch_routes_listed(platform):
    server = ConsoleServer(platform, port=0)
    try:
        routes = server.dispatch_routes()
        paths = {route["path"] for route in routes}
        assert "/api/dispatch/subscribers" in paths
        assert "/api/dispatch/dead/{subID}/replay" in paths
    finally:
        pass
