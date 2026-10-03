"""投递服务 HTTP 边界。

与内部控制台（``/api/...``）完全隔离，单独监听一个端口，只暴露对外投递需要的
接口。鉴权统一为 ``Authorization: Bearer <token>``，token 不存明文、只认哈希；
作用域（admin/ingest/subscriber）在 :class:`~psdline.webhook.service.Principal`
上强制，subscriber 只能触达自己名下的订户。
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ..errors import RailError
from .service import Principal, WebhookService

_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class WebhookRouter:
    """极简路径模板路由（``/v1/subs/{subID}``）。"""

    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern, list[str], object]] = []

    def add(self, method: str, template: str, handler) -> None:
        names = _PARAM.findall(template)
        pattern = re.compile("^" + _PARAM.sub(r"(?P<\1>[^/]+)", template) + "$")
        self._routes.append((method, pattern, names, handler))

    def match(self, method: str, path: str):
        for route_method, pattern, _names, handler in self._routes:
            if route_method != method:
                continue
            matched = pattern.match(path)
            if matched:
                return handler, matched.groupdict()
        return None


class WebhookApi:
    """把 HTTP 请求翻译成 :class:`WebhookService` 调用并统一鉴权。"""

    def __init__(self, service: WebhookService) -> None:
        self._service = service
        self._router = WebhookRouter()
        self._register()

    @property
    def service(self) -> WebhookService:
        return self._service

    def _register(self) -> None:
        add = self._router.add
        add("GET", "/healthz", lambda p, b, q, who: {"ok": True})

        add("POST", "/v1/events", self._ingest)

        add("POST", "/v1/subs", self._create_sub)
        add("GET", "/v1/subs", self._list_subs)
        add("GET", "/v1/subs/{subID}", self._get_sub)
        add("POST", "/v1/subs/{subID}", self._update_sub)
        add("POST", "/v1/subs/{subID}/pause", self._pause_sub)
        add("POST", "/v1/subs/{subID}/resume", self._resume_sub)
        add("DELETE", "/v1/subs/{subID}", self._revoke_sub)
        add("POST", "/v1/subs/{subID}/test", self._test_sub)
        add("GET", "/v1/subs/{subID}/deliveries", self._list_deliveries)
        add("POST", "/v1/subs/{subID}/replay-dead", self._replay_dead)

        add("GET", "/v1/deliveries", self._list_all_deliveries)
        add("GET", "/v1/deliveries/{deliveryID}", self._get_delivery)
        add("POST", "/v1/deliveries/{deliveryID}/replay", self._replay_delivery)

        add("POST", "/v1/credentials", self._create_credential)
        add("GET", "/v1/credentials", self._list_credentials)
        add("POST", "/v1/credentials/{keyID}/revoke", self._revoke_credential)

        add("GET", "/v1/events", self._list_events)
        add("GET", "/v1/audit", self._list_audit)
        add("POST", "/v1/audit/verify", self._verify_audit)
        add("GET", "/v1/stats", self._stats)

    def handle(self, method: str, path: str, query: dict, body: dict,
               headers) -> tuple[int, dict]:
        matched = self._router.match(method, path)
        if matched is None:
            return 404, {"error": "not_found", "path": path}
        handler, params = matched
        if path != "/healthz":
            principal = self._authenticate(headers)
            if principal is None:
                return 401, {"error": "unauthorized", "message": "缺少或无效的凭据"}
        else:
            principal = Principal(key_id="anonymous", scope="", name="anonymous")
        try:
            payload = handler(params, body, query, principal)
        except RailError as error:
            status = 403 if error.message.startswith(("需要", "只能", "凭据")) else 400
            if error.component == "webhook" and "无权" in error.message:
                status = 403
            if "不存在" in error.message:
                status = 404
            if "只有死信" in error.message:
                status = 409
            return status, {"error": type(error).__name__, "message": error.message,
                            "component": error.component}
        except (TypeError, ValueError) as error:
            return 400, {"error": "bad_request", "message": str(error)}
        return 200, payload

    def _authenticate(self, headers) -> Principal | None:
        raw = headers.get("Authorization", "")
        if not raw.startswith("Bearer "):
            return None
        return self._service.authenticate(raw[len("Bearer "):].strip())

    # ---- 事件 ---------------------------------------------------------

    def _ingest(self, params, body, query, who: Principal) -> dict:
        events = body.get("events")
        if isinstance(events, list):
            who.require_scope(SCOPE_ADMIN, SCOPE_INGEST)
            results = [self._service.ingest_api(who, item) for item in events
                       if isinstance(item, dict)]
            return {"accepted": len(results), "events": results}
        return self._service.ingest_api(who, body)

    # ---- 订户 ---------------------------------------------------------

    def _create_sub(self, params, body, query, who: Principal) -> dict:
        return self._service.create_subscription(who, body)

    def _list_subs(self, params, body, query, who: Principal) -> dict:
        return self._service.list_subscriptions(who)

    def _get_sub(self, params, body, query, who: Principal) -> dict:
        return {"subscription": self._service.get_subscription(who, params["subID"])}

    def _update_sub(self, params, body, query, who: Principal) -> dict:
        return {"subscription": self._service.update_subscription(
            who, params["subID"], body)}

    def _pause_sub(self, params, body, query, who: Principal) -> dict:
        return {"subscription": self._service.pause_subscription(who, params["subID"])}

    def _resume_sub(self, params, body, query, who: Principal) -> dict:
        return {"subscription": self._service.resume_subscription(who, params["subID"])}

    def _revoke_sub(self, params, body, query, who: Principal) -> dict:
        return {"subscription": self._service.revoke_subscription(who, params["subID"])}

    def _test_sub(self, params, body, query, who: Principal) -> dict:
        return self._service.test_delivery(who, params["subID"])

    def _list_deliveries(self, params, body, query, who: Principal) -> dict:
        return self._service.list_deliveries(
            who, params["subID"], query.get("status"),
            _as_int(query, "limit", 100), _as_int(query, "after_seq", 0))

    def _replay_dead(self, params, body, query, who: Principal) -> dict:
        return self._service.replay_dead(who, params["subID"])

    # ---- 投递 ---------------------------------------------------------

    def _list_all_deliveries(self, params, body, query, who: Principal) -> dict:
        who.require_scope(SCOPE_ADMIN, SCOPE_SUBSCRIBER)
        sub_id = query.get("sub_id") if who.scope == SCOPE_ADMIN else who.sub_id
        return self._service.list_deliveries(
            who, sub_id, query.get("status"),
            _as_int(query, "limit", 100), _as_int(query, "after_seq", 0))

    def _get_delivery(self, params, body, query, who: Principal) -> dict:
        return {"delivery": self._service.get_delivery(who, params["deliveryID"])}

    def _replay_delivery(self, params, body, query, who: Principal) -> dict:
        return {"delivery": self._service.replay_delivery(who, params["deliveryID"])}

    # ---- 凭据 ---------------------------------------------------------

    def _create_credential(self, params, body, query, who: Principal) -> dict:
        return self._service.create_credential(
            who,
            str(body.get("name", "")),
            str(body.get("scope", "")),
            list(body.get("allowed_topics") or []),
            str(body.get("sub_id", "")),
        )

    def _list_credentials(self, params, body, query, who: Principal) -> dict:
        return self._service.list_credentials(who)

    def _revoke_credential(self, params, body, query, who: Principal) -> dict:
        return self._service.revoke_credential(who, params["keyID"])

    # ---- 事件/审计/统计 -----------------------------------------------

    def _list_events(self, params, body, query, who: Principal) -> dict:
        return self._service.list_events(
            who, _as_int(query, "after_seq", 0), _as_int(query, "limit", 100))

    def _list_audit(self, params, body, query, who: Principal) -> dict:
        return self._service.list_audit(
            who, _as_int(query, "after_id", 0), _as_int(query, "limit", 100))

    def _verify_audit(self, params, body, query, who: Principal) -> dict:
        return self._service.verify_audit(who)

    def _stats(self, params, body, query, who: Principal) -> dict:
        if who.scope == SCOPE_SUBSCRIBER:
            sub = self._service.store.get_subscription(who.sub_id)
            if sub is None:
                raise RailError("订户不存在", component="webhook")
            view = self._service.get_subscription(who, who.sub_id)
            return {"sub_id": who.sub_id, "counts": view["counts"],
                    "inflight": self._service.dispatcher.inflight()}
        return self._service.stats()


def _as_int(query: dict, key: str, default: int) -> int:
    raw = query.get(key)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except (TypeError, ValueError) as error:
        raise RailError(f"参数 {key!r} 必须是整数", component="webhook") from error


class _Handler(BaseHTTPRequestHandler):
    server_version = "psdline-webhook/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # 访问审计在 API 层按动作落哈希链，这里不刷 stderr。
        return

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self._respond(400, {"error": "bad_request", "message": "请求体不是合法 JSON"})
            return
        if not isinstance(body, dict):
            body = {}
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        status, payload = self.server.api.handle(  # type: ignore[attr-defined]
            method, parsed.path, query, body, self.headers
        )
        self._respond(status, payload)

    def _respond(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _WebhookHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], api: WebhookApi) -> None:
        super().__init__(address, _Handler)
        self.api = api


class WebhookServer:
    """投递服务 HTTP 的起停封装（后台线程）。"""

    def __init__(self, service: WebhookService, host: str = "127.0.0.1",
                 port: int = 8090) -> None:
        self._service = service
        self._host = host
        self._port = port
        self._api = WebhookApi(service)
        self._server: _WebhookHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def api(self) -> WebhookApi:
        return self._api

    @property
    def port(self) -> int:
        if self._server is None:
            return self._port
        return int(self._server.server_address[1])

    def start(self) -> str:
        if self._server is not None:
            return self.base_url()
        self._server = _WebhookHTTPServer((self._host, self._port), self._api)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="psdline-webhook-http", daemon=True
        )
        self._thread.start()
        return self.base_url()

    def base_url(self) -> str:
        host = self._host if self._host not in ("0.0.0.0", "") else "127.0.0.1"
        return f"http://{host}:{self.port}"

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
