"""对外投递的管理接口。

所有 ``/api/dispatch/...`` 路径都走令牌鉴权（``Authorization: Bearer <token>``），
分三级权限：``auditor`` 只读、``ops`` 可处理投递与死信、``admin`` 可登记/吊销
与发令牌。健康探针与状态里的非敏感计数不需要令牌。

路由在本模块内做一段式匹配（支持 ``{id}`` 形参），避免改动既有控制台路由器。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..app import Platform
from ..dispatch import SCOPE_ADMIN, SCOPE_AUDITOR, SCOPE_OPS, READ_SCOPES
from ..errors import RailError

PREFIX = "/api/dispatch"

WRITE_SCOPES = (SCOPE_ADMIN, SCOPE_OPS)
ADMIN_SCOPES = (SCOPE_ADMIN,)

Handler = Callable[[dict, dict], dict]


@dataclass(frozen=True)
class AdminRoute:
    method: str
    pattern: str
    scopes: tuple[str, ...]
    handler: str


def _split(path: str) -> list[str]:
    return [part for part in path.strip("/").split("/") if part]


class DispatchAdmin:
    """把带令牌的管理请求翻译成 :class:`DispatchService` 调用。"""

    def __init__(self, platform: Platform) -> None:
        self._platform = platform
        self._routes: list[AdminRoute] = self._register()

    def routes(self) -> list[dict]:
        return [
            {"method": route.method, "path": "/" + route.pattern, "scopes": list(route.scopes)}
            for route in self._routes
        ]

    def handle(
        self, method: str, path: str, query: dict, body: dict, headers: dict
    ) -> tuple[int, dict]:
        """处理一次管理请求，返回 ``(状态码, 响应体)``。"""

        service = self._platform.dispatch
        if service is None:
            return 404, {"error": "not_found", "message": "对外投递未启用"}
        matched = self._match(method, path)
        if matched is None:
            return 404, {"error": "not_found", "path": path}
        route, params = matched
        if route.pattern != "api/dispatch/health":
            token = self._bearer(headers)
            try:
                service.tokens.authenticate(token, route.scopes)
            except RailError as error:
                status = 401 if error.component == "unauthorized" else 403
                return status, {"error": type(error).__name__, **error.as_record()}
        merged = {**query, **params}
        try:
            payload = getattr(self, route.handler)(service, merged, body)
        except RailError as error:
            status = 409 if error.component not in ("console", "dispatch", "unauthorized", "forbidden") else 400
            return status, {"error": type(error).__name__, **error.as_record()}
        except (TypeError, ValueError) as error:
            return 400, {"error": "bad_request", "message": str(error)}
        return 200, payload

    # ---- 路由表 -------------------------------------------------------

    def _register(self) -> list[AdminRoute]:
        r = AdminRoute
        return [
            r("GET", "api/dispatch/health", READ_SCOPES, "_health"),
            r("GET", "api/dispatch/status", READ_SCOPES, "_status"),
            r("GET", "api/dispatch/events", READ_SCOPES, "_events"),
            r("GET", "api/dispatch/history", READ_SCOPES, "_history"),
            r("GET", "api/dispatch/dead", READ_SCOPES, "_dead_list"),
            r("POST", "api/dispatch/dead/{subID}/replay", WRITE_SCOPES, "_dead_replay"),
            r("POST", "api/dispatch/dead/{subID}/discard", ADMIN_SCOPES, "_dead_discard"),
            r("GET", "api/dispatch/subscribers", READ_SCOPES, "_sub_list"),
            r("POST", "api/dispatch/subscribers", ADMIN_SCOPES, "_sub_create"),
            r("GET", "api/dispatch/subscribers/{subID}", READ_SCOPES, "_sub_get"),
            r("POST", "api/dispatch/subscribers/{subID}", WRITE_SCOPES, "_sub_update"),
            r("POST", "api/dispatch/subscribers/{subID}/pause", WRITE_SCOPES, "_sub_pause"),
            r("POST", "api/dispatch/subscribers/{subID}/resume", WRITE_SCOPES, "_sub_resume"),
            r("POST", "api/dispatch/subscribers/{subID}/revoke", ADMIN_SCOPES, "_sub_revoke"),
            r("POST", "api/dispatch/subscribers/{subID}/rotate-secret", ADMIN_SCOPES, "_sub_rotate"),
            r("GET", "api/dispatch/tokens", ADMIN_SCOPES, "_token_list"),
            r("POST", "api/dispatch/tokens", ADMIN_SCOPES, "_token_create"),
            r("POST", "api/dispatch/tokens/{tokenID}/revoke", ADMIN_SCOPES, "_token_revoke"),
            r("POST", "api/dispatch/pump", WRITE_SCOPES, "_pump"),
        ]

    def _match(self, method: str, path: str) -> tuple[AdminRoute, dict] | None:
        segments = _split(path)
        fallback: tuple[AdminRoute, dict] | None = None
        for route in self._routes:
            if route.method != method.upper():
                continue
            pattern = _split("/" + route.pattern)
            if len(pattern) != len(segments):
                continue
            params: dict[str, str] = {}
            ok = True
            for expected, actual in zip(pattern, segments):
                if expected.startswith("{") and expected.endswith("}"):
                    params[expected[1:-1]] = actual
                elif expected != actual:
                    ok = False
                    break
            if ok:
                candidate = (route, params)
                if "{" not in route.pattern:
                    return candidate
                fallback = fallback or candidate
        return fallback

    @staticmethod
    def _bearer(headers: dict) -> str:
        for name, value in headers.items():
            if name.lower() == "authorization" and str(value).startswith("Bearer "):
                return str(value).removeprefix("Bearer ").strip()
        return ""

    # ---- 处理器 -------------------------------------------------------

    def _health(self, service, params: dict, body: dict) -> dict:
        return {"ok": True, "head_seq": service.status()["head_seq"], "dead": service.status()["dead"]}

    def _status(self, service, params: dict, body: dict) -> dict:
        return service.status()

    def _events(self, service, params: dict, body: dict) -> dict:
        return service.events(int(params.get("after_seq", 0)), int(params.get("limit", 100)))

    def _history(self, service, params: dict, body: dict) -> dict:
        return service.history(str(params.get("sub_id", "")), int(params.get("limit", 50)))

    def _dead_list(self, service, params: dict, body: dict) -> dict:
        return service.list_dead(str(params.get("sub_id", "")))

    def _dead_replay(self, service, params: dict, body: dict) -> dict:
        return service.replay_dead(str(params["subID"]), by=self._actor(body))

    def _dead_discard(self, service, params: dict, body: dict) -> dict:
        return service.discard_dead(str(params["subID"]), by=self._actor(body))

    def _sub_list(self, service, params: dict, body: dict) -> dict:
        return {"subscribers": [sub.public_view() for sub in service.subscriptions.list()]}

    def _sub_get(self, service, params: dict, body: dict) -> dict:
        return {"subscriber": service.subscriptions.get(str(params["subID"])).public_view()}

    def _sub_create(self, service, params: dict, body: dict) -> dict:
        name = self._require(body, "name")
        callback = self._require(body, "callback")
        topics = body.get("topics", ("door",))
        if not isinstance(topics, (list, tuple)):
            raise RailError("topics 必须是数组", component="dispatch")
        return service.register_subscriber(
            by=self._actor(body),
            name=name,
            callback=callback,
            topics=tuple(str(item) for item in topics),
            stations=body.get("stations", ()),
            components=body.get("components", ()),
            token=str(body.get("token", "")),
            headers=body.get("headers"),
            rate_per_min=body.get("rate_per_min", 0.0),
            start_seq=int(body.get("start_seq", service.outbox.head_seq)),
        )

    def _sub_update(self, service, params: dict, body: dict) -> dict:
        allowed = {"name", "callback", "topics", "stations", "components", "token", "headers", "rate_per_min"}
        changes = {key: value for key, value in body.items() if key in allowed}
        return service.update_subscriber(str(params["subID"]), by=self._actor(body), **changes)

    def _sub_pause(self, service, params: dict, body: dict) -> dict:
        return service.pause_subscriber(
            str(params["subID"]), by=self._actor(body), reason=str(body.get("reason", ""))
        )

    def _sub_resume(self, service, params: dict, body: dict) -> dict:
        from_seq = body.get("from_seq")
        return service.resume_subscriber(
            str(params["subID"]),
            by=self._actor(body),
            from_seq=int(from_seq) if from_seq is not None else None,
        )

    def _sub_revoke(self, service, params: dict, body: dict) -> dict:
        return service.revoke_subscriber(
            str(params["subID"]), by=self._actor(body), reason=str(body.get("reason", ""))
        )

    def _sub_rotate(self, service, params: dict, body: dict) -> dict:
        return service.rotate_secret(str(params["subID"]), by=self._actor(body))

    def _token_list(self, service, params: dict, body: dict) -> dict:
        return {"tokens": [token.public_view() for token in service.tokens.list()]}

    def _token_create(self, service, params: dict, body: dict) -> dict:
        return service.issue_token(
            self._require(body, "label"),
            str(body.get("scope", SCOPE_OPS)),
            by=self._actor(body),
        )

    def _token_revoke(self, service, params: dict, body: dict) -> dict:
        return service.revoke_token(str(params["tokenID"]), by=self._actor(body))

    def _pump(self, service, params: dict, body: dict) -> dict:
        return service.pump_once()

    @staticmethod
    def _require(body: dict, key: str) -> str:
        value = body.get(key)
        if value is None or str(value) == "":
            raise RailError(f"缺少必填字段 {key!r}", component="dispatch")
        return str(value)

    @staticmethod
    def _actor(body: dict) -> str:
        return str(body.get("_actor", "api"))
