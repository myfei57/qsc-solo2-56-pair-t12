"""投递服务门面：把持久化与调度装成一条链，对上承接事件源与管理接口。

职责边界：

* :meth:`ingest` / :meth:`ingest_bus_event` 是唯一事件入口：先落只追加总账
  （同 ``event_id`` 幂等），再由调度器泵给订户。轮询时代的「漏」靠总账序号与
  订户游标兜底，「重」靠投递状态机与 ``Event-ID`` 兜底；
* 订阅、凭据、暂停、重投等所有管理动作都先鉴权（在 HTTP 层），再在此处写
  哈希链审计，审计与状态变化谁都不能只做一半（先审计后改状态，异常会留下
  动作意图）；
* 凭据分三档作用域：``admin`` 全权、``ingest`` 只能推事件、``subscriber`` 只能
  操作自己名下的订户。
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..clock import Clock, SystemClock
from ..errors import RailError
from ..eventbus import Event
from .dispatcher import Dispatcher, aggregate_key
from .security import canonical_json, new_token, sha256_hex
from .store import DEAD, WebhookStore
from .transport import HttpTransport

SCOPE_ADMIN = "admin"
SCOPE_INGEST = "ingest"
SCOPE_SUBSCRIBER = "subscriber"
SCOPES = (SCOPE_ADMIN, SCOPE_INGEST, SCOPE_SUBSCRIBER)

WILDCARD = "*"


@dataclass(frozen=True)
class Principal:
    """鉴权后的调用方。"""

    key_id: str
    scope: str
    name: str
    allowed_topics: tuple[str, ...] = ()
    sub_id: str = ""

    def require_admin(self) -> None:
        if self.scope != SCOPE_ADMIN:
            raise RailError("需要管理员凭据", component="webhook")

    def require_scope(self, *scopes: str) -> None:
        if self.scope not in scopes:
            raise RailError(f"凭据作用域不允许此操作: {self.scope}", component="webhook")

    def owns(self, sub_id: str) -> bool:
        return self.scope == SCOPE_ADMIN or (
            self.scope == SCOPE_SUBSCRIBER and self.sub_id == sub_id
        )

    def require_owns(self, sub_id: str) -> None:
        if not self.owns(sub_id):
            raise RailError("只能操作本凭据名下的订户", component="webhook")


class WebhookService:
    """订阅、打包、投递、审计一条链的对外门面。"""

    def __init__(
        self,
        db_path: str,
        clock: Clock | None = None,
        config=None,
        transport=None,
        unit: str = "psdline",
    ) -> None:
        self._clock = clock or SystemClock()
        self._config = config
        self.store = WebhookStore(db_path)
        if transport is None and config is not None:
            transport = HttpTransport(timeout_s=config.timeout_s)
        kwargs = {"unit": unit}
        if config is not None:
            kwargs.update(
                enqueue_interval_s=config.enqueue_interval_s,
                schedule_interval_s=config.schedule_interval_s,
                lease_s=config.lease_s,
                workers=config.workers,
                max_concurrency_per_sub=config.max_concurrency_per_sub,
                timeout_s=config.timeout_s,
                backoff_base_s=config.backoff_base_s,
                backoff_factor=config.backoff_factor,
                backoff_max_s=config.backoff_max_s,
            )
        self.dispatcher = Dispatcher(self.store, clock=self._clock, transport=transport, **kwargs)
        self._unit = unit
        self._bridge_unsub = None

    # ---- 生命周期 -----------------------------------------------------

    def start(self) -> None:
        self.dispatcher.start()

    def stop(self) -> None:
        if self._bridge_unsub is not None:
            self._bridge_unsub()
            self._bridge_unsub = None
        self.dispatcher.stop()

    def attach_bus(self, bus, topics) -> None:
        """把平台事件总线桥接成投递事件（``door`` 等门控主题）。"""

        topics = tuple(topics)

        def on_event(event: Event) -> None:
            if event.topic in topics or WILDCARD in topics:
                self.ingest_bus_event(event)

        self._bridge_unsub = bus.subscribe(WILDCARD, on_event)

    # ---- 事件入口 -----------------------------------------------------

    def ingest_bus_event(self, event: Event) -> dict:
        """从平台事件总线摄入一条事件（进程内入口）。"""

        payload = dict(event.payload)
        occurred_at = float(payload.pop("_at", self._clock.now()))
        return self.ingest(
            topic=event.topic,
            action=event.action,
            payload=payload,
            source="bus",
            occurred_at=occurred_at,
            audit=False,
        )

    def ingest(
        self,
        topic: str,
        action: str,
        payload: dict,
        *,
        event_id: str = "",
        source: str = "api",
        actor: str = "anonymous",
        occurred_at: float | None = None,
        audit: bool = True,
    ) -> dict:
        """登记一条事件到只追加总账；重复 ``event_id`` 直接返回旧事件（幂等）。"""

        if not topic:
            raise RailError("事件主题不能为空", component="webhook")
        if not isinstance(payload, dict):
            raise RailError("事件负载必须是对象", component="webhook")
        event_id = event_id or f"evt-{uuid.uuid4().hex}"
        now = self._clock.now()
        occurred = self._clock.now() if occurred_at is None else float(occurred_at)
        key = aggregate_key(payload)
        inserted = self.store.insert_event(
            event_id, topic, action or "event", key, occurred, now,
            canonical_json(payload),
            source,
        )
        if inserted and audit:
            self.store.append_audit(
                now, actor, "event_ingested",
                {"event_id": event_id, "topic": topic, "action": action, "source": source},
            )
        return {"event_id": event_id, "inserted": inserted, "seq": self._event_seq(event_id)}

    def ingest_api(self, principal: Principal, body: dict) -> dict:
        """外部推事件入口，要求 ingest/admin 作用域且主题在凭据允许范围内。"""

        principal.require_scope(SCOPE_ADMIN, SCOPE_INGEST)
        topic = str(body.get("topic", ""))
        action = str(body.get("action", "event"))
        payload = body.get("payload", {})
        if not isinstance(payload, dict):
            raise RailError("事件负载必须是对象", component="webhook")
        self._require_topic(principal, topic)
        return self.ingest(
            topic, action, payload,
            event_id=str(body.get("event_id", "")),
            source="ingest-api",
            actor=principal.key_id,
            occurred_at=_optional_float(body.get("occurred_at")),
        )

    def _event_seq(self, event_id: str) -> int:
        event = self.store.get_event(event_id)
        return int(event["seq"]) if event else 0

    # ---- 凭据 ---------------------------------------------------------

    def create_credential(
        self,
        principal: Principal,
        name: str,
        scope: str,
        allowed_topics: list[str] | None = None,
        sub_id: str = "",
    ) -> dict:
        """签发凭据；明文 token 只返回这一次。subscriber 凭据绑定一个订户。"""

        principal.require_admin()
        if not name:
            raise RailError("凭据名称不能为空", component="webhook")
        if scope not in SCOPES:
            raise RailError(f"未知凭据作用域: {scope}", component="webhook")
        if scope == SCOPE_SUBSCRIBER and not sub_id:
            raise RailError("订户凭据必须绑定一个订户", component="webhook")
        if sub_id and self.store.get_subscription(sub_id) is None:
            raise RailError(f"订户不存在: {sub_id}", component="webhook")
        topics = list(allowed_topics or [WILDCARD])
        self._validate_topics(topics)
        token = new_token()
        key_id = f"key-{uuid.uuid4().hex[:12]}"
        self.store.insert_credential(
            key_id, name, scope, sha256_hex(token), topics, self._clock.now(),
            bound_sub_id=sub_id,
        )
        self.store.append_audit(
            self._clock.now(), principal.key_id, "credential_created",
            {"key_id": key_id, "name": name, "scope": scope, "topics": topics,
             "sub_id": sub_id},
        )
        return {"key_id": key_id, "name": name, "scope": scope, "token": token,
                "allowed_topics": topics, "sub_id": sub_id}

    def authenticate(self, token: str) -> Principal | None:
        """按明文令牌解析调用方；不存在或已吊销返回 None。"""

        if not token:
            return None
        record = self.store.get_credential_by_hash(sha256_hex(token))
        if record is None:
            return None
        topics = tuple(_load_topics(record["allowed_topics"]))
        return Principal(
            key_id=record["key_id"], scope=record["scope"], name=record["name"],
            allowed_topics=topics, sub_id=record.get("bound_sub_id", ""),
        )

    def list_credentials(self, principal: Principal) -> dict:
        principal.require_admin()
        records = self.store.list_credentials()
        return {"credentials": [self._credential_view(row) for row in records]}

    def revoke_credential(self, principal: Principal, key_id: str) -> dict:
        principal.require_admin()
        revoked = self.store.revoke_credential(key_id)
        self.store.append_audit(
            self._clock.now(), principal.key_id, "credential_revoked",
            {"key_id": key_id, "revoked": revoked},
        )
        return {"key_id": key_id, "revoked": revoked}

    def _credential_view(self, record: dict) -> dict:
        return {
            "key_id": record["key_id"], "name": record["name"], "scope": record["scope"],
            "allowed_topics": _load_topics(record["allowed_topics"]),
            "sub_id": record.get("bound_sub_id", ""),
            "created_at": record["created_at"], "revoked": bool(record["revoked"]),
        }

    # ---- 订阅 ---------------------------------------------------------

    def create_subscription(self, principal: Principal, body: dict) -> dict:
        """登记一个订户（管理员操作），返回签名密钥与可选 Bearer 凭据。

        订户随后可以：凭返回的 ``secret`` 校验投递签名；或由管理员再签发绑定
        到该订户的 subscriber 凭据，用于查询自己的投递与更新地址。新建订户只收
        「创建之后」的事件（游标取当前最大序号），不追历史，语义明确且不会一
        注册就被历史风暴打满。
        """

        principal.require_admin()
        name = str(body.get("name", ""))
        target_url = str(body.get("target_url", ""))
        topics = list(body.get("topics") or [])
        if not name:
            raise RailError("订户名称不能为空", component="webhook")
        self._validate_url(target_url)
        self._validate_topics(topics)
        max_rate = float(body.get("max_rate", self._default("default_max_rate", 0.0)))
        max_attempts = int(body.get("max_attempts", self._default("default_max_attempts", 8)))
        if max_rate < 0:
            raise RailError("限流不能为负", component="webhook")
        if not 1 <= max_attempts <= 50:
            raise RailError("重试上限必须落在 1..50", component="webhook")
        secret = new_token(24)
        auth_token = str(body.get("auth_token", "")) or new_token(24)
        sub_id = f"sub-{uuid.uuid4().hex[:12]}"
        cursor = self.store.max_event_seq()
        self.store.insert_subscription(
            sub_id, name, target_url, topics, secret, auth_token, max_rate,
            max_attempts, self._clock.now(), principal.key_id, cursor_seq=cursor,
        )
        self.store.append_audit(
            self._clock.now(), principal.key_id, "subscription_created",
            {"sub_id": sub_id, "name": name, "target_url": target_url, "topics": topics,
             "max_rate": max_rate, "max_attempts": max_attempts},
        )
        return self.get_subscription(principal, sub_id, reveal=True)

    def get_subscription(self, principal: Principal, sub_id: str,
                         reveal: bool = False) -> dict:
        record = self.store.get_subscription(sub_id)
        if record is None:
            raise RailError(f"订户不存在: {sub_id}", component="webhook")
        principal.require_owns(sub_id)
        return self._subscription_view(record, reveal=reveal)

    def list_subscriptions(self, principal: Principal) -> dict:
        records = self.store.list_subscriptions()
        if principal.scope == SCOPE_SUBSCRIBER:
            records = [row for row in records if row["sub_id"] == principal.sub_id]
        return {"subscriptions": [self._subscription_view(row) for row in records]}

    def update_subscription(self, principal: Principal, sub_id: str, body: dict) -> dict:
        principal.require_owns(sub_id)
        fields: dict = {}
        subscriber_only = {"name", "target_url"}
        if "name" in body:
            fields["name"] = str(body["name"])
        if "target_url" in body:
            url = str(body["target_url"])
            self._validate_url(url)
            fields["target_url"] = url
        if principal.scope == SCOPE_ADMIN and "topics" in body:
            topics = list(body["topics"])
            self._validate_topics(topics)
            fields["topics"] = topics
        if principal.scope == SCOPE_ADMIN and "max_rate" in body:
            rate = float(body["max_rate"])
            if rate < 0:
                raise RailError("限流不能为负", component="webhook")
            fields["max_rate"] = rate
        if principal.scope == SCOPE_ADMIN and "max_attempts" in body:
            attempts = int(body["max_attempts"])
            if not 1 <= attempts <= 50:
                raise RailError("重试上限必须落在 1..50", component="webhook")
            fields["max_attempts"] = attempts
        requested = set(body)
        if requested - subscriber_only - {"topics", "max_rate", "max_attempts"}:
            raise RailError("包含不允许更新的字段", component="webhook")
        if not fields:
            raise RailError("没有可更新字段（订户凭据只能改名称与投递地址）",
                            component="webhook")
        self.store.update_subscription(sub_id, fields)
        self.store.append_audit(
            self._clock.now(), principal.key_id, "subscription_updated",
            {"sub_id": sub_id, "fields": list(fields)},
        )
        return self.get_subscription(principal, sub_id)

    def pause_subscription(self, principal: Principal, sub_id: str) -> dict:
        principal.require_admin()
        return self._set_status(principal, sub_id, "paused", "subscription_paused")

    def resume_subscription(self, principal: Principal, sub_id: str) -> dict:
        principal.require_admin()
        return self._set_status(principal, sub_id, "active", "subscription_resumed")

    def revoke_subscription(self, principal: Principal, sub_id: str) -> dict:
        principal.require_admin()
        return self._set_status(principal, sub_id, "revoked", "subscription_revoked")

    def _set_status(self, principal: Principal, sub_id: str, status: str,
                    audit_action: str) -> dict:
        if self.store.get_subscription(sub_id) is None:
            raise RailError(f"订户不存在: {sub_id}", component="webhook")
        self.store.set_subscription_status(sub_id, status)
        self.store.append_audit(
            self._clock.now(), principal.key_id, audit_action, {"sub_id": sub_id}
        )
        return self.get_subscription(principal, sub_id)

    def _subscription_view(self, record: dict, reveal: bool = False) -> dict:
        view = {
            "sub_id": record["sub_id"], "name": record["name"],
            "target_url": record["target_url"], "topics": _load_topics(record["topics"]),
            "max_rate": record["max_rate"], "max_attempts": record["max_attempts"],
            "status": record["status"], "cursor_seq": record["cursor_seq"],
            "created_at": record["created_at"], "created_by": record["created_by"],
            "counts": self.store.delivery_counts(record["sub_id"]),
        }
        if reveal:
            view["secret"] = record["secret"]
            view["auth_token"] = record["auth_token"]
        return view

    # ---- 投递查询、死信重投、试投 -------------------------------------

    def list_deliveries(self, principal: Principal, sub_id: str | None,
                        status: str | None, limit: int, after_seq: int) -> dict:
        if sub_id:
            principal.require_owns(sub_id)
        elif principal.scope == SCOPE_SUBSCRIBER:
            sub_id = principal.sub_id
        rows = self.store.list_deliveries(sub_id=sub_id, status=status, limit=limit,
                                          after_seq=after_seq)
        return {"deliveries": [self._delivery_view(row) for row in rows]}

    def get_delivery(self, principal: Principal, delivery_id: str) -> dict:
        row = self.store.get_delivery(delivery_id)
        if row is None:
            raise RailError(f"投递不存在: {delivery_id}", component="webhook")
        principal.require_owns(row["sub_id"])
        view = self._delivery_view(row)
        view["attempts_detail"] = self.store.list_attempts(delivery_id)
        return view

    def replay_delivery(self, principal: Principal, delivery_id: str) -> dict:
        """人工重投一条死信：同一 Event-ID、复用同一投递行。"""

        principal.require_scope(SCOPE_ADMIN, SCOPE_SUBSCRIBER)
        row = self.store.get_delivery(delivery_id)
        if row is None:
            raise RailError(f"投递不存在: {delivery_id}", component="webhook")
        principal.require_owns(row["sub_id"])
        if row["status"] != DEAD:
            raise RailError("只有死信可以人工重投", component="webhook")
        reset = self.store.replay(delivery_id, self._clock.now())
        self.store.append_audit(
            self._clock.now(), principal.key_id, "delivery_replayed",
            {"delivery_id": delivery_id, "sub_id": row["sub_id"],
             "event_id": row["event_id"]},
        )
        return self._delivery_view(reset or row)

    def replay_dead(self, principal: Principal, sub_id: str = "") -> dict:
        target = sub_id or None
        if target:
            principal.require_owns(target)
        elif principal.scope == SCOPE_SUBSCRIBER:
            target = principal.sub_id
        count = self.store.replay_dead(target, self._clock.now())
        self.store.append_audit(
            self._clock.now(), principal.key_id, "dead_bulk_replayed",
            {"sub_id": target or "*", "count": count},
        )
        return {"replayed": count, "sub_id": target or "*"}

    def test_delivery(self, principal: Principal, sub_id: str) -> dict:
        """向订户地址同步发一条探测事件（不进总账、不重试），供登记时验证。"""

        principal.require_owns(sub_id)
        record = self.store.get_subscription(sub_id)
        if record is None:
            raise RailError(f"订户不存在: {sub_id}", component="webhook")
        event_id = f"ping-{uuid.uuid4().hex}"
        fake_delivery = {
            "delivery_id": f"ping-{uuid.uuid4().hex[:12]}",
            "event_id": event_id, "attempts": 1, "secret": record["secret"],
            "auth_token": record["auth_token"], "target_url": record["target_url"],
        }
        event = {
            "event_id": event_id, "seq": 0, "topic": "webhook", "action": "ping",
            "aggregate_key": "test", "occurred_at": self._clock.now(),
            "payload": '{"message":"webhook 连通性探测"}',
        }
        envelope, body = self.dispatcher.build_envelope(fake_delivery, event,
                                                        self._clock.now())
        headers = self.dispatcher.build_headers(fake_delivery, envelope, body)
        outcome = self.dispatcher._transport.send(record["target_url"], body, headers)
        self.store.append_audit(
            self._clock.now(), principal.key_id, "subscription_tested",
            {"sub_id": sub_id, "ok": outcome.ok, "status": outcome.status,
             "error": outcome.error},
        )
        return {"ok": outcome.ok, "status": outcome.status, "error": outcome.error}

    def _delivery_view(self, row: dict) -> dict:
        keys = (
            "delivery_id", "sub_id", "event_id", "seq", "aggregate_key", "status",
            "attempts", "not_before", "last_status", "last_error", "delivered_at",
            "dead_at", "replayed_from", "lease_expires",
        )
        view = {key: row.get(key) for key in keys}
        if "sub_name" in row:
            view["sub_name"] = row["sub_name"]
        return view

    # ---- 事件/审计查询与统计 ------------------------------------------

    def list_events(self, principal: Principal, after_seq: int, limit: int) -> dict:
        principal.require_admin()
        rows = self.store.list_events(after_seq=after_seq, limit=limit)
        return {"events": rows}

    def list_audit(self, principal: Principal, after_id: int, limit: int) -> dict:
        principal.require_scope(SCOPE_ADMIN, SCOPE_SUBSCRIBER)
        rows = self.store.list_audit(limit=limit, after_id=after_id)
        return {"audit": rows}

    def verify_audit(self, principal: Principal) -> dict:
        principal.require_admin()
        return self.store.verify_chain()

    def stats(self) -> dict:
        subs = self.store.list_subscriptions(include_revoked=True)
        return {
            "subscriptions": len(subs),
            "active": sum(1 for row in subs if row["status"] == "active"),
            "events": self.store.max_event_seq(),
            "deliveries": self.store.delivery_counts(),
            "inflight": self.dispatcher.inflight(),
            "audit_chain": self.store.verify_chain(),
            "worker_id": self.dispatcher._worker_id,
        }

    # ---- 校验 ---------------------------------------------------------

    def _validate_url(self, target_url: str) -> None:
        if not target_url:
            raise RailError("投递地址不能为空", component="webhook")
        parts = urlsplit(target_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise RailError("投递地址必须是合法的 http(s) URL", component="webhook")

    def _validate_topics(self, topics: list[str]) -> None:
        if not topics:
            raise RailError("至少选择一个事件主题", component="webhook")
        for item in topics:
            if not isinstance(item, str) or not item:
                raise RailError("事件主题不能为空串", component="webhook")
            if item.count(".") > 1:
                raise RailError(f"事件主题格式非法: {item}", component="webhook")

    def _topic_allowed(self, principal: Principal, topic: str) -> bool:
        return WILDCARD in principal.allowed_topics or topic in principal.allowed_topics

    def _require_topic(self, principal: Principal, topic: str) -> None:
        if principal.scope == SCOPE_ADMIN:
            return
        if not self._topic_allowed(principal, topic):
            raise RailError(f"凭据无权推送主题: {topic}", component="webhook")

    def _default(self, key: str, fallback):
        if self._config is None:
            return fallback
        return getattr(self._config, key, fallback)


def _load_topics(text: str) -> list[str]:
    """读回落盘的主题列表。"""

    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _optional_float(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise RailError("occurred_at 必须是数值时间戳", component="webhook") from error
