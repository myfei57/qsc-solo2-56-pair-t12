"""对外投递服务门面。

把出箱、订户登记、令牌、投递器装成一条链，并把进程内事件总线作为事件入口：
门控组件照常 ``bus.publish``，这里订阅全量事件、落出箱、扇出投递。服务可随
控制台一起起停（``serve``），也可在测试里只装配不起线程、手动 ``pump_once``。

管理动作（登记/吊销/重投等）全部经平台审计流水留痕，与投递尝试流水一起构成
“订阅、打包、投递、审计”的完整链路。
"""

from __future__ import annotations

import os
from collections.abc import Callable

from ..clock import Clock, SystemClock
from ..eventbus import Event, EventBus
from ..store import JsonStore
from .crypto import load_or_create_master_key
from .dispatcher import Dispatcher
from .ledger import HashJournal
from .model import StoredEvent
from .outbox import OUTBOX_JOURNAL as OUTBOX_NAME, Outbox
from .ratelimit import RateLimiter
from .registry import (
    SUB_JOURNAL,
    TOKEN_JOURNAL,
    SubRegistry,
    TokenRegistry,
)
from .transport import HttpSender, Sender

DISPATCH_DIR = "dispatch"

# 投递子系统自己产生的事件不再回流到出箱，避免自激循环。
INTERNAL_COMPONENTS = frozenset({"dispatch"})


class DispatchService:
    """对外投递整条链的装配与管理入口。"""

    def __init__(
        self,
        store: JsonStore,
        bus: EventBus,
        clock: Clock | None = None,
        *,
        sender: Sender | None = None,
        audit: Callable[[str, str, str, dict], None] | None = None,
        max_attempts: int = 8,
        base_backoff_s: float = 1.0,
        max_backoff_s: float = 300.0,
        request_timeout_s: float = 10.0,
        concurrency: int = 8,
        global_rate_per_min: float = 0.0,
        journal_segment: int = 1024,
        master_key_env: str | None = None,
        ingest_topics: tuple[str, ...] = ("door", "audit"),
    ) -> None:
        self._store = store
        self._bus = bus
        self._clock = clock or SystemClock()
        root = os.path.join(store.root, DISPATCH_DIR)
        self._root = root
        master_key = load_or_create_master_key(os.path.join(root, "master.key"), master_key_env)
        self._sub_journal = HashJournal(root, SUB_JOURNAL, journal_segment)
        self._token_journal = HashJournal(root, TOKEN_JOURNAL, journal_segment)
        self._event_journal = HashJournal(root, OUTBOX_NAME, journal_segment)
        self._attempt_journal = HashJournal(root, "attempts", journal_segment)
        self.subscriptions = SubRegistry(self._clock, self._sub_journal, master_key)
        self.tokens = TokenRegistry(self._clock, self._token_journal)
        self.outbox = Outbox(self._clock, self._event_journal)
        self._limiter = RateLimiter(self._clock)
        self._audit_cb = audit
        self.dispatcher = Dispatcher(
            self.subscriptions,
            self.outbox,
            store,
            self._attempt_journal,
            self._limiter,
            sender or HttpSender(),
            max_attempts=max_attempts,
            base_backoff_s=base_backoff_s,
            max_backoff_s=max_backoff_s,
            request_timeout_s=request_timeout_s,
            concurrency=concurrency,
            global_rate_per_min=global_rate_per_min,
            audit=self._audit_dispatch,
            clock=self._clock,
        )
        self._ingest_topics = set(ingest_topics)
        self._unsubscribe: Callable[[], None] | None = None
        self._started = False

    # ---- 生命周期 -----------------------------------------------------

    def attach(self) -> None:
        """把事件入口挂到总线（幂等）。"""

        if self._unsubscribe is None:
            self._unsubscribe = self._bus.subscribe("*", self._on_event)

    def start(self) -> None:
        """挂总线并启动投递工作线程。"""

        self.attach()
        if not self._started:
            self.dispatcher.start()
            self._started = True

    def stop(self) -> None:
        if self._started:
            self.dispatcher.stop()
            self._started = False
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None

    def pump_once(self, wait_idle: bool = True) -> dict:
        return self.dispatcher.pump_once(wait_idle=wait_idle)

    # ---- 事件入口 -----------------------------------------------------

    def ingest(self, event: Event, *, event_id: str = "") -> tuple[StoredEvent, bool]:
        """把一条事件喂进出箱（测试与补录用）。"""

        return self.outbox.ingest(
            event.topic,
            event.component,
            event.action,
            dict(event.payload),
            event_id=event_id,
        )

    def _on_event(self, event: Event) -> None:
        if event.component in INTERNAL_COMPONENTS:
            return
        if event.topic not in self._ingest_topics:
            return
        # 审计主题下只放行门控链路产生的条目；投递子系统自身的管理审计
        # （登记、吊销、死信等）不回流，避免订户看到内部运维动作。
        if event.topic == "audit" and str(event.action).startswith("dispatch_"):
            return
        try:
            self.outbox.ingest(event.topic, event.component, event.action, dict(event.payload))
        except Exception as error:  # 总线处理器不能打断门控主流程
            self._audit_dispatch("dispatch_ingest_failed", {"error": str(error)})

    # ---- 订户管理 -----------------------------------------------------

    def register_subscriber(self, *, by: str = "bootstrap", **fields: object) -> dict:
        topics_value = fields.get("topics", ("door",))
        topics = tuple(str(item) for item in topics_value) if isinstance(topics_value, (list, tuple)) else ("door",)
        sub, secret = self.subscriptions.register(
            name=str(fields.get("name", "")),
            callback=str(fields.get("callback", "")),
            topics=topics,
            stations=tuple(str(item) for item in fields.get("stations", ())) if isinstance(fields.get("stations"), (list, tuple)) else (),
            components=tuple(str(item) for item in fields.get("components", ())) if isinstance(fields.get("components"), (list, tuple)) else (),
            token=str(fields.get("token", "")),
            headers=fields.get("headers") if isinstance(fields.get("headers"), dict) else None,
            rate_per_min=float(fields.get("rate_per_min", 0.0) or 0.0),
            start_seq=int(fields.get("start_seq", self.outbox.head_seq)),
            created_by=by,
        )
        self.dispatcher.configure_limits(sub)
        self._audit("dispatch_sub_registered", sub.id, "", {"name": sub.name, "by": by})
        return {"subscriber": sub.public_view(), "secret": secret, "secret_once": secret}

    def update_subscriber(self, sub_id: str, *, by: str = "ops", **changes: object) -> dict:
        sub = self.subscriptions.update(sub_id, created_by=by, **changes)
        self.dispatcher.configure_limits(sub)
        self._audit("dispatch_sub_updated", sub_id, "", {"by": by})
        return {"subscriber": sub.public_view()}

    def pause_subscriber(self, sub_id: str, *, by: str = "ops", reason: str = "") -> dict:
        sub = self.subscriptions.set_status(sub_id, "paused", by=by, reason=reason)
        self._audit("dispatch_sub_paused", sub_id, "", {"by": by, "reason": reason})
        return {"subscriber": sub.public_view()}

    def resume_subscriber(self, sub_id: str, *, by: str = "ops", from_seq: int | None = None) -> dict:
        sub = self.subscriptions.set_status(sub_id, "active", by=by)
        if from_seq is not None:
            self.dispatcher.reset_for(sub.id, max(0, from_seq), by=by)
        self.dispatcher.configure_limits(sub)
        self._audit("dispatch_sub_resumed", sub_id, "", {"by": by})
        return {"subscriber": sub.public_view()}

    def revoke_subscriber(self, sub_id: str, *, by: str = "admin", reason: str = "") -> dict:
        sub = self.subscriptions.set_status(sub_id, "revoked", by=by, reason=reason)
        self._audit("dispatch_sub_revoked", sub_id, "", {"by": by, "reason": reason})
        return {"subscriber": sub.public_view()}

    def rotate_secret(self, sub_id: str, *, by: str = "admin") -> dict:
        secret = self.subscriptions.rotate_secret(sub_id, by=by)
        self._audit("dispatch_sub_secret_rotated", sub_id, "", {"by": by})
        return {"subscriber": self.subscriptions.get(sub_id).public_view(), "secret_once": secret}

    # ---- 令牌 ---------------------------------------------------------

    def issue_token(self, label: str, scope: str, *, by: str = "bootstrap") -> dict:
        token, raw = self.tokens.issue(label, scope, created_by=by)
        self._audit("dispatch_token_issued", token.id, "", {"label": label, "scope": scope, "by": by})
        return {"token": token.public_view(), "token_once": raw}

    def revoke_token(self, token_id: str, *, by: str = "admin") -> dict:
        token = self.tokens.revoke(token_id, by=by)
        self._audit("dispatch_token_revoked", token_id, "", {"by": by})
        return {"token": token.public_view()}

    # ---- 死信 ---------------------------------------------------------

    def list_dead(self, sub_id: str = "") -> dict:
        return {"dead": self.dispatcher.dead_letters(sub_id)}

    def replay_dead(self, sub_id: str, *, by: str = "ops") -> dict:
        return self.dispatcher.replay_dead(sub_id, by=by)

    def discard_dead(self, sub_id: str, *, by: str = "admin") -> dict:
        return self.dispatcher.discard_dead(sub_id, by=by)

    # ---- 查询 ---------------------------------------------------------

    def status(self) -> dict:
        summary = self.dispatcher.summary()
        summary["subscribers_view"] = [sub.public_view() for sub in self.subscriptions.list()]
        summary["tokens"] = [token.public_view() for token in self.tokens.list()]
        summary["storage"] = self._root
        return summary

    def history(self, sub_id: str = "", limit: int = 50) -> dict:
        return {"attempts": self.dispatcher.history(sub_id, limit)}

    def events(self, after_seq: int = 0, limit: int = 100) -> dict:
        items = self.outbox.range(after_seq, limit)
        return {"events": [item.core() | {"seq": item.seq} for item in items], "head": self.outbox.head_seq}

    # ---- 审计桥 -------------------------------------------------------

    def _audit(self, kind: str, sub_id: str, station_id: str, detail: dict) -> None:
        if self._audit_cb is not None:
            self._audit_cb(kind, sub_id, station_id, detail)
        # 同时在总线上发一条，平台自己的审计/监控可见。
        self._bus.publish(
            Event.of(
                "dispatch",
                "dispatch",
                kind,
                severity="notice",
                sub_id=sub_id,
                **{k: v for k, v in detail.items() if isinstance(v, (str, int, float, bool))},
            )
        )

    def _audit_dispatch(self, kind: str, detail: dict) -> None:
        if self._audit_cb is not None:
            self._audit_cb(kind, str(detail.get("sub", "")), "", dict(detail))
