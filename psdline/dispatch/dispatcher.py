"""投递调度器：订阅 → 打包 → 投递 → 审计 一条链。

并发模型
    订户之间完全并发（有界线程池 + 全局令牌桶）；同一订户串行严格有序：当前
    序号未确认，后面的事件不发。因此失败的影响被限制在这一个订户的链上。

崩溃安全
    每次“取走（租约）、确认、重试、进死信、人工重投”先写只追加的尝试流水，再
    更新快照（原子替换）。重启时以快照为起点、尝试流水补齐末尾未落快照的动作；
    租约超时未确认视为崩溃中断，自动重新投递。订户按 ``Idempotency-Key`` 去重，
    所以重复投递不会产生第二份效果（见 :mod:`psdline.dispatch.envelope`）。

死信取舍
    由投递方保管：失败上下文、订户配置与审计都在本系统里，运维只需在一处处置。
    订户恢复后人工“重投”即可继续；订户也能通过只读接口自取死信详情。
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from ..clock import Clock, SystemClock
from ..errors import StorageError
from ..store import JsonStore
from .envelope import build_request
from .ledger import GENESIS, HashJournal
from .model import StoredEvent, Subscription
from .outbox import Outbox
from .ratelimit import RateLimiter
from .registry import SubRegistry
from .transport import DeliveryResult, Sender

ATTEMPTS_JOURNAL = "attempts"
STATE_DOC = "dispatch/state"

KIND_LEASE = "leased"
KIND_ACK = "acked"
KIND_RETRY = "retry_scheduled"
KIND_DEAD = "dead"
KIND_REPLAYED = "replayed"
KIND_SKIPPED = "skipped"
LEASE_SECONDS = 60.0


def backoff_delay(attempt: int, base_s: float, cap_s: float) -> float:
    """指数退避：base * 2^(attempt-1)，封顶；首次失败退 base。"""

    delay = base_s * (2 ** max(0, attempt - 1))
    return min(cap_s, max(base_s, delay))


class _Cursor:
    """单个订户的投递游标与故障状态。"""

    def __init__(self, next_seq: int = 0) -> None:
        self.next_seq = next_seq
        self.attempts = 0
        self.not_before = 0.0
        self.lease_deadline = 0.0
        self.last_error = ""
        self.dead: dict | None = None
        self.in_flight: StoredEvent | None = None

    def as_dict(self) -> dict:
        return {
            "next_seq": self.next_seq,
            "attempts": self.attempts,
            "not_before": self.not_before,
            "lease_deadline": self.lease_deadline,
            "last_error": self.last_error,
            "dead": self.dead,
            "in_flight_seq": self.in_flight.seq if self.in_flight else 0,
        }

    @classmethod
    def from_dict(cls, record: dict) -> "_Cursor":
        cursor = cls(next_seq=int(record.get("next_seq", 0)))
        cursor.attempts = int(record.get("attempts", 0))
        cursor.not_before = float(record.get("not_before", 0.0))
        cursor.lease_deadline = float(record.get("lease_deadline", 0.0))
        cursor.last_error = str(record.get("last_error", ""))
        cursor.dead = record.get("dead") if isinstance(record.get("dead"), dict) else None
        return cursor


class Dispatcher:
    """按订阅把出箱事件有序、幂等、可恢复地投出去。"""

    def __init__(
        self,
        registry: SubRegistry,
        outbox: Outbox,
        store: JsonStore,
        attempts: HashJournal,
        limiter: RateLimiter,
        sender: Sender,
        *,
        max_attempts: int = 8,
        base_backoff_s: float = 1.0,
        max_backoff_s: float = 300.0,
        request_timeout_s: float = 10.0,
        lease_seconds: float = LEASE_SECONDS,
        concurrency: int = 8,
        global_rate_per_min: float = 0.0,
        audit: Callable[[str, dict], None] | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._registry = registry
        self._outbox = outbox
        self._store = store
        self._attempts = attempts
        self._limiter = limiter
        self._sender = sender
        self._max_attempts = max(1, max_attempts)
        self._base = max(0.001, base_backoff_s)
        self._cap = max(self._base, max_backoff_s)
        self._timeout = max(0.5, request_timeout_s)
        self._lease_seconds = max(1.0, lease_seconds)
        self._audit = audit
        self._wall = clock or SystemClock()
        self._cursors: dict[str, _Cursor] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition()
        self._pool = threading.Semaphore(max(1, concurrency))
        self._active = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tick_s = 0.2
        self._events_since_snapshot = 0
        self._snapshot_every = 16
        self._limiter.set_global(global_rate_per_min)
        for sub in registry.list():
            self._limiter.configure(sub.id, sub.rate_per_min)
        self._restore()

    # ---- 生命周期 -----------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="dispatch-pump", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        with self._condition:
            self._condition.notify_all()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)

    def pump_once(self, wait_idle: bool = True) -> dict:
        """同步推进（测试与手动触发用）：排空所有当前可发的投递。

        一个 worker 结算后可能放出同订户链上的下一条，因此要反复 pump，
        直到“一整轮没有产生任何新租约且没有在途投递”才算排空。
        """

        deadline = self._wall.monotonic() + 30.0
        while True:
            leased = self._pump()
            if not wait_idle or (leased == 0 and self._active == 0):
                break
            with self._condition:
                while self._active and self._wall.monotonic() < deadline:
                    self._condition.wait(timeout=0.05)
            if self._wall.monotonic() >= deadline and self._active:
                break
        return self.summary()

    # ---- 订户接入 -----------------------------------------------------

    def configure_limits(self, sub: Subscription) -> None:
        with self._lock:
            self._limiter.configure(sub.id, sub.rate_per_min)
            self._cursors.setdefault(sub.id, _Cursor(max(sub.start_seq, 0)))
            self._locks.setdefault(sub.id, threading.Lock())

    def reset_for(self, sub_id: str, start_seq: int, *, by: str = "bootstrap") -> bool:
        """恢复投递时把游标放到指定序号（只用于暂停后恢复/重订）。"""

        with self._lock:
            cursor = self._cursors.get(sub_id) or _Cursor(0)
            previous = cursor.next_seq
            cursor.next_seq = max(0, start_seq)
            cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.lease_deadline = 0.0
            cursor.dead = None
            cursor.last_error = ""
            cursor.in_flight = None
            self._cursors[sub_id] = cursor
        self._attempts.append(
            {"kind": KIND_REPLAYED, "sub": sub_id, "from_seq": previous, "to_seq": start_seq, "by": by}
        )
        self._snapshot()
        self._wake()
        return True

    # ---- 死信处置 -----------------------------------------------------

    def dead_letters(self, sub_id: str = "") -> list[dict]:
        with self._lock:
            items = [
                cursor.dead
                for sid, cursor in self._cursors.items()
                if cursor.dead is not None and (not sub_id or sid == sub_id)
            ]
            return sorted(items, key=lambda item: int(item["event_seq"]))

    def replay_dead(self, sub_id: str, *, by: str = "ops", reset_attempts: bool = True) -> dict:
        """人工重投死信：游标回到死信事件，立即重新投递。"""

        self._registry.require_live(sub_id)
        with self._lock:
            cursor = self._require_cursor(sub_id)
            if cursor.dead is None:
                return {"sub": sub_id, "replayed": False, "reason": "没有死信"}
            event_seq = int(cursor.dead["event_seq"])
            dead = cursor.dead
            cursor.next_seq = event_seq
            if reset_attempts:
                cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.lease_deadline = 0.0
            cursor.dead = None
            cursor.in_flight = None
        self._attempts.append(
            {
                "kind": KIND_REPLAYED,
                "sub": sub_id,
                "from_seq": event_seq,
                "to_seq": event_seq,
                "by": by,
                "previous_attempts": int(dead.get("attempts", 0)),
            }
        )
        self._record("dispatch_dead_replayed", sub=sub_id, event_seq=event_seq, by=by)
        self._snapshot()
        self._wake()
        self.pump_once()
        return {"sub": sub_id, "replayed": True, "event_seq": event_seq}

    def discard_dead(self, sub_id: str, *, by: str = "ops") -> dict:
        """人工放弃死信（管理动作，需 admin）：游标越过该事件继续后续投递。"""

        with self._lock:
            cursor = self._require_cursor(sub_id)
            if cursor.dead is None:
                return {"sub": sub_id, "discarded": False, "reason": "没有死信"}
            event_seq = int(cursor.dead["event_seq"])
            self._attempts.append(
                {"kind": "dead_discarded", "sub": sub_id, "event_seq": event_seq, "by": by}
            )
            cursor.next_seq = event_seq + 1
            cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.lease_deadline = 0.0
            cursor.dead = None
            cursor.in_flight = None
        self._record("dispatch_dead_discarded", sub=sub_id, event_seq=event_seq, by=by)
        self._snapshot()
        self._wake()
        return {"sub": sub_id, "discarded": True, "event_seq": event_seq}

    # ---- 状态 ---------------------------------------------------------

    def summary(self) -> dict:
        with self._lock:
            per_sub: dict[str, dict] = {}
            in_flight_total = 0
            dead_total = 0
            delivered = 0
            for sub_id, cursor in self._cursors.items():
                if cursor.in_flight is not None or cursor.lease_deadline > self._wall.now():
                    in_flight_total += 1
                if cursor.dead is not None:
                    dead_total += 1
                delivered += max(0, cursor.next_seq - self._start_seq(sub_id))
                per_sub[sub_id] = {
                    "next_seq": cursor.next_seq,
                    "attempts": cursor.attempts,
                    "not_before": cursor.not_before,
                    "in_flight": cursor.in_flight.seq if cursor.in_flight else 0,
                    "last_error": cursor.last_error,
                    "dead_seq": cursor.dead["event_seq"] if cursor.dead else 0,
                }
            head = self._outbox.head_seq
            pending = sum(max(0, head - item["next_seq"]) + (1 if item["in_flight"] else 0) for item in per_sub.values())
            return {
                "head_seq": head,
                "subscribers": len(self._cursors),
                "in_flight": in_flight_total,
                "dead": dead_total,
                "delivered_advanced": delivered,
                "pending": pending,
                "active_workers": self._active,
                "attempts_logged": self._attempts.count,
                "per_subscriber": per_sub,
            }

    def history(self, sub_id: str = "", limit: int = 50) -> list[dict]:
        """读取投递尝试流水（审计链），可按订户过滤。"""

        records = self._attempts.replay()
        filtered = [item for item in records if not sub_id or item.get("sub") == sub_id]
        return filtered[-max(1, limit) :]

    # ---- 主循环 -------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            self._pump()
            with self._condition:
                self._condition.wait(timeout=self._tick_s)

    def _wake(self) -> None:
        with self._condition:
            self._condition.notify_all()

    def _pump(self) -> int:
        """扫描所有订户并派发到期投递，返回本轮新发出的租约数。"""

        now = self._wall.now()
        leased = 0
        for sub in self._registry.list():
            if not sub.is_live():
                continue
            self.configure_limits(sub)
            with self._lock:
                cursor = self._cursors[sub.id]
                lock = self._locks[sub.id]
                busy = cursor.in_flight is not None
                # 活进程里只要有在途投递就绝不重派，哪怕回调很慢：
                # 结果要么由 worker 结算，要么由进程崩溃后的重启恢复。
                due = cursor.not_before <= now
                blocked = cursor.dead is not None
                event = self._next_event(sub, cursor)
            if busy or not due or blocked or event is None:
                continue
            if not lock.acquire(blocking=False):
                continue
            leased = False
            try:
                with self._lock:
                    if cursor.in_flight is not None:
                        continue
                    self._lease(sub, cursor, event)
                    leased = True
                self._pool.acquire()
                with self._condition:
                    self._active += 1
                    self._condition.notify_all()
                thread = threading.Thread(
                    target=self._deliver_guarded, args=(sub.id, event.seq), daemon=True
                )
                thread.start()
                leased += 1
            finally:
                lock.release()
        return leased
    def _next_event(self, sub: Subscription, cursor: _Cursor) -> StoredEvent | None:
        """返回订户关心的下一条事件；不关心的事件游标直接越过，不卡住链路。"""

        head = self._outbox.head_seq
        advanced = False
        while cursor.next_seq < head:
            event = self._outbox.get(cursor.next_seq + 1)
            if sub.matches(event):
                if advanced:
                    self._persist_skips(sub.id, cursor.next_seq)
                return event
            cursor.next_seq = event.seq
            advanced = True
        if advanced:
            self._persist_skips(sub.id, cursor.next_seq)
        return None

    def _persist_skips(self, sub_id: str, seq: int) -> None:
        """把“越过不关心事件”落流水，重启后无需重复扫描全量出箱。"""

        self._attempts.append(
            {"kind": KIND_SKIPPED, "sub": sub_id, "event_seq": seq, "at": self._wall.now()}
        )
        self._snapshot()

    def _start_seq(self, sub_id: str) -> int:
        sub = self._lookup(sub_id)
        return sub.start_seq if sub else 0

    def _lookup(self, sub_id: str) -> Subscription | None:
        try:
            return self._registry.get(sub_id)
        except Exception:
            return None

    def _lease(self, sub: Subscription, cursor: _Cursor, event: StoredEvent) -> None:
        cursor.in_flight = event
        cursor.lease_deadline = self._wall.now() + self._lease_seconds
        self._attempts.append(
            {
                "kind": KIND_LEASE,
                "sub": sub.id,
                "event_seq": event.seq,
                "event_id": event.id,
                "at": self._wall.now(),
                "lease_seconds": self._lease_seconds,
                "attempt": cursor.attempts + 1,
            }
        )
        # 租约已在只追加流水里持久化；快照节流写入即可，崩溃后靠流水恢复。

    def _deliver_guarded(self, sub_id: str, event_seq: int) -> None:
        try:
            self._deliver(sub_id, event_seq)
        except Exception as error:  # 工作线程绝不能把异常吞出进程
            self._record("dispatch_worker_error", sub=sub_id, event_seq=event_seq, error=str(error))
        finally:
            self._pool.release()
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def _deliver(self, sub_id: str, event_seq: int) -> None:
        sub = self._lookup(sub_id)
        if sub is None:
            return
        try:
            event = self._outbox.get(event_seq)
        except KeyError:
            return
        body, headers = build_request(sub, event)
        if not self._limiter.acquire(sub_id, timeout=self._timeout * 2):
            result = DeliveryResult(ok=False, kind="retry", reason="rate_limited")
        else:
            result = self._sender.post(sub.callback, body, headers, self._timeout)
        with self._lock:
            cursor = self._require_cursor(sub_id)
            if cursor.in_flight is None or cursor.in_flight.seq != event_seq:
                return  # 已被恢复路径接管，迟到结果丢弃
            self._settle(sub, cursor, event, result)

    def _settle(
        self,
        sub: Subscription,
        cursor: _Cursor,
        event: StoredEvent,
        result: DeliveryResult,
    ) -> None:
        now = self._wall.now()
        base = {
            "sub": sub.id,
            "event_seq": event.seq,
            "event_id": event.id,
            "at": now,
            "status": result.status,
            "reason": result.reason,
        }
        cursor.in_flight = None
        cursor.lease_deadline = 0.0
        cursor.last_error = "" if result.ok else result.reason
        if result.ok:
            cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.next_seq = event.seq
            self._attempts.append({**base, "kind": KIND_ACK})
        elif result.permanent:
            cursor.attempts += 1
            self._mark_dead(sub, cursor, event, result.reason, permanent=True)
        else:
            cursor.attempts += 1
            if cursor.attempts >= self._max_attempts:
                self._mark_dead(sub, cursor, event, result.reason, permanent=False)
            else:
                cursor.not_before = now + backoff_delay(cursor.attempts, self._base, self._cap)
                self._attempts.append(
                    {
                        **base,
                        "kind": KIND_RETRY,
                        "attempt": cursor.attempts,
                        "not_before": cursor.not_before,
                    }
                )
                self._record(
                    "dispatch_retry",
                    sub=sub.id,
                    event_seq=event.seq,
                    attempt=cursor.attempts,
                    reason=result.reason,
                )
        self._snapshot()
        self._wake()

    def _mark_dead(
        self, sub: Subscription, cursor: _Cursor, event: StoredEvent, reason: str, *, permanent: bool
    ) -> None:
        record = {
            "sub": sub.id,
            "sub_name": sub.name,
            "callback": sub.callback,
            "event_seq": event.seq,
            "event_id": event.id,
            "topic": event.topic,
            "attempts": cursor.attempts + (0 if permanent else 0),
            "reason": reason,
            "permanent": permanent,
            "dead_at": self._wall.now(),
        }
        cursor.dead = record
        cursor.not_before = 0.0
        self._attempts.append(
            {
                "kind": KIND_DEAD,
                "sub": sub.id,
                "event_seq": event.seq,
                "event_id": event.id,
                "attempt": cursor.attempts,
                "reason": reason,
                "permanent": permanent,
                "at": record["dead_at"],
            }
        )
        self._record(
            "dispatch_dead",
            sub=sub.id,
            event_seq=event.seq,
            attempts=cursor.attempts,
            reason=reason,
            permanent=permanent,
        )

    # ---- 快照与恢复 ---------------------------------------------------

    def _require_cursor(self, sub_id: str) -> _Cursor:
        cursor = self._cursors.get(sub_id)
        if cursor is None:
            cursor = _Cursor(0)
            self._cursors[sub_id] = cursor
            self._locks.setdefault(sub_id, threading.Lock())
        return cursor

    def _snapshot(self, *, force: bool = False) -> None:
        self._events_since_snapshot += 1
        if not force and self._events_since_snapshot < self._snapshot_every:
            return
        payload = {
            "version": 1,
            "written_at": self._wall.now(),
            "head_seq": self._outbox.head_seq,
            "attempts_count": self._attempts.count,
            "attempts_tail": self._attempts.tail,
            "cursors": {sub_id: cursor.as_dict() for sub_id, cursor in self._cursors.items()},
        }
        self._store.write(STATE_DOC, payload)
        self._events_since_snapshot = 0

    def _restore(self) -> None:
        snapshot = self._store.read(STATE_DOC)
        cursors: dict[str, _Cursor] = {}
        attempts_seen = 0
        if isinstance(snapshot, dict):
            for sub_id, item in snapshot.get("cursors", {}).items():
                if isinstance(item, dict):
                    cursors[str(sub_id)] = _Cursor.from_dict(item)
            attempts_seen = int(snapshot.get("attempts_count", 0))
        records = self._attempts.replay()
        if len(records) < attempts_seen:
            raise StorageError(
                "投递尝试流水比快照更短：历史文件被截断或更换", component="dispatch"
            )
        if (
            isinstance(snapshot, dict)
            and len(records) == attempts_seen
            and snapshot.get("attempts_tail", GENESIS) != self._attempts.tail
        ):
            raise StorageError("投递快照对应的尝试流水尾部不匹配（历史被改写）", component="dispatch")
        for record in records[attempts_seen:]:
            self._apply_record(cursors, record)
        # 快照里若有在途租约（最后一次快照后崩溃），一律作废重投：订户按
        # Idempotency-Key 幂等，重复投递无副作用。
        for cursor in cursors.values():
            cursor.in_flight = None
            cursor.lease_deadline = 0.0
        for sub in self._registry.list():
            cursors.setdefault(sub.id, _Cursor(max(sub.start_seq, 0)))
        with self._lock:
            self._cursors = cursors
            self._locks = {sub_id: threading.Lock() for sub_id in cursors}
        if not isinstance(snapshot, dict):
            self._snapshot(force=True)

    def _apply_record(self, cursors: dict[str, _Cursor], record: dict) -> None:
        kind = str(record.get("kind"))
        sub_id = str(record.get("sub", ""))
        cursor = cursors.setdefault(sub_id, _Cursor(0))
        seq = int(record.get("event_seq", 0))
        if kind == KIND_ACK:
            cursor.next_seq = max(cursor.next_seq, seq)
            cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.dead = None
        elif kind == KIND_RETRY:
            cursor.attempts = int(record.get("attempt", cursor.attempts))
            cursor.not_before = float(record.get("not_before", 0.0))
        elif kind == KIND_DEAD:
            cursor.attempts = int(record.get("attempt", cursor.attempts))
            cursor.not_before = 0.0
            sub = self._lookup(sub_id)
            cursor.dead = {
                "sub": sub_id,
                "sub_name": sub.name if sub else "",
                "callback": sub.callback if sub else "",
                "event_seq": seq,
                "event_id": str(record.get("event_id", "")),
                "topic": str(record.get("topic", "")),
                "attempts": cursor.attempts,
                "reason": str(record.get("reason", "")),
                "permanent": bool(record.get("permanent", False)),
                "dead_at": float(record.get("at", 0.0)),
            }
        elif kind == KIND_REPLAYED:
            cursor.next_seq = int(record.get("to_seq", cursor.next_seq))
            cursor.attempts = 0
            cursor.not_before = 0.0
            cursor.dead = None
        elif kind == KIND_SKIPPED:
            cursor.next_seq = max(cursor.next_seq, seq)
        elif kind == "dead_discarded":
            if cursor.dead and int(cursor.dead.get("event_seq", 0)) == seq:
                cursor.dead = None
            cursor.next_seq = max(cursor.next_seq, seq + 1)
            cursor.attempts = 0
            cursor.not_before = 0.0

    # ---- 审计 ---------------------------------------------------------

    def _record(self, kind: str, **detail: object) -> None:
        if self._audit is not None:
            try:
                self._audit(kind, detail)
            except Exception:
                pass
