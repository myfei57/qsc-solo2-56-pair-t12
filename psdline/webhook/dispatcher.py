"""打包与投递调度：入队循环、租约认领、退避重试、死信。

并发模型（崩溃安全 + 部分失败恢复的关键）：

* **入队循环**周期性把事件总账泵入每个 active 订户的 ``deliveries``，读游标与
  建待投行在同一个 ``BEGIN IMMEDIATE`` 事务里，崩溃只会整批重做；
* **调度循环**先回收超时租约（崩溃 worker 的 leased 回 pending），再从到期
  pending 里选候选：同一订户不超过其并发上限，同一聚合键已有在途投递时跳过
  （后到的留给下一拍），保证每键有序、不同键并发；
* **worker** 条件认领（pending 才认领、尝试数即 fencing token），投完带 token
  落库；worker 崩溃后旧 token 失效，迟到结果不会二次落库——同一条事件不会因为
  重试产生第二份投递，订户再按 ``Event-ID`` 去重即效果恰好一次；
* 失败按指数退避 + 全抖动调度下一次，超过订户重试上限（或 410）进死信，等
  人工通过管理接口重投，重投不换 ``Event-ID``。
"""

from __future__ import annotations

import json
import os
import random
import threading
import uuid

from ..clock import Clock, SystemClock
from .ratelimit import RateLimiter
from .security import canonical_json, sign_body
from .store import DEAD, PENDING, SUCCEEDED, WebhookStore
from .transport import HttpTransport, SendResult

DEFAULT_UNIT = "psdline"

# 尝试结果常量
R_OK = "success"
R_FAIL = "failure"
R_PERMANENT = "permanent"
R_RATE_LIMITED = "rate_limited"
R_LEASE_LOST = "lease_lost"


def topic_matches(topic: str, action: str, filters: list[str]) -> bool:
    """事件是否命中过滤项（``*`` / 精确主题 / ``主题.动作``）。"""

    for item in filters:
        if item == "*" or item == topic or item == f"{topic}.{action}":
            return True
    return False


def aggregate_key(payload: dict, fallback: str = "") -> str:
    """从事件负载推导聚合键：站台优先，其次列车，再退化到固定单键。

    同一聚合键严格有序投递；门控事件几乎都带站台，退化时全订户共用一个键，
    退化为完全顺序（安全但牺牲并发），绝不允许乱序。
    """

    for key in ("station_id", "train_id", "component"):
        value = payload.get(key)
        if value not in (None, ""):
            return f"{key}:{value}"
    return fallback or "unit"


class Dispatcher:
    """入队、认领、投递、退避、死信的总调度。"""

    def __init__(
        self,
        store: WebhookStore,
        clock: Clock | None = None,
        transport=None,
        *,
        unit: str = DEFAULT_UNIT,
        enqueue_interval_s: float = 0.2,
        schedule_interval_s: float = 0.1,
        lease_s: float = 30.0,
        workers: int = 16,
        max_concurrency_per_sub: int = 4,
        timeout_s: float = 10.0,
        backoff_base_s: float = 1.0,
        backoff_factor: float = 2.0,
        backoff_max_s: float = 300.0,
        worker_id: str | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or SystemClock()
        self._transport = transport or HttpTransport(timeout_s=timeout_s)
        self._unit = unit
        self._enqueue_interval = enqueue_interval_s
        self._schedule_interval = schedule_interval_s
        self._lease_s = lease_s
        self._workers = max(1, int(workers))
        self._max_per_sub = max(1, int(max_concurrency_per_sub))
        self._base = backoff_base_s
        self._factor = backoff_factor
        self._cap = backoff_max_s
        self._worker_id = worker_id or f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._rates = RateLimiter(self._clock.now)
        self._stop = threading.Event()
        self._pool_sem = threading.BoundedSemaphore(self._workers)
        self._threads: list[threading.Thread] = []
        self._workers_alive: list[threading.Thread] = []
        self._workers_lock = threading.Lock()
        self._inflight = 0
        self._inflight_lock = threading.Lock()

    # ---- 生命周期 -----------------------------------------------------

    def start(self) -> None:
        """启动入队循环与调度循环（守护线程）。"""

        if self._threads:
            return
        self._stop.clear()
        self._threads = [
            self._spawn("webhook-enqueuer", self._run_enqueuer),
            self._spawn("webhook-scheduler", self._run_scheduler),
        ]

    def stop(self) -> None:
        """通知循环退出并等待在途传输收口（传输超时内）。"""

        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=max(5.0, self._schedule_interval * 10))
        # 等待已提交的在途传输（最坏一个 HTTP 超时）。
        self.wait_idle(timeout=self._lease_s + 1.0)
        self._threads = []

    def _spawn(self, name: str, target) -> threading.Thread:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        return thread

    def _sleep(self, seconds: float) -> None:
        self._stop.wait(timeout=max(0.0, seconds))

    # ---- 入队循环 -----------------------------------------------------

    def _run_enqueuer(self) -> None:
        while not self._stop.is_set():
            try:
                self._store.pump_subscriptions(self._clock.now())
            except Exception as error:  # pragma: no cover - 靠下一拍自愈
                self._log_audit("enqueue_error", {"error": str(error)})
            self._sleep(self._enqueue_interval)

    # ---- 调度循环 -----------------------------------------------------

    def _run_scheduler(self) -> None:
        while not self._stop.is_set():
            try:
                claimed = self.schedule_once()
            except Exception as error:  # pragma: no cover - 靠下一拍自愈
                claimed = 0
                self._log_audit("schedule_error", {"error": str(error)})
            self._sleep(0.0 if claimed else self._schedule_interval)

    def schedule_once(self) -> int:
        """一拍：回收过期租约、限流过滤、认领并提交投递，返回认领数。"""

        now = self._clock.now()
        try:
            self._store.reclaim_expired(now)
        except Exception:  # pragma: no cover - 下一拍继续
            pass
        leased_counts, occupied = self._store.leased_keys()
        blocked_keys: set[tuple[str, str]] = set()
        candidates = self._store.due_candidates(now, limit=max(64, self._workers * 4))
        claimed = 0
        for candidate in candidates:
            sub_id = candidate["sub_id"]
            key = candidate["aggregate_key"]
            if leased_counts.get(sub_id, 0) >= self._max_per_sub:
                continue
            if (sub_id, key) in occupied or (sub_id, key) in blocked_keys:
                continue
            rate = float(candidate.get("sub_max_rate") or 0.0)
            if rate > 0 and not self._rates.allow(sub_id, rate):
                blocked_keys.add((sub_id, key))
                continue
            delivery = self._store.claim(candidate["delivery_id"], self._worker_id,
                                         now, self._lease_s)
            if delivery is None:
                continue
            occupied.add((sub_id, key))
            leased_counts[sub_id] = leased_counts.get(sub_id, 0) + 1
            claimed += 1
            self._submit(delivery)
        return claimed

    def _submit(self, delivery: dict) -> None:
        self._pool_sem.acquire()
        with self._inflight_lock:
            self._inflight += 1
        thread = threading.Thread(
            target=self._worker,
            name=f"webhook-send-{delivery['delivery_id'][:8]}",
            args=(delivery,),
            daemon=True,
        )
        with self._workers_lock:
            self._workers_alive.append(thread)
        thread.start()

    # ---- worker -------------------------------------------------------

    def _worker(self, delivery: dict) -> None:
        try:
            self.deliver(delivery)
        finally:
            with self._inflight_lock:
                self._inflight -= 1
            self._pool_sem.release()

    def deliver(self, delivery: dict) -> str:
        """打包并投递一条，落库最终结果，返回最终状态。"""

        delivery_id = delivery["delivery_id"]
        lease_token = int(delivery["lease_token"] or 0)
        event = self._store.get_event(delivery["event_id"])
        now = self._clock.now()
        if event is None:
            # 数据被外部破坏才会发生；按永久失败处理，等人工核查。
            self._store.record_attempt(delivery_id, lease_token, R_PERMANENT, now,
                                       error="事件总账中找不到对应事件")
            result_status = self._store.finish_failed(
                delivery_id, lease_token, None, "事件缺失", now, now, dead=True
            )
            self._log_audit("delivery_dead", self._dead_detail(delivery, "事件缺失"))
            return result_status or DEAD

        envelope, body = self.build_envelope(delivery, event, now)
        headers = self.build_headers(delivery, envelope, body)
        started = self._clock.monotonic()
        outcome: SendResult = self._transport.send(delivery["target_url"], body, headers)
        duration_ms = (self._clock.monotonic() - started) * 1000.0
        at = self._clock.now()

        if outcome.ok:
            self._store.record_attempt(delivery_id, lease_token, R_OK, at,
                                       http_status=outcome.status, duration_ms=duration_ms)
            if self._store.finish_succeeded(delivery_id, lease_token, outcome.status or 0, at):
                return SUCCEEDED
            self._store.record_attempt(delivery_id, lease_token, R_LEASE_LOST, at,
                                       error="租约已交接，迟到结果被丢弃")
            return "leased"

        attempts = int(delivery["attempts"])
        max_attempts = int(delivery.get("sub_max_attempts") or 1)
        dead = outcome.permanent or attempts >= max_attempts
        if dead:
            self._store.record_attempt(delivery_id, lease_token, R_PERMANENT, at,
                                       http_status=outcome.status, error=outcome.error,
                                       duration_ms=duration_ms)
            new_status = self._store.finish_failed(
                delivery_id, lease_token, outcome.status, outcome.error, at, at, dead=True
            )
            if new_status == DEAD:
                self._log_audit("delivery_dead",
                                self._dead_detail(delivery, outcome.error))
            return new_status or "leased"

        not_before = at + self.backoff_delay(attempts)
        self._store.record_attempt(delivery_id, lease_token, R_FAIL, at,
                                   http_status=outcome.status, error=outcome.error,
                                   duration_ms=duration_ms)
        new_status = self._store.finish_failed(
            delivery_id, lease_token, outcome.status, outcome.error, at, not_before,
            dead=False,
        )
        if new_status is None:
            self._store.record_attempt(delivery_id, lease_token, R_LEASE_LOST, at,
                                       error="租约已交接，迟到结果被丢弃")
            return "leased"
        return new_status

    def backoff_delay(self, attempts: int) -> float:
        """指数退避 + 全抖动：``random(0, min(cap, base * factor**(n-1)))``。

        全抖动打散重试风暴，同时保证第 n 次尝试最坏不超过封顶退避。
        """

        upper = min(self._cap, self._base * (self._factor ** max(0, attempts - 1)))
        return random.uniform(0.0, upper)

    # ---- 打包 ---------------------------------------------------------

    def build_envelope(self, delivery: dict, event: dict, now: float) -> tuple[dict, bytes]:
        """构造对外投递信封并序列化。

        ``id`` 恒为事件总账里的 ``event_id``：重试、租约交接、人工重投都不换号，
        订户以它为幂等键。``seq`` 为该订户可观察到的单调序号（这里用全局事件
        序号，订户可见序号也因此单调），可用于检测缺口。
        """

        try:
            payload = json.loads(event["payload"])
        except (json.JSONDecodeError, TypeError):
            payload = {"raw": event["payload"]}
        envelope = {
            "id": event["event_id"],
            "unit": self._unit,
            "topic": event["topic"],
            "action": event["action"],
            "seq": int(event["seq"]),
            "aggregate_key": event["aggregate_key"],
            "occurred_at": event["occurred_at"],
            "delivered_at": now,
            "delivery_id": delivery["delivery_id"],
            "attempt": int(delivery["attempts"]),
            "data": payload,
        }
        body = canonical_json(envelope).encode("utf-8")
        return envelope, body

    def build_headers(self, delivery: dict, envelope: dict, body: bytes) -> dict[str, str]:
        """投递请求头：幂等键、签名，可选 Bearer 凭据。"""

        timestamp = str(int(self._clock.now()))
        signature = sign_body(delivery["secret"], timestamp, body)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Event-ID": envelope["id"],
            "Event-Topic": envelope["topic"],
            "Event-Action": envelope["action"],
            "Event-Seq": str(envelope["seq"]),
            "Delivery-ID": envelope["delivery_id"],
            "Delivery-Attempt": str(envelope["attempt"]),
            "X-Signature-Timestamp": timestamp,
            "X-Signature": f"sha256={signature}",
            "User-Agent": "psdline-webhook/1.0",
        }
        if delivery.get("auth_token"):
            headers["Authorization"] = f"Bearer {delivery['auth_token']}"
        return headers

    # ---- 审计与观测 ---------------------------------------------------

    def _log_audit(self, action: str, detail: dict) -> None:
        try:
            self._store.append_audit(self._clock.now(), "dispatcher", action, detail)
        except Exception:  # pragma: no cover - 审计失败不阻断投递
            pass

    def _dead_detail(self, delivery: dict, reason: str) -> dict:
        return {
            "delivery_id": delivery["delivery_id"],
            "sub_id": delivery["sub_id"],
            "event_id": delivery["event_id"],
            "reason": reason,
        }

    def inflight(self) -> int:
        """返回当前在途投递数。"""

        with self._inflight_lock:
            return self._inflight

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """等待在途投递收口（验证与优雅停机用，停机流程按名字调用）。"""

        deadline = self._clock.monotonic() + timeout
        while self.inflight() > 0 and self._clock.monotonic() < deadline:
            self._sleep(0.01)
        return self.inflight() == 0
