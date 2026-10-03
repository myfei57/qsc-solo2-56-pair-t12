"""令牌桶限流。

每个订户一把桶（``rate_per_min``，登记时为 0 表示只受全局上限约束），另设一把
全局桶保护本进程的总出站吞吐。投递线程在发出 HTTP 请求前先取令牌，桶空即等待，
退避重试的请求与正常请求一样受限流约束，避免故障订户把出口打满。
"""

from __future__ import annotations

import threading

from ..clock import Clock, SystemClock

GLOBAL_KEY = "__global__"


class RateLimiter:
    """按 key 分桶的令牌桶；``rate_per_min <= 0`` 表示该桶不限速。"""

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._tokens: dict[str, float] = {}
        self._updated: dict[str, float] = {}
        self._rates: dict[str, float] = {}
        self._capacity: dict[str, float] = {}

    def configure(self, key: str, rate_per_min: float, *, burst: float | None = None) -> None:
        """设置某把桶的速率（令牌/分钟）与突发容量。"""

        with self._lock:
            rate = max(0.0, float(rate_per_min))
            self._rates[key] = rate
            capacity = float(burst) if burst is not None else max(1.0, rate / 60.0)
            self._capacity[key] = max(1.0, capacity)
            if key not in self._tokens:
                self._tokens[key] = self._capacity[key]
                self._updated[key] = self._clock.monotonic()

    def set_global(self, rate_per_min: float) -> None:
        rate = max(0.0, float(rate_per_min))
        self.configure(GLOBAL_KEY, rate, burst=max(1.0, rate / 60.0))

    def acquire(self, key: str, timeout: float = 30.0) -> bool:
        """取一个令牌；按挂钟补充桶容量，超时返回 ``False``。"""

        deadline = self._clock.monotonic() + max(0.0, timeout)
        while True:
            wait = self._try_take(key)
            if wait == 0.0:
                return True
            remaining = deadline - self._clock.monotonic()
            if wait > remaining:
                return False
            self._clock.sleep(wait)

    def _try_take(self, key: str) -> float:
        with self._lock:
            now = self._clock.monotonic()
            wait = 0.0
            for bucket in (key, GLOBAL_KEY):
                rate = self._rates.get(bucket, 0.0)
                if rate <= 0:
                    continue
                if bucket not in self._tokens:
                    self._tokens[bucket] = 1.0
                    self._updated[bucket] = now
                elapsed = max(0.0, now - self._updated[bucket])
                self._tokens[bucket] = min(
                    self._capacity.get(bucket, 1.0),
                    self._tokens[bucket] + elapsed * rate / 60.0,
                )
                self._updated[bucket] = now
                if self._tokens[bucket] < 1.0:
                    wait = max(wait, (1.0 - self._tokens[bucket]) * 60.0 / rate)
            if wait == 0.0:
                for bucket in (key, GLOBAL_KEY):
                    if self._rates.get(bucket, 0.0) > 0:
                        self._tokens[bucket] -= 1.0
            return wait
