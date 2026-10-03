"""订户级令牌桶限流（秒级，进程内）。

每个订户一把桶，``max_rate`` 为每秒允许投递条数（0 表示不限）。多进程部署时
桶不共享，允许的实际速率可能按进程数放大；速率硬保证由订户侧幂等与退避兜底，
本桶只负责单进程内不把慢订户打爆。桶用一把共享锁保护，线程安全。
"""

from __future__ import annotations

import threading


class TokenBucket:
    """一把惰性补充的令牌桶。"""

    def __init__(self, rate_per_s: float, clock_now) -> None:
        self._rate = float(rate_per_s)
        self._now = clock_now
        self._tokens = float(rate_per_s) if rate_per_s > 0 else 0.0
        self._updated = clock_now()

    def allow(self, rate_per_s: float) -> bool:
        """取一个令牌；``rate_per_s`` 为 0 表示不限流。"""

        if rate_per_s <= 0:
            return True
        now = self._now()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        if self._rate != rate_per_s:
            self._rate = float(rate_per_s)
        self._tokens = min(rate_per_s, self._tokens + elapsed * rate_per_s)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def retry_after(self, rate_per_s: float) -> float:
        """预计多少秒后有一个令牌。"""

        if rate_per_s <= 0:
            return 0.0
        deficit = max(0.0, 1.0 - self._tokens)
        return deficit / rate_per_s if rate_per_s > 0 else 0.0


class RateLimiter:
    """按订户维护令牌桶。"""

    def __init__(self, clock_now) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._clock_now = clock_now
        self._lock = threading.Lock()

    def allow(self, sub_id: str, rate_per_s: float) -> bool:
        if rate_per_s <= 0:
            return True
        with self._lock:
            bucket = self._buckets.get(sub_id)
            if bucket is None:
                bucket = TokenBucket(rate_per_s, self._clock_now)
                self._buckets[sub_id] = bucket
            return bucket.allow(rate_per_s)

    def retry_after(self, sub_id: str, rate_per_s: float) -> float:
        if rate_per_s <= 0:
            return 0.0
        with self._lock:
            bucket = self._buckets.get(sub_id)
            if bucket is None:
                return 0.0
            return bucket.retry_after(rate_per_s)
