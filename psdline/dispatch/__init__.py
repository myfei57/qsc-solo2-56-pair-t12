"""对外事件投递（webhook 分发）。

链路：总线事件 → :class:`Outbox`（只追加、去重、全局序号）→
:class:`Dispatcher`（订阅匹配、逐条有序、退避重试、限流、租约恢复）→
HTTP 回调；失败到上限进死信，支持人工重投。订阅、凭据、令牌、每次投递尝试
全部走带哈希链的只追加流水，历史不可变。
"""

from __future__ import annotations

from .dispatcher import Dispatcher, backoff_delay
from .envelope import build_request, classify, idempotency_key, sign
from .ledger import HashJournal, chain_hash
from .model import (
    SCOPE_ADMIN,
    SCOPE_AUDITOR,
    SCOPE_OPS,
    SCOPES,
    STATUS_ACTIVE,
    STATUS_PAUSED,
    STATUS_REVOKED,
    StoredEvent,
    Subscription,
)
from .outbox import Outbox
from .ratelimit import RateLimiter
from .registry import READ_SCOPES, SubRegistry, TokenRegistry
from .service import DispatchService
from .transport import HttpSender

__all__ = [
    "Dispatcher",
    "DispatchService",
    "HashJournal",
    "HttpSender",
    "Outbox",
    "READ_SCOPES",
    "SCOPE_ADMIN",
    "SCOPE_AUDITOR",
    "SCOPE_OPS",
    "SCOPES",
    "STATUS_ACTIVE",
    "STATUS_PAUSED",
    "STATUS_REVOKED",
    "StoredEvent",
    "SubRegistry",
    "Subscription",
    "RateLimiter",
    "TokenRegistry",
    "backoff_delay",
    "build_request",
    "chain_hash",
    "classify",
    "idempotency_key",
    "sign",
]
