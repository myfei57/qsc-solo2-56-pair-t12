"""对外事件投递的数据模型。

三类不可变对象：

* :class:`StoredEvent` —— 已进入出箱流水、带全局序号的门控事件；
* :class:`Subscription` —— 订户登记（回调地址、过滤条件、凭据、生命周期状态）；
* :class:`Token` —— 管理 API 令牌（只存散列）。

过滤规则：主题精确匹配或 ``"*"`` 全量；可再按载荷里的 ``station_id`` 与事件
组件收窄。订户对象内存里持有明文凭据（投递时要用来签名），落盘与对外视图都
必须经过 :class:`~psdline.dispatch.registry.SubRegistry` 加密封装。
"""

from __future__ import annotations

from dataclasses import dataclass, field

STATUS_ACTIVE = "active"
STATUS_PAUSED = "paused"
STATUS_REVOKED = "revoked"

SCOPE_ADMIN = "admin"
SCOPE_OPS = "ops"
SCOPE_AUDITOR = "auditor"
SCOPES = (SCOPE_ADMIN, SCOPE_OPS, SCOPE_AUDITOR)


@dataclass(frozen=True)
class StoredEvent:
    """出箱里的一条事件，序号在全系统范围内严格递增。"""

    seq: int
    id: str
    topic: str
    component: str
    action: str
    at: float
    payload: dict = field(default_factory=dict)

    def core(self) -> dict:
        """返回去掉投递序号后的事件内容（签名与回放用）。"""

        return {
            "id": self.id,
            "topic": self.topic,
            "component": self.component,
            "action": self.action,
            "at": self.at,
            "payload": self.payload,
        }


def topic_matches(patterns: tuple[str, ...], topic: str) -> bool:
    """主题是否命中订户的主题集合（``*`` 表示全量）。"""

    return "*" in patterns or topic in patterns


@dataclass(frozen=True)
class Subscription:
    """一份订户登记。"""

    id: str
    name: str
    callback: str
    topics: tuple[str, ...]
    stations: tuple[str, ...]
    components: tuple[str, ...]
    secret: str
    token: str
    headers: dict
    rate_per_min: float
    start_seq: int
    status: str
    created_at: float
    created_by: str
    updated_at: float

    def matches(self, event: StoredEvent) -> bool:
        """事件是否属于该订户关心的范围。"""

        if not topic_matches(self.topics, event.topic):
            return False
        if self.stations:
            station = str(event.payload.get("station_id", ""))
            if station not in self.stations:
                return False
        if self.components and event.component not in self.components:
            return False
        return True

    def is_live(self) -> bool:
        """只有生效中的订户参与投递。"""

        return self.status == STATUS_ACTIVE

    def public_view(self) -> dict:
        """对外视图：绝不带出任何凭据材料。"""

        return {
            "id": self.id,
            "name": self.name,
            "callback": self.callback,
            "topics": list(self.topics),
            "stations": list(self.stations),
            "components": list(self.components),
            "rate_per_min": self.rate_per_min,
            "start_seq": self.start_seq,
            "status": self.status,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class Token:
    """管理 API 令牌，散列落盘，明文只在签发那一刻返回。"""

    id: str
    label: str
    scope: str
    secret_hash: str
    created_at: float
    created_by: str
    revoked: bool = False

    def public_view(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "scope": self.scope,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "revoked": self.revoked,
        }
