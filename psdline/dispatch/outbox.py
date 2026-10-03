"""事件出箱：门控事件进入对外投递链路的唯一入口。

事件先落带哈希链的只追加流水（拿到全局递增序号），再交给投递器扇出。先持久化
后投递保证崩溃安全：进程在任何时刻被杀，重启后都能从流水恢复全部未确认投递，
不会漏；同事件 id 重复进入只追加一次，天然挡住重试/回放造成的第二份效果。
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable

from ..clock import Clock
from .ledger import HashJournal
from .model import StoredEvent

OUTBOX_JOURNAL = "events"


class Outbox:
    """带序号与去重的只追加事件出箱。"""

    def __init__(
        self,
        clock: Clock,
        journal: HashJournal,
        *,
        on_append: Callable[[StoredEvent], None] | None = None,
    ) -> None:
        self._clock = clock
        self._journal = journal
        self._on_append = on_append
        self._lock = threading.RLock()
        self._events: list[StoredEvent] = []
        self._ids: dict[str, int] = {}
        self._replay()

    @property
    def head_seq(self) -> int:
        """已确认落盘的最大序号（空出箱为 0）。"""

        with self._lock:
            return len(self._events)

    def ingest(
        self,
        topic: str,
        component: str,
        action: str,
        payload: dict,
        *,
        event_id: str = "",
    ) -> tuple[StoredEvent, bool]:
        """事件进入出箱；返回 ``(事件, 是否首次写入)``。

        相同 ``event_id`` 再次进入时返回已存在的事件与 ``False``，不会产生
        第二份流水，也就不会对任何订户产生第二次投递。
        """

        with self._lock:
            existing_id = payload.get("event_id")
            event_id = event_id or (str(existing_id) if existing_id else "") or uuid.uuid4().hex
            existing = self._ids.get(event_id)
            if existing is not None:
                return self._events[existing - 1], False
            seq = len(self._events) + 1
            event = StoredEvent(
                seq=seq,
                id=event_id,
                topic=topic,
                component=component,
                action=action,
                at=self._clock.now(),
                payload=dict(payload),
            )
            self._journal.append(event.core())
            self._events.append(event)
            self._ids[event_id] = seq
        if self._on_append is not None:
            self._on_append(event)
        return event, True

    def get(self, seq: int) -> StoredEvent:
        with self._lock:
            if seq < 1 or seq > len(self._events):
                raise KeyError(seq)
            return self._events[seq - 1]

    def range(self, after_seq: int = 0, limit: int = 500) -> list[StoredEvent]:
        """按序号区间读取事件（``after_seq`` 之后至多 ``limit`` 条）。"""

        with self._lock:
            start = max(0, after_seq)
            end = min(len(self._events), start + max(1, limit))
            return list(self._events[start:end])

    def all(self) -> list[StoredEvent]:
        with self._lock:
            return list(self._events)

    def _replay(self) -> None:
        for record in self._journal.replay():
            seq = len(self._events) + 1
            event = StoredEvent(
                seq=seq,
                id=str(record.get("id", "")),
                topic=str(record.get("topic", "")),
                component=str(record.get("component", "")),
                action=str(record.get("action", "")),
                at=float(record.get("at", 0.0)),
                payload=record.get("payload") if isinstance(record.get("payload"), dict) else {},
            )
            self._events.append(event)
            self._ids[event.id] = seq
