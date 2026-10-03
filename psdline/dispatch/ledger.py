"""带哈希链的只追加流水。

所有历史（出箱事件、订户登记、投递尝试、令牌、死信）都落到这种流水里：每条
记录保存前一条与自身的 SHA-256，形成链式结构。任何一条被改写、删除或插入，
回放校验都会在第一处断裂点报错；快照只作为加速重启的缓存，始终以全量回放
校验为准。

分段文件形如 ``<name>-00000.jsonl``，每行一个信封：
``{"prev": "<上一条散列>", "self": "<本条散列>", "record": {...}}``。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any

from ..errors import StorageError

GENESIS = "0" * 64


def canonical(record: Any) -> bytes:
    """流水记录的规范序列化（排序键、紧凑分隔），保证跨进程散列一致。"""

    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def chain_hash(previous: str, record: Any) -> str:
    """计算一条记录的链散列。"""

    digest = hashlib.sha256()
    digest.update(previous.encode("ascii"))
    digest.update(canonical(record))
    return digest.hexdigest()


class HashJournal:
    """分段、带哈希链、写入即 ``fsync`` 的只追加流水。"""

    def __init__(self, root: str, name: str, segment_limit: int = 1024) -> None:
        self._root = os.path.abspath(root)
        self._name = name
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        self._count = 0
        self._tail = GENESIS
        self._replay()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def tail(self) -> str:
        with self._lock:
            return self._tail

    def append(self, record: Any) -> int:
        """追加一条记录并做链式校验写入，返回其序号（从 1 开始）。"""

        with self._lock:
            self._sync_tail_from_disk()
            index = self._count
            path = self._segment_path(index // self._segment_limit)
            envelope = {"prev": self._tail, "self": "", "record": record}
            envelope["self"] = chain_hash(self._tail, record)
            line = json.dumps(envelope, ensure_ascii=False) + "\n"
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水 {self._name} 失败: {error}", component="dispatch") from error
            self._count += 1
            self._tail = envelope["self"]
            return self._count

    def replay(self) -> list[Any]:
        """全量回放并校验哈希链，返回全部业务记录。"""

        with self._lock:
            records: list[Any] = []
            previous = GENESIS
            for segment in range(4096):
                path = self._segment_path(segment)
                if not os.path.isfile(path):
                    break
                previous = self._read_segment(path, previous, records)
            self._last_verified_tail = previous
            return records

    def _replay(self) -> None:
        records = self.replay()
        self._count = len(records)
        self._tail = getattr(self, "_last_verified_tail", GENESIS)

    def _read_segment(self, path: str, previous: str, records: list[Any]) -> str:
        """读取并校验一个段，把业务记录追加进 ``records``，返回段尾链散列。"""

        base = len(records)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for offset, line in enumerate(handle):
                    if not line.strip():
                        continue
                    try:
                        envelope = json.loads(line)
                        record = envelope["record"]
                        expect_prev = str(envelope["prev"])
                        expect_self = str(envelope["self"])
                    except (json.JSONDecodeError, KeyError, TypeError) as error:
                        raise StorageError(f"流水 {path} 记录损坏: {error}", component="dispatch") from error
                    if expect_prev != previous:
                        raise StorageError(
                            f"流水 {self._name} 第 {base + offset + 1} 条的前向散列断裂（历史被改写或缺失）",
                            component="dispatch",
                        )
                    actual = chain_hash(previous, record)
                    if expect_self != actual:
                        raise StorageError(
                            f"流水 {self._name} 第 {base + offset + 1} 条内容散列不匹配（记录被篡改）",
                            component="dispatch",
                        )
                    records.append(record)
                    previous = actual
        except OSError as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="dispatch") from error
        return previous

    def _sync_tail_from_disk(self) -> None:
        """只统计磁盘条数并读取最后一条的自身散列，低成本对齐写位点。

        同一目录被同进程内多个句柄依次写入（旧句柄已停）时，后者内存里缓存
        的尾部会过期；全链路完整性仍由 :meth:`replay` 在启动时校验，这里只
        解决“下一条该挂在谁后面”，不做全量回放以免每条追加都 O(n)。
        """

        total = 0
        last_self = GENESIS
        for segment in range(4096):
            path = self._segment_path(segment)
            if not os.path.isfile(path):
                break
            with open(path, "r", encoding="utf-8") as handle:
                last_line = ""
                for line in handle:
                    if line.strip():
                        total += 1
                        last_line = line
            if last_line:
                try:
                    envelope = json.loads(last_line)
                    last_self = str(envelope.get("self", GENESIS))
                except json.JSONDecodeError:
                    pass
        if total != self._count or self._tail != last_self:
            self._count = total
            self._tail = last_self

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._name}-{index:05d}.jsonl")
