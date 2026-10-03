"""投递子系统持久化（SQLite + WAL）。

五张表：

* ``events`` 事件总账，只追加，``event_id`` 去重、``seq`` 全局有序；
* ``subscriptions`` 订户登记与投递游标（订户只登记关心的事件，游标前的事件
  视为本订户不追历史）；
* ``credentials`` 凭据，只存令牌的 SHA-256；
* ``deliveries`` 每订户每事件一条的投递状态机（pending/leased/succeeded/dead），
  ``(sub_id,event_id)`` 唯一，重试与重投复用同一行；
* ``delivery_attempts`` 每次尝试只追加；``audit_records`` 只追加且带哈希链。

``events``、``delivery_attempts``、``audit_records`` 在数据库层用触发器禁止
UPDATE/DELETE，历史不可变不靠约定，靠库本身拒绝写。崩溃安全靠 WAL 与
「先落库后投递」：投递循环任何时刻挂掉，重启后靠租约回收（leased 超时回到
pending）与投递状态机继续，不会丢也不会在状态机里出现两条同一事件。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid

from ..errors import RailError, StorageError
from .security import canonical_json

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    topic TEXT NOT NULL,
    action TEXT NOT NULL,
    aggregate_key TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    ingested_at REAL NOT NULL,
    source TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    allowed_topics TEXT NOT NULL,
    bound_sub_id TEXT NOT NULL DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    sub_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    topics TEXT NOT NULL,
    secret TEXT NOT NULL,
    auth_token TEXT NOT NULL DEFAULT '',
    max_rate REAL NOT NULL,
    max_attempts INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    cursor_seq INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    sub_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    aggregate_key TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    not_before REAL NOT NULL,
    lease_owner TEXT,
    lease_token INTEGER,
    lease_expires REAL,
    last_status INTEGER,
    last_error TEXT,
    delivered_at REAL,
    dead_at REAL,
    replayed_from TEXT,
    created_at REAL NOT NULL,
    UNIQUE(sub_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_deliveries_due
    ON deliveries(status, not_before);
CREATE INDEX IF NOT EXISTS idx_deliveries_sub_seq
    ON deliveries(sub_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    result TEXT NOT NULL,
    http_status INTEGER,
    error TEXT,
    duration_ms REAL,
    at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_delivery
    ON delivery_attempts(delivery_id, id);

CREATE TABLE IF NOT EXISTS audit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events 是只追加总账，禁止修改'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events 是只追加总账，禁止删除'); END;
CREATE TRIGGER IF NOT EXISTS attempts_no_update BEFORE UPDATE ON delivery_attempts
BEGIN SELECT RAISE(ABORT, 'delivery_attempts 只追加，禁止修改'); END;
CREATE TRIGGER IF NOT EXISTS attempts_no_delete BEFORE DELETE ON delivery_attempts
BEGIN SELECT RAISE(ABORT, 'delivery_attempts 只追加，禁止删除'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_records
BEGIN SELECT RAISE(ABORT, 'audit_records 只追加，禁止修改'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_records
BEGIN SELECT RAISE(ABORT, 'audit_records 只追加，禁止删除'); END;
"""

PENDING = "pending"
LEASED = "leased"
SUCCEEDED = "succeeded"
DEAD = "dead"


def new_id() -> str:
    """生成投递子系统使用的随机标识。"""

    return uuid.uuid4().hex


def _chain_hash(prev_hash: str, at: float, actor: str, action: str, detail: str) -> str:
    """计算审计哈希链一环：上一环哈希串接本条规范化内容。"""

    try:
        parsed = json.loads(detail)
    except json.JSONDecodeError:
        parsed = detail
    body = canonical_json({"at": at, "actor": actor, "action": action, "detail": parsed})
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class WebhookStore:
    """投递子系统的全部持久化操作。"""

    def __init__(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._initialize()

    # ---- 连接与建表 ---------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        con.row_factory = sqlite3.Row
        return con

    def _initialize(self) -> None:
        with self._lock, self._connect() as con:
            con.executescript(SCHEMA)
            row = con.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            elif int(row["value"]) != SCHEMA_VERSION:
                raise StorageError(
                    f"投递库 schema 版本不匹配: {row['value']} != {SCHEMA_VERSION}",
                    component="webhook",
                )

    # ---- 事件总账 -----------------------------------------------------

    def insert_event(
        self,
        event_id: str,
        topic: str,
        action: str,
        aggregate_key: str,
        occurred_at: float,
        ingested_at: float,
        payload: str,
        source: str,
    ) -> bool:
        """登记一条事件；同 ``event_id`` 重复登记返回 False（摄入幂等）。"""

        with self._lock, self._connect() as con:
            row = con.execute("SELECT COALESCE(MAX(seq), 0) AS m FROM events").fetchone()
            cursor = con.execute(
                "INSERT OR IGNORE INTO events"
                "(event_id, seq, topic, action, aggregate_key, occurred_at,"
                " ingested_at, source, payload)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    int(row["m"]) + 1,
                    topic,
                    action,
                    aggregate_key,
                    occurred_at,
                    ingested_at,
                    source,
                    payload,
                ),
            )
            return cursor.rowcount == 1

    def max_event_seq(self) -> int:
        with self._connect() as con:
            row = con.execute("SELECT COALESCE(MAX(seq), 0) AS m FROM events").fetchone()
            return int(row["m"])

    def get_event(self, event_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            return dict(row) if row else None

    def list_events(self, after_seq: int = 0, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
                (int(after_seq), limit),
            ).fetchall()
            return [dict(row) for row in rows]

    # ---- 凭据 ---------------------------------------------------------

    def insert_credential(
        self,
        key_id: str,
        name: str,
        scope: str,
        token_hash: str,
        allowed_topics: list[str],
        created_at: float,
        bound_sub_id: str = "",
    ) -> None:
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT INTO credentials"
                "(key_id, name, scope, token_hash, allowed_topics, bound_sub_id,"
                " revoked, created_at)"
                " VALUES(?,?,?,?,?,?,0,?)",
                (key_id, name, scope, token_hash, canonical_json(allowed_topics),
                 bound_sub_id, created_at),
            )

    def get_credential_by_hash(self, token_hash: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM credentials WHERE token_hash=? AND revoked=0", (token_hash,)
            ).fetchone()
            return dict(row) if row else None

    def list_credentials(self, include_revoked: bool = False) -> list[dict]:
        sql = "SELECT * FROM credentials"
        if not include_revoked:
            sql += " WHERE revoked=0"
        sql += " ORDER BY created_at, key_id"
        with self._connect() as con:
            return [dict(row) for row in con.execute(sql).fetchall()]

    def revoke_credential(self, key_id: str) -> bool:
        with self._lock, self._connect() as con:
            cursor = con.execute(
                "UPDATE credentials SET revoked=1 WHERE key_id=? AND revoked=0", (key_id,)
            )
            return cursor.rowcount == 1

    # ---- 订户 ---------------------------------------------------------

    def insert_subscription(
        self,
        sub_id: str,
        name: str,
        target_url: str,
        topics: list[str],
        secret: str,
        auth_token: str,
        max_rate: float,
        max_attempts: int,
        created_at: float,
        created_by: str,
        cursor_seq: int = 0,
    ) -> None:
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT INTO subscriptions"
                "(sub_id, name, target_url, topics, secret, auth_token,"
                " max_rate, max_attempts, status, cursor_seq, created_at, created_by)"
                " VALUES(?,?,?,?,?,?,?,?,'active',?,?,?)",
                (
                    sub_id,
                    name,
                    target_url,
                    canonical_json(topics),
                    secret,
                    auth_token,
                    float(max_rate),
                    int(max_attempts),
                    int(cursor_seq),
                    created_at,
                    created_by,
                ),
            )

    def get_subscription(self, sub_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM subscriptions WHERE sub_id=?", (sub_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_subscriptions(self, include_revoked: bool = False) -> list[dict]:
        sql = "SELECT * FROM subscriptions"
        if not include_revoked:
            sql += " WHERE status!='revoked'"
        sql += " ORDER BY created_at, sub_id"
        with self._connect() as con:
            return [dict(row) for row in con.execute(sql).fetchall()]

    def update_subscription(self, sub_id: str, fields: dict) -> bool:
        """更新订户可变字段（url/topics/name/限流/重试上限）。"""

        allowed = {"name", "target_url", "topics", "max_rate", "max_attempts"}
        sets: list[str] = []
        values: list[object] = []
        for key, value in fields.items():
            if key not in allowed:
                raise RailError(f"订户字段 {key!r} 不允许修改", component="webhook")
            if key == "topics":
                value = canonical_json(list(value))
            sets.append(f"{key}=?")
            values.append(value)
        if not sets:
            return False
        values.append(sub_id)
        with self._lock, self._connect() as con:
            cursor = con.execute(
                f"UPDATE subscriptions SET {', '.join(sets)} WHERE sub_id=?", values
            )
            return cursor.rowcount == 1

    def set_subscription_status(self, sub_id: str, status: str) -> bool:
        if status not in {"active", "paused", "revoked"}:
            raise RailError(f"非法订户状态: {status}", component="webhook")
        with self._lock, self._connect() as con:
            cursor = con.execute(
                "UPDATE subscriptions SET status=? WHERE sub_id=?", (status, sub_id)
            )
            return cursor.rowcount == 1

    # ---- 入队（事件总账 -> 订户待投） ---------------------------------

    def pump_subscriptions(self, now: float, batch: int = 500) -> int:
        """把各订户游标之后、命中其过滤条件的事件写入 deliveries。

        一个 ``BEGIN IMMEDIATE`` 事务里完成「读游标-插待投-推进游标」，崩溃
        只会导致整批重做（INSERT OR IGNORE 去重），不会漏事件或重复建待投行。
        """

        enqueued = 0
        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                # active 订户入队并推进游标；paused 订户不投递但同样推进游标——
                # 暂停期间发生的事件显式跳过（恢复后只收新事件，语义可预期）；
                # revoked 订户完全冻结。
                subs = con.execute(
                    "SELECT * FROM subscriptions WHERE status IN ('active', 'paused')"
                ).fetchall()
                for sub in subs:
                    cursor_seq = int(sub["cursor_seq"])
                    events = con.execute(
                        "SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
                        (cursor_seq, batch),
                    ).fetchall()
                    if not events:
                        continue
                    if sub["status"] == "active":
                        filters = _load_list(sub["topics"])
                        for event in events:
                            if not _matches_any(event["topic"], event["action"], filters):
                                continue
                            con.execute(
                                "INSERT OR IGNORE INTO deliveries"
                                "(delivery_id, sub_id, event_id, seq, aggregate_key,"
                                " status, attempts, not_before, created_at)"
                                " VALUES(?,?,?,?,?, 'pending', 0, ?, ?)",
                                (
                                    new_id(),
                                    sub["sub_id"],
                                    event["event_id"],
                                    event["seq"],
                                    event["aggregate_key"],
                                    now,
                                    now,
                                ),
                            )
                            enqueued += 1
                    con.execute(
                        "UPDATE subscriptions SET cursor_seq=? WHERE sub_id=?",
                        (int(events[-1]["seq"]), sub["sub_id"]),
                    )
                con.commit()
            except Exception:
                con.rollback()
                raise
        return enqueued

    # ---- 投递状态机 ---------------------------------------------------

    def due_candidates(self, now: float, limit: int) -> list[dict]:
        """取到期候选（仅 active 订户），按全局序号升序。"""

        with self._connect() as con:
            rows = con.execute(
                "SELECT d.*, s.target_url, s.secret, s.auth_token,"
                " s.max_attempts AS sub_max_attempts, s.max_rate AS sub_max_rate,"
                " s.topics AS sub_topics"
                " FROM deliveries d JOIN subscriptions s ON s.sub_id=d.sub_id"
                " WHERE d.status='pending' AND d.not_before <= ? AND s.status='active'"
                " ORDER BY d.seq LIMIT ?",
                (now, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def leased_keys(self) -> tuple[dict[str, int], set[tuple[str, str]]]:
        """返回每订户在租约中的投递数，以及在租约的（订户，聚合键）集合。"""

        counts: dict[str, int] = {}
        occupied: set[tuple[str, str]] = set()
        with self._connect() as con:
            rows = con.execute(
                "SELECT sub_id, aggregate_key FROM deliveries WHERE status='leased'"
            ).fetchall()
        for row in rows:
            counts[row["sub_id"]] = counts.get(row["sub_id"], 0) + 1
            occupied.add((row["sub_id"], row["aggregate_key"]))
        return counts, occupied

    def claim(self, delivery_id: str, worker_id: str, now: float, lease_s: float) -> dict | None:
        """条件认领一条到期待投；并发下只有一个 worker 认领成功。

        认领即把尝试数 +1 并写入带 fencing token 的租约，最终落库必须带原 token
        才生效，worker 崩溃后租约被回收，旧 worker 的迟到结果不会二次落库。
        """

        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=? AND status='pending'"
                    " AND not_before <= ?",
                    (delivery_id, now),
                ).fetchone()
                if row is None:
                    con.commit()
                    return None
                token = int(row["attempts"]) + 1
                con.execute(
                    "UPDATE deliveries SET status='leased', lease_owner=?,"
                    " lease_token=?, lease_expires=?, attempts=attempts+1"
                    " WHERE delivery_id=? AND status='pending'",
                    (worker_id, token, now + lease_s, delivery_id),
                )
                full = con.execute(
                    "SELECT d.*, s.target_url, s.secret, s.auth_token,"
                    " s.max_attempts AS sub_max_attempts, s.max_rate AS sub_max_rate,"
                    " s.topics AS sub_topics"
                    " FROM deliveries d JOIN subscriptions s ON s.sub_id=d.sub_id"
                    " WHERE d.delivery_id=?",
                    (delivery_id,),
                ).fetchone()
                con.commit()
                return dict(full)
            except Exception:
                con.rollback()
                raise

    def reclaim_expired(self, now: float) -> int:
        """把超时租约交回 pending，并为每条补一条 expired 尝试记录。"""

        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                rows = con.execute(
                    "SELECT delivery_id, attempts FROM deliveries"
                    " WHERE status='leased' AND lease_expires < ?",
                    (now,),
                ).fetchall()
                for row in rows:
                    con.execute(
                        "UPDATE deliveries SET status='pending', lease_owner=NULL,"
                        " lease_token=NULL, lease_expires=NULL, not_before=?"
                        " WHERE delivery_id=?",
                        (now, row["delivery_id"]),
                    )
                    con.execute(
                        "INSERT INTO delivery_attempts"
                        "(delivery_id, attempt_no, result, http_status, error,"
                        " duration_ms, at)"
                        " VALUES(?,?, 'expired', NULL, 'lease 超时回收', NULL, ?)",
                        (row["delivery_id"], row["attempts"], now),
                    )
                con.commit()
                return len(rows)
            except Exception:
                con.rollback()
                raise

    def record_attempt(
        self,
        delivery_id: str,
        attempt_no: int,
        result: str,
        at: float,
        http_status: int | None = None,
        error: str | None = None,
        duration_ms: float | None = None,
    ) -> None:
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT INTO delivery_attempts"
                "(delivery_id, attempt_no, result, http_status, error, duration_ms, at)"
                " VALUES(?,?,?,?,?,?,?)",
                (delivery_id, attempt_no, result, http_status, error, duration_ms, at),
            )

    def finish_succeeded(
        self, delivery_id: str, lease_token: int, http_status: int, at: float
    ) -> bool:
        """带 fencing token 落库成功结果；token 不符（租约已交接）返回 False。"""

        with self._lock, self._connect() as con:
            cursor = con.execute(
                "UPDATE deliveries SET status='succeeded', lease_owner=NULL,"
                " lease_token=NULL, lease_expires=NULL, last_status=?,"
                " last_error=NULL, delivered_at=? "
                "WHERE delivery_id=? AND status='leased' AND lease_token=?",
                (http_status, at, delivery_id, lease_token),
            )
            return cursor.rowcount == 1

    def finish_failed(
        self,
        delivery_id: str,
        lease_token: int,
        http_status: int | None,
        error: str,
        at: float,
        not_before: float,
        dead: bool,
    ) -> str | None:
        """落库失败结果：成功更新返回新状态（dead/pending），token 不符返回 None。"""

        with self._lock, self._connect() as con:
            if dead:
                cursor = con.execute(
                    "UPDATE deliveries SET status='dead', lease_owner=NULL,"
                    " lease_token=NULL, lease_expires=NULL, last_status=?,"
                    " last_error=?, dead_at=?, not_before=? "
                    "WHERE delivery_id=? AND status='leased' AND lease_token=?",
                    (http_status, error, at, at, delivery_id, lease_token),
                )
                new_status = DEAD
            else:
                cursor = con.execute(
                    "UPDATE deliveries SET status='pending', lease_owner=NULL,"
                    " lease_token=NULL, lease_expires=NULL, last_status=?,"
                    " last_error=?, dead_at=NULL, not_before=? "
                    "WHERE delivery_id=? AND status='leased' AND lease_token=?",
                    (http_status, error, not_before, delivery_id, lease_token),
                )
                new_status = PENDING
            return new_status if cursor.rowcount == 1 else None

    def get_delivery(self, delivery_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_deliveries(
        self,
        sub_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        after_seq: int = 0,
    ) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        clauses = ["d.seq > ?"]
        values: list[object] = [int(after_seq)]
        if sub_id:
            clauses.append("d.sub_id=?")
            values.append(sub_id)
        if status:
            clauses.append("d.status=?")
            values.append(status)
        values.append(limit)
        sql = (
            "SELECT d.*, s.name AS sub_name FROM deliveries d"
            " JOIN subscriptions s ON s.sub_id=d.sub_id"
            f" WHERE {' AND '.join(clauses)} ORDER BY d.seq LIMIT ?"
        )
        with self._connect() as con:
            return [dict(row) for row in con.execute(sql, values).fetchall()]

    def list_attempts(self, delivery_id: str) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM delivery_attempts WHERE delivery_id=? ORDER BY id",
                (delivery_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def replay(self, delivery_id: str, now: float) -> dict | None:
        """把一条死信重置为 pending（复用同一行、同一 Event-ID）。"""

        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=? AND status='dead'",
                    (delivery_id,),
                ).fetchone()
                if row is None:
                    con.commit()
                    return None
                con.execute(
                    "UPDATE deliveries SET status='pending', attempts=0, not_before=?,"
                    " lease_owner=NULL, lease_token=NULL, lease_expires=NULL,"
                    " last_status=NULL, last_error=NULL, delivered_at=NULL,"
                    " dead_at=NULL,"
                    " replayed_from=COALESCE(replayed_from, delivery_id)"
                    " WHERE delivery_id=?",
                    (now, delivery_id),
                )
                con.execute(
                    "INSERT INTO delivery_attempts"
                    "(delivery_id, attempt_no, result, http_status, error,"
                    " duration_ms, at)"
                    " VALUES(?, 0, 'replay', NULL, '人工重投', NULL, ?)",
                    (delivery_id, now),
                )
                full = con.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
                ).fetchone()
                con.commit()
                return dict(full)
            except Exception:
                con.rollback()
                raise

    def replay_dead(self, sub_id: str | None, now: float) -> int:
        """批量重投某订户（或全部）的死信。"""

        clause = "status='dead'"
        values: list[object] = []
        if sub_id:
            clause += " AND sub_id=?"
            values.append(sub_id)
        with self._lock, self._connect() as con:
            rows = con.execute(
                f"SELECT delivery_id FROM deliveries WHERE {clause}", values
            ).fetchall()
        for row in rows:
            self.replay(row["delivery_id"], now)
        return len(rows)

    def delivery_counts(self, sub_id: str | None = None) -> dict[str, int]:
        sql = "SELECT status, COUNT(*) AS n FROM deliveries"
        values: list[object] = []
        if sub_id:
            sql += " WHERE sub_id=?"
            values.append(sub_id)
        sql += " GROUP BY status"
        with self._connect() as con:
            counts = {row["status"]: int(row["n"]) for row in con.execute(sql, values)}
        return {
            PENDING: counts.get(PENDING, 0),
            LEASED: counts.get(LEASED, 0),
            SUCCEEDED: counts.get(SUCCEEDED, 0),
            DEAD: counts.get(DEAD, 0),
        }

    # ---- 审计（哈希链，只追加） ---------------------------------------

    def append_audit(self, at: float, actor: str, action: str, detail: object) -> dict:
        """追加一条审计，环哈希由上一条哈希与本条内容确定。"""

        detail_text = canonical_json(detail)
        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                last = con.execute(
                    "SELECT hash FROM audit_records ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = last["hash"] if last else ""
                digest = _chain_hash(prev_hash, at, actor, action, detail_text)
                cursor = con.execute(
                    "INSERT INTO audit_records(at, actor, action, detail, prev_hash, hash)"
                    " VALUES(?,?,?,?,?,?)",
                    (at, actor, action, detail_text, prev_hash, digest),
                )
                row = con.execute(
                    "SELECT * FROM audit_records WHERE id=?", (cursor.lastrowid,)
                ).fetchone()
                con.commit()
                return dict(row)
            except Exception:
                con.rollback()
                raise

    def list_audit(self, limit: int = 100, after_id: int = 0) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM audit_records WHERE id > ? ORDER BY id LIMIT ?",
                (int(after_id), limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def verify_chain(self) -> dict:
        """从头复算哈希链，返回校验结果与断点。"""

        with self._connect() as con:
            rows = con.execute("SELECT * FROM audit_records ORDER BY id").fetchall()
        prev_hash = ""
        for row in rows:
            expected = _chain_hash(
                prev_hash, row["at"], row["actor"], row["action"], row["detail"]
            )
            if row["prev_hash"] != prev_hash or row["hash"] != expected:
                return {"ok": False, "broken_at": row["id"], "entries": len(rows)}
            prev_hash = row["hash"]
        return {"ok": True, "broken_at": None, "entries": len(rows)}


def _load_list(text: str) -> list[str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _matches_any(topic: str, action: str, filters: list[str]) -> bool:
    """事件是否命中订户的任一过滤项（``*``/主题/``主题.动作``）。"""

    for item in filters:
        if item == "*" or item == topic or item == f"{topic}.{action}":
            return True
    return False
