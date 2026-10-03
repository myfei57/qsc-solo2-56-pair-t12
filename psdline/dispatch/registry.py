"""订户登记与管理令牌。

两份状态都走「只追加事件流水 + 内存物化」：登记、更新、暂停、恢复、吊销、
密钥轮换、令牌签发与吊销各自是一条流水记录，当前态由回放得到，历史不可变。
订户的签名密钥、自定义认证头与令牌在写入流水前用主密钥加密（见
:mod:`psdline.dispatch.crypto`），即便流水文件被拷走也无法直接拿到凭据。
"""

from __future__ import annotations

import json

from ..clock import Clock
from ..errors import RailError
from ..ids import IdFactory
from .crypto import open_seal, random_secret, random_token, seal
from .ledger import HashJournal
from .model import (
    SCOPE_ADMIN,
    SCOPE_AUDITOR,
    SCOPE_OPS,
    SCOPES,
    STATUS_ACTIVE,
    STATUS_PAUSED,
    STATUS_REVOKED,
    Subscription,
    Token,
)

SUB_JOURNAL = "subscriptions"
TOKEN_JOURNAL = "tokens"

_VALID_STATUSES = (STATUS_ACTIVE, STATUS_PAUSED, STATUS_REVOKED)


def _as_str_tuple(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise RailError("过滤条件必须是字符串数组", component="dispatch")
    result = tuple(str(item) for item in values if str(item) != "")
    return result


def _validate_callback(callback: str) -> str:
    if not callback.startswith(("https://", "http://")):
        raise RailError("回调地址必须是 http(s) URL", component="dispatch")
    return callback


class SubRegistry:
    """订户登记表（事件溯源）。"""

    def __init__(self, clock: Clock, journal: HashJournal, master_key: bytes) -> None:
        self._clock = clock
        self._journal = journal
        self._master_key = master_key
        self._ids = IdFactory("sub")
        self._subs: dict[str, Subscription] = {}
        self._replay()
    # ---- 读 -----------------------------------------------------------

    def get(self, sub_id: str) -> Subscription:
        sub = self._subs.get(sub_id)
        if sub is None:
            raise RailError(f"订户不存在: {sub_id}", component="dispatch")
        return sub

    def list(self) -> list[Subscription]:
        return [self._subs[key] for key in sorted(self._subs)]

    def require_live(self, sub_id: str) -> Subscription:
        sub = self.get(sub_id)
        if not sub.is_live():
            raise RailError(f"订户 {sub_id} 当前状态为 {sub.status}，不可投递", component="dispatch")
        return sub

    # ---- 写（全部落不可变流水） ---------------------------------------

    def register(
        self,
        name: str,
        callback: str,
        topics: tuple[str, ...],
        *,
        stations: tuple[str, ...] = (),
        components: tuple[str, ...] = (),
        token: str = "",
        headers: dict | None = None,
        rate_per_min: float = 0.0,
        start_seq: int = 0,
        created_by: str = "bootstrap",
    ) -> tuple[Subscription, str]:
        """登记订户，返回订户对象与一次性明文签名密钥。"""

        if not name:
            raise RailError("订户名称不能为空", component="dispatch")
        _validate_callback(callback)
        topics = topics or ("*",)
        secret = random_secret()
        now = self._clock.now()
        sub = Subscription(
            id=self._ids.next(),
            name=name,
            callback=callback,
            topics=tuple(dict.fromkeys(topics)),
            stations=_as_str_tuple(stations),
            components=_as_str_tuple(components),
            secret=secret,
            token=token,
            headers=dict(headers or {}),
            rate_per_min=max(0.0, float(rate_per_min)),
            start_seq=max(0, int(start_seq)),
            status=STATUS_ACTIVE,
            created_at=now,
            created_by=created_by,
            updated_at=now,
        )
        self._journal.append(
            {
                "kind": "sub_registered",
                "sub": self._sealed_view(sub),
            }
        )
        self._subs[sub.id] = sub
        return sub, secret

    def update(self, sub_id: str, *, created_by: str = "bootstrap", **changes: object) -> Subscription:
        """更新可变字段（地址、过滤、限流、令牌、自定义头）。"""

        current = self.get(sub_id)
        if current.status == STATUS_REVOKED:
            raise RailError("已吊销的订户不可修改，请重新登记", component="dispatch")
        fields: dict = {
            "name": str(changes["name"]) if "name" in changes else current.name,
            "callback": current.callback,
            "topics": current.topics,
            "stations": current.stations,
            "components": current.components,
            "token": current.token,
            "headers": current.headers,
            "rate_per_min": current.rate_per_min,
        }
        if "callback" in changes:
            fields["callback"] = _validate_callback(str(changes["callback"]))
        if "topics" in changes:
            topics = _as_str_tuple(changes["topics"]) or ("*",)
            fields["topics"] = tuple(dict.fromkeys(topics))
        if "stations" in changes:
            fields["stations"] = _as_str_tuple(changes["stations"])
        if "components" in changes:
            fields["components"] = _as_str_tuple(changes["components"])
        if "token" in changes:
            fields["token"] = str(changes["token"] or "")
        if "headers" in changes:
            raw_headers = changes["headers"]
            if not isinstance(raw_headers, dict):
                raise RailError("自定义认证头必须是对象", component="dispatch")
            fields["headers"] = {str(k): str(v) for k, v in raw_headers.items()}
        if "rate_per_min" in changes:
            fields["rate_per_min"] = max(0.0, float(changes["rate_per_min"]))
        updated = Subscription(
            id=current.id,
            name=fields["name"],
            callback=fields["callback"],
            topics=fields["topics"],
            stations=fields["stations"],
            components=fields["components"],
            secret=current.secret,
            token=fields["token"],
            headers=fields["headers"],
            rate_per_min=fields["rate_per_min"],
            start_seq=current.start_seq,
            status=current.status,
            created_at=current.created_at,
            created_by=current.created_by,
            updated_at=self._clock.now(),
        )
        self._journal.append(
            {
                "kind": "sub_updated",
                "sub": self._sealed_view(updated),
                "by": created_by,
            }
        )
        self._subs[sub_id] = updated
        return updated

    def set_status(
        self, sub_id: str, status: str, *, by: str = "bootstrap", reason: str = ""
    ) -> Subscription:
        """暂停、恢复或吊销订户。"""

        if status not in _VALID_STATUSES:
            raise RailError(f"非法订户状态: {status}", component="dispatch")
        current = self.get(sub_id)
        updated = Subscription(
            id=current.id,
            name=current.name,
            callback=current.callback,
            topics=current.topics,
            stations=current.stations,
            components=current.components,
            secret=current.secret,
            token=current.token,
            headers=current.headers,
            rate_per_min=current.rate_per_min,
            start_seq=current.start_seq,
            status=status,
            created_at=current.created_at,
            created_by=current.created_by,
            updated_at=self._clock.now(),
        )
        self._journal.append(
            {"kind": "sub_status", "id": sub_id, "status": status, "by": by, "reason": reason}
        )
        self._subs[sub_id] = updated
        return updated

    def rotate_secret(self, sub_id: str, *, by: str = "bootstrap") -> str:
        """轮换签名密钥，返回新明文（只出现这一次）。"""

        current = self.get(sub_id)
        secret = random_secret()
        updated = Subscription(
            id=current.id,
            name=current.name,
            callback=current.callback,
            topics=current.topics,
            stations=current.stations,
            components=current.components,
            secret=secret,
            token=current.token,
            headers=current.headers,
            rate_per_min=current.rate_per_min,
            start_seq=current.start_seq,
            status=current.status,
            created_at=current.created_at,
            created_by=current.created_by,
            updated_at=self._clock.now(),
        )
        self._journal.append({"kind": "sub_rotated", "id": sub_id, "sub": self._sealed_view(updated), "by": by})
        self._subs[sub_id] = updated
        return secret

    # ---- 凭据落盘 -----------------------------------------------------

    def _sealed_view(self, sub: Subscription) -> dict:
        """把订户序列化成流水记录，敏感字段全部加密。"""

        view = sub.public_view()
        view["secret_sealed"] = seal(sub.secret.encode("utf-8"), self._master_key)
        if sub.token:
            view["token_sealed"] = seal(sub.token.encode("utf-8"), self._master_key)
        if sub.headers:
            view["headers_sealed"] = seal(
                json.dumps(sub.headers, ensure_ascii=False).encode("utf-8"), self._master_key
            )
        return view

    def _unseal_sub(self, record: dict) -> Subscription:
        secret = open_seal(str(record["secret_sealed"]), self._master_key).decode("utf-8")
        token = ""
        if record.get("token_sealed"):
            token = open_seal(str(record["token_sealed"]), self._master_key).decode("utf-8")
        headers: dict = {}
        if record.get("headers_sealed"):
            raw = open_seal(str(record["headers_sealed"]), self._master_key)
            loaded = json.loads(raw.decode("utf-8"))
            headers = loaded if isinstance(loaded, dict) else {}
        return Subscription(
            id=str(record["id"]),
            name=str(record["name"]),
            callback=str(record["callback"]),
            topics=tuple(str(item) for item in record.get("topics", ["*"])),
            stations=tuple(str(item) for item in record.get("stations", [])),
            components=tuple(str(item) for item in record.get("components", [])),
            secret=secret,
            token=token,
            headers=headers,
            rate_per_min=float(record.get("rate_per_min", 0.0)),
            start_seq=int(record.get("start_seq", 0)),
            status=str(record.get("status", STATUS_ACTIVE)),
            created_at=float(record.get("created_at", 0.0)),
            created_by=str(record.get("created_by", "replay")),
            updated_at=float(record.get("updated_at", 0.0)),
        )

    # ---- 回放（崩溃安全的来源） ---------------------------------------

    def _replay(self) -> None:
        for record in self._journal.replay():
            kind = str(record.get("kind"))
            if kind in ("sub_registered", "sub_updated", "sub_rotated"):
                sub = self._unseal_sub(record["sub"])
                self._subs[sub.id] = sub
            elif kind == "sub_status":
                current = self._subs[str(record["id"])]
                self._subs[current.id] = Subscription(
                    id=current.id,
                    name=current.name,
                    callback=current.callback,
                    topics=current.topics,
                    stations=current.stations,
                    components=current.components,
                    secret=current.secret,
                    token=current.token,
                    headers=current.headers,
                    rate_per_min=current.rate_per_min,
                    start_seq=current.start_seq,
                    status=str(record["status"]),
                    created_at=current.created_at,
                    created_by=current.created_by,
                    updated_at=current.updated_at,
                )


class TokenRegistry:
    """管理 API 令牌表（只存散列）。"""

    def __init__(self, clock: Clock, journal: HashJournal) -> None:
        self._clock = clock
        self._journal = journal
        self._ids = IdFactory("tok")
        self._tokens: dict[str, Token] = {}
        self._replay()

    def list(self) -> list[Token]:
        return [self._tokens[key] for key in sorted(self._tokens)]

    def issue(self, label: str, scope: str, *, created_by: str = "bootstrap") -> tuple[Token, str]:
        """签发令牌，返回 ``(对象, 一次性明文)``。"""

        if not label:
            raise RailError("令牌标签不能为空", component="dispatch")
        if scope not in SCOPES:
            raise RailError(f"令牌权限必须是 {SCOPES} 之一", component="dispatch")
        raw, secret_hash = random_token()
        token = Token(
            id=self._ids.next(),
            label=label,
            scope=scope,
            secret_hash=secret_hash,
            created_at=self._clock.now(),
            created_by=created_by,
        )
        self._journal.append(
            {
                "kind": "token_issued",
                "id": token.id,
                "label": token.label,
                "scope": token.scope,
                "secret_hash": token.secret_hash,
                "at": token.created_at,
                "by": created_by,
            }
        )
        self._tokens[token.id] = token
        return token, raw

    def revoke(self, token_id: str, *, by: str = "bootstrap") -> Token:
        token = self._tokens.get(token_id)
        if token is None:
            raise RailError(f"令牌不存在: {token_id}", component="dispatch")
        if token.revoked:
            return token
        updated = Token(
            id=token.id,
            label=token.label,
            scope=token.scope,
            secret_hash=token.secret_hash,
            created_at=token.created_at,
            created_by=token.created_by,
            revoked=True,
        )
        self._journal.append({"kind": "token_revoked", "id": token_id, "at": self._clock.now(), "by": by})
        self._tokens[token_id] = updated
        return updated

    def authenticate(self, presented: str, required: tuple[str, ...]) -> Token:
        """校验明文令牌并检查权限；失败抛 ``unauthorized`` 或 ``forbidden``。"""

        from .crypto import compare_token

        matched: Token | None = None
        for token in self._tokens.values():
            if not token.revoked and compare_token(token.secret_hash, presented):
                matched = token
                break
        if matched is None:
            raise RailError("令牌缺失、无效或已吊销", component="unauthorized")
        if matched.scope not in required:
            raise RailError(
                f"令牌权限 {matched.scope} 不足，需要 {required} 之一", component="forbidden"
            )
        return matched

    # ---- 回放 ---------------------------------------------------------

    def _replay(self) -> None:
        for record in self._journal.replay():
            kind = str(record.get("kind"))
            if kind == "token_issued":
                token = Token(
                    id=str(record["id"]),
                    label=str(record["label"]),
                    scope=str(record["scope"]),
                    secret_hash=str(record["secret_hash"]),
                    created_at=float(record["at"]),
                    created_by=str(record.get("by", "replay")),
                )
                self._tokens[token.id] = token
            elif kind == "token_revoked":
                current = self._tokens[str(record["id"])]
                self._tokens[current.id] = Token(
                    id=current.id,
                    label=current.label,
                    scope=current.scope,
                    secret_hash=current.secret_hash,
                    created_at=current.created_at,
                    created_by=current.created_by,
                    revoked=True,
                )


# 供权限矩阵引用的最小权限集合常量。
READ_SCOPES = (SCOPE_ADMIN, SCOPE_OPS, SCOPE_AUDITOR)
