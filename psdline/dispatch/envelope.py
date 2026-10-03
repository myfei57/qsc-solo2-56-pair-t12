"""事件打包与回调签名。

取舍：**逐条投递、按发生顺序**。每个订户一条链，未确认序号会阻塞其后的事件，
因此不会乱序；失败重试只重发当前这一条。批投虽然吞吐高，但一旦部分失败就得
拆批或重复整批，幂等与确认语义都更绕，门控事件量级下逐条更稳，吞吐用并发
（不同订户之间）补。

请求约定（订户按此对接）：

* ``POST <callback>``，``Content-Type: application/json; charset=utf-8``；
* 请求体是 :class:`~psdline.dispatch.model.StoredEvent` 的信封 JSON；
* ``Idempotency-Key`` 恒等重发：订户必须按它去重，同 key 只有第一次生效；
* ``Signature: sha256=<HMAC-SHA256(secret, 规范请求体)>``，验签防伪造；
* 订户返回 2xx 即确认；5xx / 连接失败退避重试；401、403、404、410 视为永久
  拒绝，直接进死信，其余 4xx 按可重试处理（多为限流或暂态校验失败）。
"""

from __future__ import annotations

import hashlib
import hmac
import json

from .model import StoredEvent, Subscription

SIGNATURE_VERSION = "sha256"
PERMANENT_STATUS = frozenset({401, 403, 404, 410})
ACK_STATUS = frozenset(range(200, 300))


def idempotency_key(sub_id: str, event: StoredEvent) -> str:
    """同订户同事件的任何重发，key 完全一致（订户据此做幂等）。"""

    return f"{sub_id}:{event.seq}"


def encode_body(event: StoredEvent) -> bytes:
    """把事件信封序列化成请求体（排序键，签名与线上字节一致）。"""

    return json.dumps(event.core(), ensure_ascii=False, sort_keys=True).encode("utf-8")


def sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def build_request(sub: Subscription, event: StoredEvent) -> tuple[bytes, dict]:
    """组装一次投递的请求体与请求头。"""

    body = encode_body(event)
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Idempotency-Key": idempotency_key(sub.id, event),
        "PSDLine-Event-ID": event.id,
        "PSDLine-Event-Seq": str(event.seq),
        "PSDLine-Delivery": "v1",
        "Signature": sign(sub.secret, body),
    }
    for name, value in sub.headers.items():
        headers[str(name)] = str(value)
    if sub.token:
        headers["Authorization"] = f"Bearer {sub.token}"
    return body, headers


def classify(status: int) -> str:
    """把 HTTP 状态码归类成 ``ack`` / ``retry`` / ``reject``。"""

    if status in ACK_STATUS:
        return "ack"
    if status in PERMANENT_STATUS:
        return "reject"
    return "retry"
