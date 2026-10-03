"""安全原语：凭据生成、哈希、HMAC 签名、规范化 JSON。

凭据（API token、HMAC 密钥）只在创建时返回明文一次；库里只存 SHA-256，拖库
也无法冒用。投递请求体用订户密钥做 HMAC-SHA256 签名（``X-Signature`` 头），
订户侧应校验签名，保证事件来自本系统且未被篡改。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets


def new_token(length: int = 32) -> str:
    """生成 URL 安全的随机凭据（默认 256 位熵）。"""

    if length < 16:
        raise ValueError("凭据长度至少 16 字节")
    return secrets.token_urlsafe(length)


def sha256_hex(value: str) -> str:
    """计算字符串的 SHA-256 十六进制摘要（用于凭据落库）。"""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sign_body(secret: str, timestamp: str, body: bytes) -> str:
    """计算投递请求签名。

    签名内容为 ``f"{timestamp}.{body}"``，与 ``X-Signature-Timestamp`` 头配套，
    订户侧应限制时间戳新鲜度以防重放。
    """

    digest = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    digest.update(timestamp.encode("ascii"))
    digest.update(b".")
    digest.update(body)
    return digest.hexdigest()


def canonical_json(payload: object) -> str:
    """规范化 JSON：键排序、紧凑分隔、不转义非 ASCII。

    事件正文、审计明细都用它编码，保证「同一个对象在任何时刻编码结果一致」，
    审计哈希链与签名才稳定可复算。
    """

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
