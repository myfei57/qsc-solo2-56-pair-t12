"""出站 HTTP 投递通道。

生产实现用标准库 ``urllib``（零三方依赖）；测试与演练可注入任何实现
:class:`Sender` 协议的假通道，模拟 200、503、超时、网络错误，无需真开端口。
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class DeliveryResult:
    """一次投递尝试的结果。"""

    ok: bool
    kind: str
    status: int = 0
    reason: str = ""

    @property
    def permanent(self) -> bool:
        """永久失败（401/403/404/410），不再退避，直接进死信。"""

        return self.kind == "reject"


class Sender(Protocol):
    """投递通道协议：发一次 POST，返回结构化结果（不抛异常）。"""

    def post(self, url: str, body: bytes, headers: dict, timeout: float) -> DeliveryResult: ...


class HttpSender:
    """``urllib`` 实现的真实投递通道。"""

    def post(self, url: str, body: bytes, headers: dict, timeout: float) -> DeliveryResult:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                response.read()
        except urllib.error.HTTPError as error:
            kind = _classify_status(int(error.code))
            return DeliveryResult(
                ok=kind == "ack", kind=kind, status=int(error.code), reason=f"HTTP {error.code}"
            )
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as error:
            return DeliveryResult(ok=False, kind="retry", reason=f"network: {error}")
        kind = _classify_status(status)
        return DeliveryResult(ok=kind == "ack", kind=kind, status=status, reason=f"HTTP {status}")


def _classify_status(status: int) -> str:
    from .envelope import PERMANENT_STATUS

    if 200 <= status < 300:
        return "ack"
    if status in PERMANENT_STATUS:
        return "reject"
    return "retry"
