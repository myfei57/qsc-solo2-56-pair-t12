"""投递传输层：把打好包的事件 POST 给订户。

成功判定：HTTP 2xx。``410 Gone`` 视为订户永久弃收，直接进死信不再退避；其它
非 2xx、连接错误、超时都可重试。传输不关心重试策略与状态机，只返回
:class:`SendResult`，决策在 :mod:`psdline.webhook.dispatcher`。
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class SendResult:
    """一次投递的传输结果。"""

    ok: bool
    status: int | None = None
    error: str = ""
    permanent: bool = False


class HttpTransport:
    """标准库实现的 HTTP POST 传输。"""

    def __init__(self, timeout_s: float = 10.0) -> None:
        self._timeout = float(timeout_s)

    def send(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> SendResult:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = int(response.status)
                response.read()
                if 200 <= status < 300:
                    return SendResult(ok=True, status=status)
                return SendResult(ok=False, status=status, error=f"HTTP {status}")
        except urllib.error.HTTPError as error:
            status = int(error.code)
            try:
                error.read()
            except OSError:
                pass
            if status == 410:
                return SendResult(ok=False, status=status, error="HTTP 410 永久弃收",
                                  permanent=True)
            return SendResult(ok=False, status=status, error=f"HTTP {status}")
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as error:
            return SendResult(ok=False, error=f"网络错误: {error}")
