"""投递子系统测试支撑：模拟订户 HTTP 端点与可编排传输。

``MockSubscriber`` 是一个真实的本地 HTTP 服务，按 ``Event-ID`` 记录去重后的
收讫序列，并可编排「前 N 次失败 / 410 / 慢响应」；``ScriptedTransport`` 不走
网络，直接按调用脚本返回，用于精确控制崩溃与租约交接。
"""

from __future__ import annotations

import json
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from psdline.webhook.transport import SendResult


class ScriptedTransport:
    """按调用脚本返回结果的传输（可选在指定调用处挂住模拟崩溃）。"""

    def __init__(self, script=None, block_on: int | None = None) -> None:
        self._script = deque(script or [])
        self.calls: list[tuple[str, dict]] = []
        self.bodies: list[dict] = []
        self._lock = threading.Lock()
        self._block = threading.Event()
        self._block_on = block_on
        if block_on is None:
            self._block.set()

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> SendResult:
        with self._lock:
            index = len(self.calls)
            self.calls.append((url, dict(headers)))
            self.bodies.append(json.loads(body.decode("utf-8")))
        if self._block_on is not None and index + 1 == self._block_on:
            # 模拟 worker 拿到租约后在传输中崩溃：一直阻塞到测试放行。
            self._block.wait(timeout=10)
            return SendResult(ok=False, error="worker 崩溃（连接中断）")
        if self._script:
            outcome = self._script.popleft()
            if isinstance(outcome, Exception):
                raise outcome
            if isinstance(outcome, tuple):
                return SendResult(ok=outcome[0], status=outcome[1],
                                  error=outcome[2] if len(outcome) > 2 else "",
                                  permanent=len(outcome) > 3 and outcome[3])
            return outcome
        return SendResult(ok=True, status=200)

    def release_crash(self) -> None:
        self._block.set()


class _CollectorHandler(BaseHTTPRequestHandler):
    server_version = "mock-subscriber/1.0"

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        envelope = json.loads(raw.decode("utf-8"))
        state = self.server.state  # type: ignore[attr-defined]
        with state["lock"]:
            state["calls"].append({
                "event_id": self.headers["Event-ID"],
                "delivery_id": self.headers["Delivery-ID"],
                "attempt": int(self.headers["Delivery-Attempt"]),
                "signature": self.headers.get("X-Signature", ""),
                "timestamp": self.headers.get("X-Signature-Timestamp", ""),
                "seq": envelope["seq"],
                "aggregate_key": envelope["aggregate_key"],
                "body": envelope,
            })
            seen = state["seen_event_ids"]
            duplicate = envelope["id"] in seen
            state["duplicates"] += int(duplicate)
            seen.add(envelope["id"])
            fail_until = state["fail_until"]
            gone_until = state["gone_until"]
            order = state["order"]
            order.append(envelope["id"])
            if state["slow"]:
                delay = state["slow"]
                state["slow"] = 0.0
                event = threading.Event()
                event.wait(timeout=delay)
        if gone_until and len(state["calls"]) <= gone_until:
            self._reply(410, {"error": "gone"})
            return
        if fail_until and len(state["calls"]) <= fail_until:
            self._reply(500, {"error": "scripted failure"})
            return
        if duplicate:
            self._reply(200, {"deduped": True})
        else:
            self._reply(200, {"received": envelope["id"]})

    def _reply(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class MockSubscriber:
    """带收讫状态的模拟订户服务。"""

    def __init__(self) -> None:
        self.state = {
            "lock": threading.Lock(),
            "calls": [],
            "seen_event_ids": set(),
            "duplicates": 0,
            "order": [],
            "fail_until": 0,
            "gone_until": 0,
            "slow": 0.0,
        }
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectorHandler)
        self._server.state = self.state  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/hook"

    def fail_next(self, count: int) -> None:
        """接下来的 count 次调用返回 500。"""

        self.state["fail_until"] = len(self.state["calls"]) + count

    def gone_next(self, count: int = 1) -> None:
        self.state["gone_until"] = len(self.state["calls"]) + count

    def slow_next(self, seconds: float) -> None:
        self.state["slow"] = seconds

    @property
    def event_ids(self) -> list[str]:
        with self.state["lock"]:
            return [call["event_id"] for call in self.state["calls"]]

    @property
    def deduped_event_ids(self) -> list[str]:
        with self.state["lock"]:
            seen: set[str] = set()
            ordered = []
            for call in self.state["calls"]:
                if call["event_id"] not in seen:
                    seen.add(call["event_id"])
                    ordered.append(call["event_id"])
            return ordered

    @property
    def duplicate_deliveries(self) -> int:
        return self.state["duplicates"]

    @property
    def calls(self) -> list[dict]:
        with self.state["lock"]:
            return list(self.state["calls"])

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
