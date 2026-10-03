"""对外事件投递：哈希链、幂等、退避死信、恢复、权限。"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from psdline.app import build_platform
from psdline.clock import ManualClock
from psdline.config import default_config
from psdline.dispatch import (
    build_request,
    classify,
    idempotency_key,
)
from psdline.dispatch.crypto import (
    aes256_encrypt_block,
    compare_token,
    hash_token,
    open_seal,
    random_secret,
    random_token,
    seal,
)
from psdline.dispatch.dispatcher import backoff_delay
from psdline.dispatch.envelope import sign
from psdline.dispatch.ledger import GENESIS, HashJournal, chain_hash
from psdline.dispatch.model import StoredEvent
from psdline.dispatch.outbox import Outbox
from psdline.dispatch.ratelimit import RateLimiter
from psdline.dispatch.registry import SubRegistry, TokenRegistry
from psdline.dispatch.transport import DeliveryResult


# ---- 加密 ----------------------------------------------------------------

def test_aes256_nist_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes256_encrypt_block(plain, key).hex() == "8ea2b7ca516745bfeafc49904b496089"


def test_seal_roundtrip_and_tamper():
    master = b"k" * 32
    sealed = seal("机密".encode(), master)
    assert open_seal(sealed, master).decode() == "机密"
    with pytest.raises(Exception):
        open_seal(sealed, b"x" * 32)


def test_token_hash_only_and_constant_time_compare():
    raw, digest = random_token()
    assert raw.startswith("psdl_")
    assert digest == hash_token(raw.removeprefix("psdl_"))
    assert compare_token(digest, raw)
    assert not compare_token(digest, raw + "x")
    assert len(random_secret()) == 64


# ---- 哈希链 --------------------------------------------------------------

def test_hash_chain_detects_tamper_and_truncation(tmp_path):
    journal = HashJournal(str(tmp_path), "events")
    for index in range(3):
        journal.append({"n": index})
    path = os.path.join(str(tmp_path), "events-00000.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    envelope = json.loads(lines[1])
    envelope["record"]["n"] = 99
    open(path, "w", encoding="utf-8").write(
        "\n".join([lines[0], json.dumps(envelope, ensure_ascii=False), *lines[2:]]) + "\n"
    )
    with pytest.raises(Exception):
        HashJournal(str(tmp_path), "events")


def test_hash_chain_spans_segments(tmp_path):
    journal = HashJournal(str(tmp_path), "seg", segment_limit=2)
    for index in range(5):
        journal.append({"n": index})
    reopened = HashJournal(str(tmp_path), "seg", segment_limit=2)
    assert [item["n"] for item in reopened.replay()] == [0, 1, 2, 3, 4]
    assert reopened.tail == journal.tail


# ---- 出箱：去重与序号 ----------------------------------------------------

def test_outbox_deduplicates_same_event_id(clock, tmp_path):
    outbox = Outbox(clock, HashJournal(str(tmp_path), "events"))
    first, was_new = outbox.ingest("door", "door", "opened", {"x": 1}, event_id="evt-1")
    assert was_new and first.seq == 1
    again, was_new = outbox.ingest("door", "door", "opened", {"x": 2}, event_id="evt-1")
    assert not was_new and again.seq == 1 and again.payload == {"x": 1}
    assert outbox.head_seq == 1


def test_outbox_auto_ids_are_unique(clock, tmp_path):
    outbox = Outbox(clock, HashJournal(str(tmp_path), "events"))
    outbox.ingest("door", "door", "opened", {})
    outbox.ingest("door", "door", "closed", {})
    assert outbox.head_seq == 2
    ids = {event.id for event in outbox.all()}
    assert len(ids) == 2


# ---- 信封：幂等键与签名 --------------------------------------------------

def test_idempotency_key_stable_across_retries():
    event = StoredEvent(seq=7, id="evt", topic="door", component="door", action="opened", at=1.0)
    key1 = idempotency_key("sub-1", event)
    key2 = idempotency_key("sub-1", event)
    assert key1 == "sub-1:7" == key2
    assert idempotency_key("sub-2", event) == "sub-2:7"


def test_request_envelope_carries_hmac_signature():
    registry = _registry()
    sub, secret = registry.register(
        name="n", callback="https://ext/hook", topics=("door",), created_by="t"
    )
    event = StoredEvent(seq=1, id="e1", topic="door", component="door", action="opened", at=1.0)
    body, headers = build_request(sub, event)
    payload = json.loads(body)
    assert payload["id"] == "e1"
    assert headers["Idempotency-Key"] == f"{sub.id}:1"
    assert headers["Signature"] == sign(secret, body)
    assert classify(200) == "ack"
    assert classify(503) == "retry"
    assert classify(410) == "reject"
    assert classify(429) == "retry"


def _registry():
    root = tempfile.mkdtemp()
    return SubRegistry(ManualClock(), HashJournal(root, "subs"), b"k" * 32)


# ---- 订户凭据落盘加密 ----------------------------------------------------

def test_subscriber_secret_is_sealed_on_disk(clock, tmp_path):
    journal = HashJournal(str(tmp_path), "subs")
    registry = SubRegistry(clock, journal, b"k" * 32)
    sub, secret = registry.register(
        name="n",
        callback="https://ext/hook",
        topics=("door",),
        token="bearer-xyz",
        headers={"X-Tenant": "acme"},
        created_by="t",
    )
    raw = open(os.path.join(str(tmp_path), "subs-00000.jsonl"), encoding="utf-8").read()
    assert secret not in raw
    assert "bearer-xyz" not in raw
    assert "acme" not in raw
    reopened = SubRegistry(clock, HashJournal(str(tmp_path), "subs"), b"k" * 32)
    restored = reopened.get(sub.id)
    assert restored.secret == secret
    assert restored.token == "bearer-xyz"
    assert restored.headers == {"X-Tenant": "acme"}
    assert "secret" not in sub.public_view()


def test_token_scope_matrix(clock, tmp_path):
    tokens = TokenRegistry(clock, HashJournal(str(tmp_path), "tokens"))
    _, raw = tokens.issue("root", "admin")
    with pytest.raises(Exception):
        tokens.authenticate("nope", ("admin",))
    token = tokens.authenticate(raw, ("admin",))
    assert token.scope == "admin"
    tokens.revoke(token.id)
    with pytest.raises(Exception):
        tokens.authenticate(raw, ("admin",))


# ---- 退避与限流 ----------------------------------------------------------

def test_exponential_backoff_caps():
    assert backoff_delay(1, 1.0, 300.0) == 1.0
    assert backoff_delay(2, 1.0, 300.0) == 2.0
    assert backoff_delay(3, 1.0, 300.0) == 4.0
    assert backoff_delay(20, 1.0, 300.0) == 300.0


def test_rate_limiter_burst_and_refill(clock):
    limiter = RateLimiter(clock)
    limiter.configure("s", 120.0, burst=1.0)
    limiter.set_global(0.0)
    assert limiter.acquire("s", timeout=0.0)
    assert not limiter.acquire("s", timeout=0.0)
    clock.advance(0.5)  # 半分钟补一个
    assert limiter.acquire("s", timeout=0.0)


def test_in_flight_delivery_is_not_redispatched_while_worker_alive(platform):
    """慢回调未返回时，后续 pump 绝不能对同一事件发第二次（避免同进程重复投递）。"""

    import threading

    service = platform.dispatch
    service.register_subscriber(by="t", name="ext", callback="http://x/hook", topics=("door",))
    sub_id = service.subscriptions.list()[0].id
    platform.arrive("T01", "ST1", 0)

    entered = threading.Event()
    release = threading.Event()

    class SlowSender:
        def __init__(self):
            self.calls = 0
            self.keys: list[str] = []

        def post(self, url, body, headers, timeout):
            self.calls += 1
            self.keys.append(headers["Idempotency-Key"])
            entered.set()
            release.wait(timeout=2.0)
            return DeliveryResult(ok=True, kind="ack", status=200)

    slow = SlowSender()
    service.dispatcher._sender = slow
    service.dispatcher.start()
    try:
        assert entered.wait(timeout=2.0)
        # 回调还没返回：反复 pump 都不得重派当前事件
        for _ in range(5):
            service.dispatcher._pump()
        assert slow.calls == 1, slow.calls
        keys_during_block = list(slow.keys)
        release.set()
        for _ in range(100):
            if service.dispatcher.summary()["in_flight"] == 0:
                break
            __import__("time").sleep(0.02)
    finally:
        service.dispatcher.stop()
    assert len(keys_during_block) == 1
    # 阻塞期间在投的那条，之后不允许出现第二次
    assert slow.keys.count(keys_during_block[0]) == 1
    assert len(slow.keys) == len(set(slow.keys))  # 全程无重复投递
    assert service.status()["per_subscriber"][sub_id]["next_seq"] == service.outbox.head_seq


# ---- 端到端投递（假 HTTP 端） -------------------------------------------

class _Collector:
    def __init__(self):
        self.received = {}
        self.bodies = []
        self.fail_times = 0
        self.status = 200
        self.lock = threading.Lock()


_COLLECTOR = _Collector()


class _CollectHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        key = self.headers.get("Idempotency-Key", "")
        with _COLLECTOR.lock:
            _COLLECTOR.received[key] = _COLLECTOR.received.get(key, 0) + 1
            _COLLECTOR.bodies.append(body)
            if _COLLECTOR.fail_times > 0:
                _COLLECTOR.fail_times -= 1
                code = 503
            else:
                code = _COLLECTOR.status
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"{}")


@pytest.fixture()
def endpoint():
    _COLLECTOR.received.clear()
    _COLLECTOR.bodies.clear()
    _COLLECTOR.fail_times = 0
    _COLLECTOR.status = 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def _platform(tmp_path, clock):
    return build_platform(default_config(), clock=clock, storage_root=str(tmp_path / "state"))


def test_delivers_in_order_with_signature(endpoint, platform):
    service = platform.dispatch
    reg = service.register_subscriber(
        by="t", name="ext", callback=f"http://127.0.0.1:{endpoint.server_address[1]}/hook",
        topics=("door",),
    )
    platform.arrive("T01", "ST1", 0)
    service.pump_once()
    summary = service.status()["per_subscriber"][reg["subscriber"]["id"]]
    assert summary["next_seq"] == service.outbox.head_seq
    assert all(count == 1 for count in _COLLECTOR.received.values())
    body = _COLLECTOR.bodies[0]
    headers_seen = {key for key in ("Idempotency-Key",)}
    assert headers_seen == {"Idempotency-Key"}
    assert sign(reg["secret_once"], body).startswith("sha256=")


class _StaticSender:
    def __init__(self, result: DeliveryResult):
        self.result = result
        self.calls = 0

    def post(self, url, body, headers, timeout):
        self.calls += 1
        return self.result


def test_failures_retry_then_dead_letter_and_manual_replay(tmp_path, clock):
    import dataclasses

    config = dataclasses.replace(
        default_config(),
        dispatch=dataclasses.replace(
            default_config().dispatch, max_attempts=3, base_backoff_s=0.01, max_backoff_s=0.01
        ),
    )
    platform = build_platform(config, clock=clock, storage_root=str(tmp_path / "state"))
    service = platform.dispatch
    reg = service.register_subscriber(by="t", name="ext", callback="http://x/hook", topics=("door",))
    sub_id = reg["subscriber"]["id"]
    platform.arrive("T01", "ST1", 0)

    flaky = _StaticSender(DeliveryResult(ok=False, kind="retry", status=503, reason="503"))
    dispatcher = service.dispatcher
    dispatcher._sender = flaky
    dispatcher.reset_for(sub_id, 0, by="t")
    for _ in range(3):
        dispatcher.pump_once()
        clock.advance(0.02)
    assert flaky.calls == 3
    dead = dispatcher.dead_letters()
    assert len(dead) == 1 and dead[0]["event_seq"] == 1

    ok = _StaticSender(DeliveryResult(ok=True, kind="ack", status=200))
    dispatcher._sender = ok
    result = service.replay_dead(sub_id, by="ops")
    assert result["replayed"]
    assert not dispatcher.dead_letters()
    assert dispatcher.summary()["per_subscriber"][sub_id]["next_seq"] == service.outbox.head_seq


def test_permanent_reject_goes_dead_immediately(platform):
    service = platform.dispatch
    service.register_subscriber(by="t", name="ext", callback="http://x/hook", topics=("door",))
    sub_id = service.subscriptions.list()[0].id
    platform.arrive("T01", "ST1", 0)
    dispatcher = service.dispatcher
    dispatcher._sender = _StaticSender(DeliveryResult(ok=False, kind="reject", status=410, reason="410"))
    dispatcher.reset_for(sub_id, 0, by="t")
    dispatcher.pump_once()
    dead = dispatcher.dead_letters()
    assert len(dead) == 1 and dead[0]["permanent"] is True


def test_crash_recovery_resumes_cursor_without_redelivery(platform):
    service = platform.dispatch
    reg = service.register_subscriber(by="t", name="ext", callback="http://x/hook", topics=("door",))
    sub_id = reg["subscriber"]["id"]
    platform.arrive("T01", "ST1", 0)
    service.dispatcher._sender = _StaticSender(DeliveryResult(ok=True, kind="ack", status=200))
    service.pump_once()
    head = service.outbox.head_seq
    assert service.status()["per_subscriber"][sub_id]["next_seq"] == head

    root = platform.store.root
    restarted = build_platform(default_config(), clock=platform.clock, storage_root=root)
    assert restarted.dispatch.status()["per_subscriber"][sub_id]["next_seq"] == head
    assert restarted.dispatch.outbox.head_seq == head


def test_revoked_and_paused_subscribers_are_not_delivered(platform):
    service = platform.dispatch
    reg = service.register_subscriber(by="t", name="ext", callback="http://x/hook", topics=("door",))
    service.pause_subscriber(reg["subscriber"]["id"], by="t")
    platform.arrive("T01", "ST1", 0)
    service.pump_once()
    cursor = service.status()["per_subscriber"][reg["subscriber"]["id"]]
    assert cursor["next_seq"] == 0
    service.resume_subscriber(reg["subscriber"]["id"], by="t", from_seq=0)
    dispatcher = service.dispatcher
    dispatcher._sender = _StaticSender(DeliveryResult(ok=True, kind="ack", status=200))
    dispatcher.pump_once()
    assert dispatcher.summary()["per_subscriber"][reg["subscriber"]["id"]]["next_seq"] >= 1


def test_filter_by_station_and_topic(platform):
    service = platform.dispatch
    only_st1 = service.register_subscriber(
        by="t", name="only-st1", callback="http://x/hook",
        topics=("door",), stations=("ST1",),
    )["subscriber"]["id"]
    other = service.register_subscriber(
        by="t", name="all", callback="http://x/hook", topics=("door",),
    )["subscriber"]["id"]
    platform.arrive("T01", "ST1", 0)
    dispatcher = service.dispatcher
    dispatcher._sender = _StaticSender(DeliveryResult(ok=True, kind="ack", status=200))
    dispatcher.pump_once()
    head = service.outbox.head_seq
    assert dispatcher.summary()["per_subscriber"][only_st1]["next_seq"] == head
    assert dispatcher.summary()["per_subscriber"][other]["next_seq"] == head

    # ST2 的 door 事件对 only-st1 是越过、对 other 是投递；两者游标都到 head
    platform.arrive("T02", "ST2", 24)
    dispatcher.pump_once()
    head2 = service.outbox.head_seq
    assert dispatcher.summary()["per_subscriber"][only_st1]["next_seq"] == head2
    assert dispatcher.summary()["per_subscriber"][other]["next_seq"] == head2


def test_topic_filter_skips_unmatched_events_without_blocking(clock, tmp_path):
    """不匹配的事件必须越过游标，不能把链卡死。"""

    platform = _platform(tmp_path, clock)
    service = platform.dispatch
    service.register_subscriber(by="t", name="audit-only", callback="http://x/hook", topics=("audit",))
    # 先制造 door 事件（订户不关心），再制造 audit 事件
    platform.arrive("T01", "ST1", 0)
    dispatcher = service.dispatcher
    dispatcher._sender = _StaticSender(DeliveryResult(ok=True, kind="ack", status=200))
    dispatcher.pump_once()
    sub_id = service.subscriptions.list()[0].id
    cursor = dispatcher.summary()["per_subscriber"][sub_id]
    # door 事件被越过，游标到达 head，链不被卡住
    assert cursor["next_seq"] == service.outbox.head_seq
