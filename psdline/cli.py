"""命令行入口。

五个子命令覆盖日常使用：

``serve``   启动控制台 HTTP 服务，可选地在启动后探测接口；
``demo``    在本地跑一遍完整流程（到站开门 → 间隙探测 → 发车 → 批量开门 →
            门区联动 → 故障置位与解除 → 序号回绕 → 控制周期 → 清扫），用于交付
            前的真实运行检查；
``status``  打印当前状态快照；
``config``  打印生效配置；
``reset``   清掉落盘的平台计数。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time

from .app import Platform, build_platform
from .clock import ManualClock, SystemClock
from .config import config_to_mapping, default_config, load_config
from .console.server import ConsoleServer, probe_endpoints
from .errors import RailError
from .webhook.server import WebhookServer
from .webhook.service import (
    SCOPE_ADMIN,
    SCOPE_INGEST,
    SCOPE_SUBSCRIBER,
    Principal,
    WebhookService,
)

DEFAULT_PROBE_PATHS = ("/api/status", "/api/readiness", "/api/stations", "/", "/alarms")


def _build(args: argparse.Namespace) -> Platform:
    config = load_config(args.config) if getattr(args, "config", None) else default_config()
    if getattr(args, "storage_root", None):
        return build_platform(config, storage_root=args.storage_root)
    return Platform(config=config)


def _dump(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _cmd_serve(args: argparse.Namespace) -> int:
    platform = _build(args)
    server = ConsoleServer(platform, host=args.host, port=args.port)
    base_url = server.start()
    payload: dict = {"listening": base_url, "routes": server.api.routes()}
    webhook_server = None
    if getattr(args, "webhook", False) or platform.config.webhook.enabled:
        service = platform.enable_webhooks(autostart=True)
        section = platform.config.webhook
        webhook_server = WebhookServer(service, host=args.webhook_host or section.host,
                                       port=args.webhook_port or section.port)
        payload["webhook"] = webhook_server.start()
    if args.probe:
        payload["probe"] = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    _dump(payload)

    def finish() -> None:
        if webhook_server is not None:
            webhook_server.stop()
        platform.shutdown()
        server.stop()

    if args.duration > 0:
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:  # pragma: no cover - 交互路径
            pass
        finish()
        return 0
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover - 交互路径
        finish()
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    clock = ManualClock() if args.fast else SystemClock()
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    storage_root = getattr(args, "storage_root", None) or tempfile.mkdtemp(prefix="psdline-demo-")
    platform = build_platform(config, clock=clock, storage_root=storage_root)

    startup = platform.start()
    arrival = platform.arrive(args.train, args.station, 0)
    position = platform.refresh_position(args.train, 12)
    gap = platform.check_gap(args.train)
    queued = platform.enqueue(args.train, "cmd-1", "open", args.station)
    processed = platform.process_queue(args.train)
    swept = platform.sweep(args.station)
    fault = platform.set_fault(_first_gate(platform, args.station))
    cleared = platform.clear_fault(_first_gate(platform, args.station))
    batched = platform.batch_open(args.station)
    renumber = platform.renumber(args.station, _mirror_mapping(platform, args.station))
    sequence = platform.sequence_verdict(65534, 4)
    dwell = platform.register_dwell(args.train, 45.0, args.station)
    route = platform.assign_route(args.train, args.station, _next_station(platform, args.station), 1200)
    departure = platform.depart(args.train, args.station)
    cycles = [platform.cycle(dt=args.dt) for _ in range(args.cycles)]
    final_sweep = platform.sweep(args.station)

    # 演示自检用临时端口，避免和本机常驻服务抢 8080。
    server = ConsoleServer(platform, port=0)
    base_url = server.start()
    probe = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    server.stop()

    report = {
        "storage_root": storage_root,
        "startup": startup,
        "arrival": {key: arrival[key] for key in ("ok", "position_m", "violations")},
        "position": position,
        "gap": gap,
        "queued": {key: queued[key] for key in ("ok", "train_id")},
        "processed": processed,
        "swept": swept,
        "batch": {key: batched[key] for key in ("ok", "order", "opened", "nearest")},
        "renumber": {key: renumber[key] for key in ("ok", "revision", "active_group")},
        "fault": fault,
        "cleared": cleared,
        "sequence": sequence,
        "dwell": dwell,
        "route": route,
        "departure": departure,
        "cycles_run": len(cycles),
        "last_cycle": cycles[-1],
        "final_sweep": {key: final_sweep[key] for key in ("closed", "scanned")},
        "probe": probe,
        "status": platform.status(),
    }
    _dump(report)

    failures = [name for name, item in probe.items() if not item["ok"]]
    for name, operation in (
        ("arrival", arrival),
        ("processed", processed),
        ("renumber", renumber),
        ("cleared", cleared),
        ("sequence", sequence),
        ("departure", departure),
    ):
        if not operation.get("ok"):
            failures.extend(f"{name}:{item}" for item in operation.get("violations", []))
    if failures:
        print(f"检查未通过: {failures}", file=sys.stderr)
        return 1
    return 0


def _mirror_mapping(platform: Platform, station_id: str) -> dict[str, str]:
    """给演示重排构造一份反向映射。"""

    groups = sorted(platform.station_view(station_id)["groups"])
    rotated = groups[1:] + groups[:1]
    return {key: value for key, value in zip(groups, rotated)}


def _first_gate(platform: Platform, station_id: str) -> str:
    """返回演示用的第一樘站台门。"""

    gates = platform.gates.by_station(station_id)
    return gates[0].id if gates else ""


def _next_station(platform: Platform, station_id: str) -> str:
    """返回线路上下一个站台，用于演示交路。"""

    stations = platform.namespace.station_ids()
    if len(stations) < 2:
        return station_id
    index = stations.index(station_id) if station_id in stations else 0
    return stations[(index + 1) % len(stations)]


def _cmd_status(args: argparse.Namespace) -> int:
    platform = _build(args)
    payload = platform.status()
    payload["groups"] = platform.snapshot()["groups"]
    _dump(payload)
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    _dump(config_to_mapping(config))
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    platform = _build(args)
    removed = platform.reset_state()
    _dump({"storage_root": platform.store.root, "platform_state_removed": removed})
    return 0


# ---- 对外投递子系统命令 ---------------------------------------------------


def _webhook_service(args: argparse.Namespace) -> tuple[Platform, WebhookService]:
    platform = _build(args)
    service = platform.enable_webhooks(autostart=False)
    return platform, service


def _admin(platform: Platform) -> Principal:
    """CLI 本地操作以 root 管理员身份执行（操作者即本机持库者）。"""

    return Principal(key_id=f"cli-{platform.unit}", scope=SCOPE_ADMIN, name="本地命令行")


def _split_topics(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "*").split(",") if item.strip()]


def _wh_bootstrap(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        result = service.create_credential(_admin(platform), args.name, SCOPE_ADMIN)
        _dump(result)
    finally:
        service.stop()
    return 0


def _wh_issue_key(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        result = service.create_credential(
            _admin(platform), args.name, args.scope,
            allowed_topics=_split_topics(args.topics), sub_id=args.sub_id or "",
        )
        _dump(result)
    finally:
        service.stop()
    return 0


def _wh_keys(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.list_credentials(_admin(platform)))
    finally:
        service.stop()
    return 0


def _wh_revoke_key(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.revoke_credential(_admin(platform), args.key_id))
    finally:
        service.stop()
    return 0


def _wh_add_sub(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        body = {
            "name": args.name,
            "target_url": args.url,
            "topics": _split_topics(args.topics),
            "max_rate": args.max_rate,
            "max_attempts": args.max_attempts,
        }
        _dump(service.create_subscription(_admin(platform), body))
    finally:
        service.stop()
    return 0


def _wh_subs(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.list_subscriptions(_admin(platform)))
    finally:
        service.stop()
    return 0


def _wh_sub_action(args: argparse.Namespace, attr: str) -> int:
    platform, service = _webhook_service(args)
    try:
        method = getattr(service, attr)
        _dump(method(_admin(platform), args.sub_id))
    finally:
        service.stop()
    return 0


def _wh_test(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.test_delivery(_admin(platform), args.sub_id))
    finally:
        service.stop()
    return 0


def _wh_emit(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        payload = json.loads(args.payload) if args.payload else {}
        if not isinstance(payload, dict):
            raise RailError("事件负载必须是 JSON 对象", component="webhook")
        _dump(service.ingest(
            args.topic, args.action, payload, event_id=args.event_id or "",
            source="cli", actor=_admin(platform).key_id,
        ))
    finally:
        service.stop()
    return 0


def _wh_events(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.list_events(_admin(platform), args.after_seq, args.limit))
    finally:
        service.stop()
    return 0


def _wh_deliveries(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.list_deliveries(_admin(platform), args.sub_id or None,
                                      args.status or None, args.limit,
                                      args.after_seq))
    finally:
        service.stop()
    return 0


def _wh_delivery(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.get_delivery(_admin(platform), args.delivery_id))
    finally:
        service.stop()
    return 0


def _wh_replay(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        if args.delivery_id:
            _dump(service.replay_delivery(_admin(platform), args.delivery_id))
        else:
            _dump(service.replay_dead(_admin(platform), args.sub_id or ""))
    finally:
        service.stop()
    return 0


def _wh_audit(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        _dump(service.list_audit(_admin(platform), args.after_id, args.limit))
    finally:
        service.stop()
    return 0


def _wh_verify(args: argparse.Namespace) -> int:
    platform, service = _webhook_service(args)
    try:
        result = service.verify_audit(_admin(platform))
        _dump(result)
        return 0 if result["ok"] else 1
    finally:
        service.stop()


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="JSON 配置文件路径", default=argparse.SUPPRESS)
    common.add_argument("--storage-root", help="覆盖状态存储目录", default=argparse.SUPPRESS)
    parser = argparse.ArgumentParser(
        prog="psdline", description="作业顺序与联锁控制服务", parents=[common]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="启动控制台服务", parents=[common])
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--duration", type=float, default=0.0, help="运行多少秒后退出，0 表示常驻")
    serve.add_argument("--probe", action="store_true", help="启动后探测接口")
    serve.add_argument("--webhook", action="store_true", help="同时启动对外事件投递服务")
    serve.add_argument("--webhook-host", default=None, help="投递服务监听地址")
    serve.add_argument("--webhook-port", type=int, default=None, help="投递服务监听端口")
    serve.set_defaults(func=_cmd_serve)

    demo = sub.add_parser("demo", help="跑一遍完整流程", parents=[common])
    demo.add_argument("--train", default="T01", help="演示用的列车标识")
    demo.add_argument("--station", default="ST1", help="演示用的站台标识")
    demo.add_argument("--cycles", type=int, default=120, help="演示控制周期数")
    demo.add_argument("--dt", type=float, default=1.0, help="控制周期步长（秒）")
    demo.add_argument("--fast", action="store_true", help="使用可推进时钟，跳过真实等待")
    demo.set_defaults(func=_cmd_demo)

    status = sub.add_parser("status", help="打印状态快照", parents=[common])
    status.set_defaults(func=_cmd_status)

    config = sub.add_parser("config", help="打印生效配置", parents=[common])
    config.set_defaults(func=_cmd_config)

    reset = sub.add_parser("reset", help="清掉落盘的平台计数", parents=[common])
    reset.set_defaults(func=_cmd_reset)

    _build_webhook_parsers(sub, common)
    return parser


def _build_webhook_parsers(sub, common) -> None:
    """注册对外投递子系统的管理命令。"""

    webhook = sub.add_parser("webhook", help="对外事件投递管理", parents=[common])
    wh = webhook.add_subparsers(dest="webhook_command", required=True)

    bootstrap = wh.add_parser("bootstrap", help="签发首个管理员凭据", parents=[common])
    bootstrap.add_argument("--name", default="root-admin")
    bootstrap.set_defaults(func=_wh_bootstrap)

    issue = wh.add_parser("issue-key", help="签发 ingest/subscriber/admin 凭据",
                          parents=[common])
    issue.add_argument("--name", required=True)
    issue.add_argument("--scope", choices=(SCOPE_ADMIN, SCOPE_INGEST, SCOPE_SUBSCRIBER),
                       required=True)
    issue.add_argument("--topics", default="*", help="允许的事件主题，逗号分隔")
    issue.add_argument("--sub-id", default="", help="subscriber 凭据绑定的订户")
    issue.set_defaults(func=_wh_issue_key)

    keys = wh.add_parser("keys", help="列出凭据", parents=[common])
    keys.set_defaults(func=_wh_keys)

    revoke = wh.add_parser("revoke-key", help="吊销凭据", parents=[common])
    revoke.add_argument("--key-id", required=True)
    revoke.set_defaults(func=_wh_revoke_key)

    add_sub = wh.add_parser("add-sub", help="登记订户", parents=[common])
    add_sub.add_argument("--name", required=True)
    add_sub.add_argument("--url", required=True, help="投递目标 URL")
    add_sub.add_argument("--topics", default="door", help="订阅主题，逗号分隔")
    add_sub.add_argument("--max-rate", type=float, default=0.0, help="每秒投递上限，0 不限")
    add_sub.add_argument("--max-attempts", type=int, default=8)
    add_sub.set_defaults(func=_wh_add_sub)

    subs = wh.add_parser("subs", help="列出订户", parents=[common])
    subs.set_defaults(func=_wh_subs)

    pause = wh.add_parser("pause-sub", help="暂停订户投递", parents=[common])
    pause.add_argument("--sub-id", required=True)
    pause.set_defaults(func=lambda a: _wh_sub_action(a, "pause_subscription"))

    resume = wh.add_parser("resume-sub", help="恢复订户投递", parents=[common])
    resume.add_argument("--sub-id", required=True)
    resume.set_defaults(func=lambda a: _wh_sub_action(a, "resume_subscription"))

    cancel = wh.add_parser("cancel-sub", help="注销订户", parents=[common])
    cancel.add_argument("--sub-id", required=True)
    cancel.set_defaults(func=lambda a: _wh_sub_action(a, "revoke_subscription"))

    test = wh.add_parser("test-sub", help="向订户地址发探测事件", parents=[common])
    test.add_argument("--sub-id", required=True)
    test.set_defaults(func=_wh_test)

    emit = wh.add_parser("emit", help="手工推一条事件进总账", parents=[common])
    emit.add_argument("--topic", default="door")
    emit.add_argument("--action", default="manual")
    emit.add_argument("--payload", default="{}", help="JSON 对象字符串")
    emit.add_argument("--event-id", default="")
    emit.set_defaults(func=_wh_emit)

    events = wh.add_parser("events", help="查事件总账", parents=[common])
    events.add_argument("--after-seq", type=int, default=0)
    events.add_argument("--limit", type=int, default=100)
    events.set_defaults(func=_wh_events)

    deliveries = wh.add_parser("deliveries", help="查投递记录", parents=[common])
    deliveries.add_argument("--sub-id", default="")
    deliveries.add_argument("--status", default="", choices=("", "pending", "leased",
                                                             "succeeded", "dead"))
    deliveries.add_argument("--after-seq", type=int, default=0)
    deliveries.add_argument("--limit", type=int, default=100)
    deliveries.set_defaults(func=_wh_deliveries)

    delivery = wh.add_parser("delivery", help="查单条投递（含每次尝试）", parents=[common])
    delivery.add_argument("--delivery-id", required=True)
    delivery.set_defaults(func=_wh_delivery)

    replay = wh.add_parser("replay", help="人工重投死信", parents=[common])
    replay.add_argument("--delivery-id", default="", help="指定单条；不给则批量")
    replay.add_argument("--sub-id", default="", help="批量重投时限定订户")
    replay.set_defaults(func=_wh_replay)

    audit = wh.add_parser("audit", help="查投递审计链", parents=[common])
    audit.add_argument("--after-id", type=int, default=0)
    audit.add_argument("--limit", type=int, default=100)
    audit.set_defaults(func=_wh_audit)

    verify = wh.add_parser("verify", help="校验审计哈希链", parents=[common])
    verify.set_defaults(func=_wh_verify)


def main(argv: list[str] | None = None) -> int:
    """命令行主入口。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RailError as error:
        print(json.dumps(error.as_record(), ensure_ascii=False), file=sys.stderr)
        return 2
