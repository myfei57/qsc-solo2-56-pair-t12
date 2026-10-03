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
    payload: dict = {"listening": base_url, "routes": server.api.routes(), "dispatch_routes": server.dispatch_routes()}
    if args.probe:
        payload["probe"] = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    _dump(payload)
    if args.duration > 0:
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:  # pragma: no cover - 交互路径
            pass
        server.stop()
        return 0
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover - 交互路径
        server.stop()
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


def _cmd_dispatch(args: argparse.Namespace) -> int:
    """对外投递的离线管理：引导令牌、登记订户、查看死信、人工重投。"""

    platform = _build(args)
    service = platform.dispatch
    if service is None:
        _dump({"error": "对外投递未启用（配置 dispatch.enabled=false）"})
        return 2
    action = args.dispatch_action

    if action == "issue-token":
        _dump(service.issue_token(args.label, args.scope, by="cli"))
        return 0
    if action == "revoke-token":
        _dump(service.revoke_token(args.token_id, by="cli"))
        return 0
    if action == "list-tokens":
        _dump({"tokens": [token.public_view() for token in service.tokens.list()]})
        return 0
    if action == "subscribe":
        start_seq = service.outbox.head_seq if args.start_seq < 0 else args.start_seq
        _dump(
            service.register_subscriber(
                by="cli",
                name=args.name,
                callback=args.callback,
                topics=tuple(args.topics.split(",")) if args.topics else ("door",),
                stations=tuple(args.stations.split(",")) if args.stations else (),
                rate_per_min=args.rate,
                start_seq=start_seq,
            )
        )
        return 0
    if action == "list":
        _dump({"subscribers": [sub.public_view() for sub in service.subscriptions.list()]})
        return 0
    if action == "pause":
        _dump(service.pause_subscriber(args.sub_id, by="cli"))
        return 0
    if action == "resume":
        _dump(service.resume_subscriber(args.sub_id, by="cli", from_seq=args.start_seq))
        return 0
    if action == "revoke":
        _dump(service.revoke_subscriber(args.sub_id, by="cli"))
        return 0
    if action == "dead":
        _dump(service.list_dead(args.sub_id or ""))
        return 0
    if action == "replay":
        _dump(service.replay_dead(args.sub_id, by="cli"))
        return 0
    if action == "discard":
        _dump(service.discard_dead(args.sub_id, by="cli"))
        return 0
    if action == "status":
        _dump(service.status())
        return 0
    print(f"未知投递子命令: {action}", file=sys.stderr)
    return 2


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

    dispatch = sub.add_parser("dispatch", help="对外事件投递管理", parents=[common])
    dispatch_sub = dispatch.add_subparsers(dest="dispatch_action", required=True)

    issue = dispatch_sub.add_parser("issue-token", help="签发管理令牌（明文只显示一次）", parents=[common])
    issue.add_argument("--label", required=True)
    issue.add_argument("--scope", choices=("admin", "ops", "auditor"), default="ops")

    revoke_tok = dispatch_sub.add_parser("revoke-token", help="吊销管理令牌", parents=[common])
    revoke_tok.add_argument("token_id")
    dispatch_sub.add_parser("list-tokens", help="列出管理令牌", parents=[common])

    subscribe = dispatch_sub.add_parser("subscribe", help="登记订户", parents=[common])
    subscribe.add_argument("--name", required=True)
    subscribe.add_argument("--callback", required=True)
    subscribe.add_argument("--topics", default="door", help="逗号分隔，* 表示全量")
    subscribe.add_argument("--stations", default="", help="逗号分隔的站台过滤")
    subscribe.add_argument("--rate", type=float, default=0.0, help="每分钟投递上限，0 不限")
    subscribe.add_argument("--start-seq", type=int, default=-1, help="从哪个序号开始，-1 表示只收新事件")
    dispatch_sub.add_parser("list", help="列出订户", parents=[common])

    pause = dispatch_sub.add_parser("pause", help="暂停订户", parents=[common])
    pause.add_argument("sub_id")
    resume = dispatch_sub.add_parser("resume", help="恢复订户", parents=[common])
    resume.add_argument("sub_id")
    resume.add_argument("--start-seq", type=int, default=None)
    revoke_sub = dispatch_sub.add_parser("revoke", help="吊销订户", parents=[common])
    revoke_sub.add_argument("sub_id")

    dead = dispatch_sub.add_parser("dead", help="查看死信", parents=[common])
    dead.add_argument("sub_id", nargs="?", default="")
    replay = dispatch_sub.add_parser("replay", help="人工重投死信", parents=[common])
    replay.add_argument("sub_id")
    discard = dispatch_sub.add_parser("discard", help="放弃死信（admin）", parents=[common])
    discard.add_argument("sub_id")
    dispatch_sub.add_parser("status", help="投递链路状态", parents=[common])
    dispatch.set_defaults(func=_cmd_dispatch)
    return parser


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
