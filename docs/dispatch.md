# 对外事件投递（Webhook 分发）

门控事件不再需要外部系统轮询：外部系统登记一次订阅，本服务把每条事件按发生
顺序、带签名地 POST 到订户回调；失败指数退避重试，超过上限进死信，由运维人工
重投。同一条事件无论投递多少次，对订户只产生一次效果。

## 1. 取舍（已选定）

| 决策点 | 选择 | 理由 |
| --- | --- | --- |
| 逐条还是按批 | **逐条、按发生顺序** | 门控事件量级不大，顺序语义清晰；单条失败只需重发一条，不存在“批里部分失败”的拆批/重投歧义。吞吐用订户间并发补 |
| 死信放哪 | **投递方保管** | 失败上下文、订户配置、审计都在本系统，运维在一处处置；订户也能通过只读 API 自取 |
| 消费保证 | **至少一次 + 订户幂等** | 崩溃恢复必然重发在途事件；靠恒定的 `Idempotency-Key` 保证订户侧去重 |
| 顺序 | **每订户一条有序链** | 当前序号未确认，后续事件不发；不同订户之间并发互不阻塞 |
| 历史 | **只追加 + 哈希链** | 事件、订阅、令牌、每次投递尝试全部进哈希链流水，任何改写/删除/插入在启动回放时报错 |

## 2. 投递协议（订户对接必读）

请求：

```
POST <登记的 callback>
Content-Type: application/json; charset=utf-8
Idempotency-Key: <sub_id>:<event_seq>     # 同事件的任何重发，此头完全相同
PSDLine-Event-ID: <event_id>
PSDLine-Event-Seq: <event_seq>
Signature: sha256=<HMAC-SHA256(secret, 原始请求体)>
# 登记时给了 token，会额外带：Authorization: Bearer <token>
# 登记时给了自定义头，会原样带上
```

请求体（信封）：

```json
{
  "id": "27ab9954…",
  "topic": "door",
  "component": "door",
  "action": "opened",
  "at": 1790989862.73,
  "payload": {"train_id": "T99", "station_id": "ST1", "group": "G01", "severity": "notice"}
}
```

订户必须做到：

1. **按 `Idempotency-Key` 去重**：先查 key 是否已处理，未处理才执行业务，
   然后再返回 2xx。返回 2xx 即确认，本服务不会再投。
2. **校验 `Signature`**：用登记时返回的一次性密钥（只显示一次，见下）对收到的
   原始字节做 HMAC-SHA256，签名不符直接拒绝。
3. **响应码约定**：2xx 确认；`5xx`、连接失败、超时按退避重试；
   `401/403/404/410` 视为永久拒绝，立即进死信；其余 4xx（如 429）按可重试处理。
4. 回调处理应当快速返回（配置超时默认 10 秒），重活异步做。

事件幂等键与序号的关系：`<sub_id>:<event_seq>`。不同订户前缀不同，所以同一条
事件给不同订户是不同的键；同一订户对同一序号永远是同一个键。

## 3. 订户过滤条件

登记时可指定：

* `topics`：主题数组，`"*"` 表示全量。门控主链路是 `"door"`；平台审计是 `"audit"`。
* `stations`：只收指定站台（匹配载荷 `station_id`）。
* `components`：只收指定组件（如 `door`、`sig`、`train`）。
* `rate_per_min`：该订户的每分钟投递上限（令牌桶），0 表示不限；另有全局桶。
* `start_seq`：从哪个出箱序号开始投。**默认是当前 head（只收新事件）**；
  填 0 表示从历史第一条开始补投。

不属于订户的事件会被记账式越过（写 `skipped` 记录），不会卡住后续事件。

## 4. 管理模型与凭据

三级权限令牌（Bearer Token，存的是 SHA-256 散列）：

* `admin`：登记/修改/吊销订户、轮换订户密钥、签发/吊销令牌、放弃死信；
* `ops`：暂停/恢复订户、触发死信重投、手动 pump；
* `auditor`：只读（状态、历史、死信、事件）。

订户回调密钥（HMAC secret）只在**登记和轮换那一刻**返回一次；落盘时用
AES-256-CTR + HMAC（encrypt-then-MAC）加密。主密钥：

* 生产环境通过环境变量 `PSDLINE_DISPATCH_KEY` 注入（base64 编码的 32 字节）；
* 未注入时在 `<storage>/dispatch/master.key` 生成 0600 权限的一次性主密钥文件。
  多实例/容器部署必须显式注入同一主密钥，否则旧密文无法解开。

第一个 admin 令牌在部署机上离线签发（不经网络）：

```bash
python -m psdline --config config/psdline.json dispatch issue-token --label root --scope admin
# 输出里的 token_once 只显示这一次，妥善保存
```

CLI 也支持离线登记与处置：

```bash
python -m psdline dispatch subscribe --name 外部A \
  --callback https://ext.example.com/hook --topics door --rate 300
python -m psdline dispatch list
python -m psdline dispatch pause   <sub_id>
python -m psdline dispatch resume  <sub_id>            # 可选 --start-seq N
python -m psdline dispatch revoke  <sub_id>
python -m psdline dispatch dead                 # 列死信
python -m psdline dispatch replay <sub_id>      # 人工重投
python -m psdline dispatch discard <sub_id>     # 放弃死信（admin）
python -m psdline dispatch status
```

## 5. 管理 HTTP 接口（均在 `/api/dispatch` 下，除 health 外都要令牌）

```
GET  /health                                   免鉴权健康探针
GET  /status                                   出箱 head、各订户游标、在途、死信
GET  /events?after_seq=&limit=                 读出箱事件（带序号）
GET  /history?sub_id=&limit=                   投递尝试流水（leased/acked/retry_scheduled/dead/skipped）
GET  /dead                                     列死信
POST /dead/{subID}/replay                      人工重投（ops/admin）
POST /dead/{subID}/discard                     放弃死信（admin）
GET  /subscribers
POST /subscribers                              登记（admin），返回 secret_once
GET  /subscribers/{subID}
POST /subscribers/{subID}                      修改（ops/admin）
POST /subscribers/{subID}/pause | /resume | /revoke
POST /subscribers/{subID}/rotate-secret        轮换回调密钥（admin）
GET  /tokens                                   （admin）
POST /tokens                                   签发（admin）
POST /tokens/{tokenID}/revoke                  （admin）
POST /pump                                     手动触发一轮投递（ops/admin）
```

调用示例：

```bash
curl -X POST http://psdline:8080/api/dispatch/subscribers \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"外部A","callback":"https://ext/hook","topics":["door"],
       "stations":["ST1"],"rate_per_min":300}'
```

## 6. 失败、重试、死信

* 退避：`base * 2^(attempt-1)`，封顶 `max_backoff_s`（默认 1s → 2 → 4 … → 300s），
  上限 `max_attempts`（默认 8 次）后进死信；
* 永久失败（401/403/404/410）不等退避，立即进死信；
* 死信记录保留订户、回调、事件内容副本、最后原因、尝试次数、是否永久失败；
* 死信会**阻塞该订户**（防止坏事件之后的事件越过它造成“跳过”），
  订户修复后 `replay` 从死信事件续上；确认无法处理时 `discard` 越过；
* 重发使用**同一个 `Idempotency-Key`**，订户去重后无第二份效果。

## 7. 崩溃安全与并发

* 事件先落哈希链出箱（fsync）再投递；进程任何时刻被杀，重启后从流水恢复，不漏；
* 每次“租约 / 确认 / 重试 / 死信 / 重投 / 越过”先写只追加尝试流水，
  游标快照只是加速重启的缓存（原子替换，每若干条刷一次），以流水回放为准；
* 快照对应的流水被截断或尾部被改写时，启动直接报错拒绝运行；
* 上次未确认的租约重启后一律重投（at-least-once），靠幂等键收敛；
* 订户间并发受有界信号量（`concurrency`，默认 8）与全局/订户令牌桶约束。

落盘布局（`<storage_root>/dispatch/`）：

```
events-00000.jsonl         # 出箱事件（哈希链）
subscriptions-00000.jsonl  # 订户登记/变更/吊销/轮换（哈希链，凭据加密）
tokens-00000.jsonl         # 令牌签发/吊销（哈希链，只存散列）
attempts-00000.jsonl       # 每次投递尝试（哈希链）
master.key                 # 0600 主密钥（或改用 PSDLINE_DISPATCH_KEY）
../dispatch/state.json     # 游标快照（可重建，原子写）
```

## 8. 配置（`config/psdline.json` 的 `dispatch` 节）

```json
"dispatch": {
  "enabled": true,
  "max_attempts": 8,
  "base_backoff_s": 1.0,
  "max_backoff_s": 300.0,
  "request_timeout_s": 10.0,
  "concurrency": 8,
  "global_rate_per_min": 0,
  "journal_segment": 1024,
  "ingest_topics": ["door", "audit"]
}
```

管理动作（登记、吊销、重投等）同时写入平台既有审计流水（`dispatch_*` 动作
类型），与投递尝试流水一起构成“订阅 → 打包 → 投递 → 审计”的完整链路。
