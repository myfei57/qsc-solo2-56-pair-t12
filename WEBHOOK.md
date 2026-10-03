# 门控事件对外投递（webhook）

外部系统不再轮询。门控事件进入系统后，按订户登记的主题打包、签名后 HTTP POST
过去；失败指数退避重试，超过上限进死信、可人工重投。投递语义为**逐条、至少
一次**，配合稳定的 `Event-ID` 幂等键，订户去重即可做到**效果恰好一次**。

## 设计取舍

| 选项 | 选择 | 理由 |
| --- | --- | --- |
| 逐条投 vs 攒批投 | **逐条**，按聚合键分区有序、跨键并发 | 门控事件量不大，实时性优先；批量投递的部分失败会退化为整批重试，幂等面更大、缺口更难定位 |
| 死信谁保管 | **投递方保管 + push 重投** | 外部订户无需回头拉取；死信与全部尝试、审计在同一处，重投仍走同一条审计链 |
| 顺序粒度 | 同一聚合键（默认站台，其次列车）严格有序，不同键并发 | 既保每站事件不错乱，又不让一个慢站堵死全线 |
| 订户能否自助 | 管理员登记订户并签发**绑定凭据**；订户凭据只能查/改自己名下的投递地址与死信 | 主题授权、限流、暂停/注销集中管控，外部系统只管接收与查询自己 |

## 一条链

```
门控组件 ──EventBus("door")──┐
                            ├─► ingest（event_id 幂等）
外部/上游 POST /v1/events ───┘            │
                                         ▼
                         events 只追加总账（seq 全局有序，触发器禁改禁删）
                                         │ 入队循环：游标 + 主题过滤
                                         ▼
                         deliveries（每订户每事件一行，唯一约束）
            pending ──租约认领(lease+fencing token)──► leased
               ▲                                        │ HTTP POST + HMAC 签名
               │                                  2xx ──┴─► succeeded
               │                            410/超限 ─────► dead（人工重投）
               └─ 退避(not_before) ◄── 其它失败
```

订阅、凭据、暂停、重投、投递结果全部落**哈希链审计**，只追加、可校验；事件
总账与每次投递尝试在 SQLite 层用触发器禁止 UPDATE/DELETE。

## 关键机制如何满足要求

- **不漏**：事件先落总账再投递；每个订户有游标，入队在一个 `BEGIN IMMEDIATE`
  事务里「读游标→建待投→推进游标」，崩溃只整批重做，`(sub_id,event_id)` 唯一
  约束保证不重复建行。
- **不重（第二份效果）**：投递行有 `pending/leased/succeeded/dead` 状态机；
  认领时尝试号即 fencing token，worker 崩溃后租约超时回收，旧 worker 的迟到
  结果因 token 不符被丢弃。重试、租约交接、人工重投**都不换 `Event-ID`**，
  订户按 `Event-ID` 去重 → 同一事件至多产生一次效果。
- **部分失败恢复**：一个订户失败不影响其它订户；单订户内一个聚合键阻塞不影响
  其它键（跨键并发）；死信可单条或按订户批量重投。
- **并发**：投递 worker 池 + 每订户并发上限；调度每拍跳过「该订户已有在途同键」
  的候选。
- **限流**：每订户令牌桶（`max_rate` 条/秒，0 不限），到期未取到令牌的候选下
  一拍再投。
- **崩溃安全**：SQLite WAL；投递前已落库，进程崩溃后重启靠租约回收继续，无
  内存态；事件/审计只追加不可变。
- **凭据与权限**：token 只存 SHA-256；三档作用域 `admin / ingest / subscriber`，
  subscriber 凭据绑定单个 `sub_id`；投递请求带 HMAC-SHA256 签名与时间戳，
  可选 `Authorization: Bearer`。

## 投递请求

```
POST <target_url>
Content-Type: application/json; charset=utf-8
Event-ID: evt-...                 # 幂等键，重试/重投恒定
Event-Topic: door
Event-Action: opened
Event-Seq: 42
Delivery-ID: <uuid>
Delivery-Attempt: 1
X-Signature-Timestamp: 1759...
X-Signature: sha256=<hex>
Authorization: Bearer <auth_token>   # 可选

{"id":"evt-...","unit":"line1","topic":"door","action":"opened","seq":42,
 "aggregate_key":"station_id:ST1","occurred_at":...,"delivered_at":...,
 "delivery_id":"...","attempt":1,"data":{ ...门控事件原文... }}
```

- 成功：HTTP `2xx`。
- `410 Gone`：永久弃收，直接进死信。
- 其它非 2xx / 连接失败 / 超时：退避重试。
- 签名：`HMAC_SHA256(secret, f"{timestamp}.{raw_body}")`，订户应校验并限制
  时间戳新鲜度。`secret` 只在登记订户时返回一次。
- **订户必须按 `Event-ID` 去重**，这是「重试不产生第二份效果」的另一半。

## 启用与使用

配置见 `config/psdline.json` 的 `webhook` 段（默认 `enabled: false`）。随主服务
一起启动：

```bash
python -m psdline --config config/psdline.json serve \
    --webhook --webhook-host 0.0.0.0 --webhook-port 8090
```

或把配置里 `webhook.enabled` 置 true，普通 `serve` 即同时起投递服务。
首次使用用 CLI 引导管理员（操作的是本机状态库，不需要已存在凭据）：

```bash
# 1. 引导管理员凭据（明文 token 只显示这一次）
python -m psdline webhook bootstrap --name root

# 2. 登记外部订户，返回 secret（校验签名）与 auth_token
python -m psdline webhook add-sub --name 外部系统A \
    --url https://a.example.com/hook --topics door,door.opened \
    --max-rate 10 --max-attempts 8

# 3.（可选）给该外部系统签发只能管理自己的凭据
python -m psdline webhook issue-key --name a-team \
    --scope subscriber --sub-id sub-xxxx

# 运行/排障
python -m psdline webhook subs
python -m psdline webhook deliveries --status dead
python -m psdline webhook delivery --delivery-id <id>
python -m psdline webhook replay --delivery-id <id>   # 或 --sub-id 批量
python -m psdline webhook pause-sub   --sub-id <id>
python -m psdline webhook resume-sub  --sub-id <id>
python -m psdline webhook test-sub    --sub-id <id>   # 同步发探测事件
python -m psdline webhook emit --topic door --action opened \
    --payload '{"station_id":"ST1"}' [--event-id ...]
python -m psdline webhook audit
python -m psdline webhook verify                          # 校验审计哈希链
```

主题过滤支持 `*`（全部）、精确主题（`door`）或 `主题.动作`（`door.opened`）。
新建订户只收**登记之后**的事件（不追历史）；暂停期间事件跳过，恢复后只收新事件。

## HTTP API（投递服务端口）

除 `GET /healthz` 外都需要 `Authorization: Bearer <token>`。

| 方法 & 路径 | 作用域 | 说明 |
| --- | --- | --- |
| `POST /v1/events` | admin/ingest | 推事件（可 `{"events":[...]}` 批量），同 `event_id` 幂等 |
| `POST /v1/subs` | admin | 登记订户，返回 `secret`/`auth_token` |
| `GET  /v1/subs` | admin/订户 | 列出（订户只看到自己） |
| `GET  /v1/subs/{id}` | admin/订户本人 | 订户详情与投递计数 |
| `POST /v1/subs/{id}` | admin/订户本人 | 更新（订户只能改 name/target_url） |
| `POST /v1/subs/{id}/test` | admin/订户本人 | 同步探测，不进总账、不重试 |
| `POST /v1/subs/{id}/pause` `/resume` | admin | 暂停/恢复 |
| `DELETE /v1/subs/{id}` | admin | 注销（保留历史） |
| `GET  /v1/subs/{id}/deliveries` | admin/订户本人 | 投递记录（可按 status/after_seq 翻页） |
| `POST /v1/subs/{id}/replay-dead` | admin/订户本人 | 批量重投死信 |
| `GET  /v1/deliveries/{id}` | admin/订户本人 | 单条投递含每次尝试 |
| `POST /v1/deliveries/{id}/replay` | admin/订户本人 | 人工重投单条死信 |
| `POST /v1/credentials` | admin | 签发凭据（明文只回一次） |
| `GET  /v1/credentials` · `POST /v1/credentials/{id}/revoke` | admin | 凭据管理 |
| `GET  /v1/events` | admin | 事件总账（不可变） |
| `GET  /v1/audit` · `POST /v1/audit/verify` | admin | 审计链与校验 |
| `GET  /v1/stats` | admin/订户 | 投递计数、在途数、哈希链状态 |

## 存储

`var/state/webhook/deliveries.db`（SQLite + WAL）。`events`、`delivery_attempts`、
`audit_records` 由数据库触发器禁止 UPDATE/DELETE，历史不可变不靠约定。备份直接
复制该文件即可；多进程可共享同一库（租约认领是条件 UPDATE，天然互斥）。

## 运维注意

- `secret`/`token` 明文只在创建响应里出现一次，丢失需吊销重发。
- 状态机字段 `leased` 长期堆积说明有 worker 崩溃且租约过长，关注 `lease_s`。
- 退避为指数退避 + 全抖动：`random(0, min(backoff_max, base * factor^(n-1)))`。
