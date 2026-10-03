"""对外投递子系统。

一条链上的五件事：

* :mod:`psdline.webhook.security` 凭据、签名与规范化编码；
* :mod:`psdline.webhook.store` SQLite 持久化（事件与审计只追加、不可变）；
* :mod:`psdline.webhook.ratelimit` 订户令牌桶限流；
* :mod:`psdline.webhook.dispatcher` 打包、租约认领、投递、退避、死信；
* :mod:`psdline.webhook.service` / :mod:`psdline.webhook.server` 门面与 HTTP 边界。

语义是「逐条、至少一次」投递：同一订户同一聚合键严格按发生顺序投递，不同键
并发；每条投递携带稳定的 ``Event-ID`` 幂等键，重试、租约交接与人工重投都不
换号，订户据此去重即可做到效果恰好一次。
"""

from .dispatcher import topic_matches, aggregate_key
from .security import canonical_json, new_token, sha256_hex, sign_body
from .service import WebhookService

__all__ = [
    "WebhookService",
    "aggregate_key",
    "canonical_json",
    "new_token",
    "sha256_hex",
    "sign_body",
    "topic_matches",
]
