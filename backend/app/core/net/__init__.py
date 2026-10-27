"""Network egress layer.

Nothing in Insyte performs an outbound HTTP request except through
`SafeHttpClient`. That is the single choke point where the SSRF policy,
byte caps, timeouts, redirect validation and concurrency limits are
enforced, so there is exactly one place to audit.
"""

from app.core.net.client import (
    HttpError,
    SafeHttpClient,
    SafeResponse,
    get_client,
)
from app.core.net.ssrf import (
    SSRFBlocked,
    describe_policy,
    ip_block_reason,
    resolve_and_validate,
    validate_url,
)

__all__ = [
    "HttpError",
    "SSRFBlocked",
    "SafeHttpClient",
    "SafeResponse",
    "describe_policy",
    "get_client",
    "ip_block_reason",
    "resolve_and_validate",
    "validate_url",
]
