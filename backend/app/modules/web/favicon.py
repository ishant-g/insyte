"""Favicon Fingerprinting (Shodan-style).

Fetches the target's favicon (one GET, the same resource Web Surface
Collection already retrieves) and computes its MurmurHash3 the way Shodan
does - over the base64 encoding of the icon bytes - so the hash can be
pivoted directly in Shodan's `http.favicon.hash` search to find other
hosts using the same icon.

The hash is implemented inline (no new dependency). It covers the icon
bytes only, and the observation says exactly that: a matching hash means
"same icon", not "same owner".
"""

from __future__ import annotations

import base64

from app.core.contracts import ModuleOutput, ObservationRecord
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ModuleCategory,
    ObservationStatus,
    ScanMode,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext

_FAVICON_PATHS = ("/favicon.ico", "/apple-touch-icon.png")

_MAX_FAVICON_BYTES = 1024 * 1024


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 (x86, 32-bit). Returns the unsigned digest.

    Reference implementation of the public-domain algorithm by Austin
    Appleby; matches the well-known test vectors (b"" -> 0,
    b"hello" -> 613153351 with seed 0).
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    mask = 0xFFFFFFFF
    length = len(data)
    h = seed & mask

    for i in range(length // 4):
        k = int.from_bytes(data[i * 4 : (i + 1) * 4], "little")
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask

    tail = data[(length // 4) * 4 :]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k

    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h


def shodan_favicon_hash(icon_bytes: bytes) -> int:
    """Shodan-compatible favicon hash: MurmurHash3 over the base64-encoded
    icon (76-char lines, as Shodan computes it), returned as signed int32."""
    encoded = base64.encodebytes(icon_bytes)
    unsigned = murmur3_x86_32(encoded)
    return unsigned - 0x100000000 if unsigned >= 0x80000000 else unsigned


class FaviconModule(IntelligenceModule):
    id = "favicon_intelligence"
    name = "Favicon Fingerprinting"
    description = (
        "Fetches the site favicon and computes its Shodan-compatible "
        "MurmurHash3, enabling pivots to other hosts using the same icon."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface",)
    timeout = 30.0
    order = 61

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        origin = ctx.target.http_origin.rstrip("/")

        fetched = None
        for path in _FAVICON_PATHS:
            ctx.check_cancelled()
            response = ctx.http.try_get(
                origin + path, max_bytes=_MAX_FAVICON_BYTES, accept="image/*"
            )
            if response is not None and response.ok and response.size > 0:
                fetched = (origin + path, response)
                break

        if fetched is None:
            output.data["note"] = "no favicon found at common paths"
            return output

        url, response = fetched
        icon_hash = shodan_favicon_hash(response.content)
        output.observations.append(
            ObservationRecord(
                source=self.id,
                asset_type=AssetType.URL,
                value=url,
                source_type=SourceKind.WEB_SURFACE,
                confidence=95,
                status=ObservationStatus.OBSERVED,
                evidence={
                    "discovery": "favicon fetched and hashed",
                    "mmh3_hash": icon_hash,
                    "sha256": response.sha256,
                    "bytes": response.size,
                    "content_type": response.content_type,
                    "shodan_query": f"http.favicon.hash:{icon_hash}",
                },
            )
        )
        output.data["favicon_url"] = url
        output.data["favicon_mmh3"] = icon_hash
        output.data["favicon_sha256"] = response.sha256
        output.metrics["favicons_hashed"] = 1
        return output
