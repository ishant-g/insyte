"""grep.app code search (keyless).

grep.app's direct JSON API is intermittently WAF-blocked for datacenter
clients (HTTP 429), which the framework already translates into a
rate-limited provider status instead of a scan failure. When reachable it
returns public code-search hits naming the target, and it is wired into
the GitHub module as that module's keyless observation path.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from app.core.target import TargetType
from app.models.enums import AssetType, SourceKind
from app.providers.base import ObservationRecord, Provider, ProviderQuery, RateLimit


class GrepAppProvider(Provider):
    id = "grepapp"
    name = "grep.app"
    kind = SourceKind.PASSIVE
    homepage = "https://grep.app"
    description = (
        "Keyless public code search across indexed GitHub repositories. "
        "Reports repositories whose code mentions the target domain, which "
        "is how leaked credentials, internal hostnames and hardcoded API "
        "endpoints surface outside the target's own infrastructure."
    )
    reliability = 60
    requires_api_key = False
    intents = ("repositories",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 25.0

    def auth_headers(self) -> dict[str, str]:
        # The direct API endpoint fronts a WAF that rejects bare HTTP
        # clients; a browser-shaped request is what its own web UI sends.
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Referer": "https://grep.app/",
        }

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if query.target.target_type is not TargetType.DOMAIN:
            return []
        domain = query.target.registrable or query.target.value
        if not domain:
            return []

        payload = self._http_json(
            f"https://grep.app/api/search?q={quote_plus(domain)}"
        )
        if not isinstance(payload, dict):
            return []
        hits = payload.get("hits")
        if not isinstance(hits, dict):
            return []
        entries = hits.get("hits")
        if not isinstance(entries, list):
            return []

        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            repo = entry.get("repo") or {}
            repo_name = str(repo.get("raw") or "").strip()
            if not repo_name or repo_name in seen:
                continue
            seen.add(repo_name)
            path = entry.get("path") or {}
            branch = entry.get("branch") or {}
            content = entry.get("content") or {}
            snippet = str(content.get("snippet") or "").strip()
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.REPOSITORY,
                    value=repo_name,
                    source_type=SourceKind.PASSIVE,
                    confidence=70,
                    evidence={
                        "discovery": "public code mentions the target domain",
                        "query": domain,
                        "file_path": str(path.get("raw") or "").strip() or None,
                        "branch": str(branch.get("raw") or "").strip() or None,
                        "snippet": snippet[:600] or None,
                    },
                )
            )
            if len(out) >= (query.limit or 25):
                break
        return out
