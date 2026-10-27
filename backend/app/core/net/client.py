"""The one HTTP client Insyte is allowed to use.

Design constraints, all of them product requirements rather than taste:

* **Read-only.** Only GET and HEAD exist on the public surface. There is no
  code path that can POST, PUT, PATCH or DELETE against a target, so the
  "Web Surface Collection is low-impact" claim is enforced by the type
  system rather than by convention.
* **Every destination is validated by `core.net.ssrf`,** including each
  redirect hop. Redirects are followed manually for exactly this reason:
  httpx's own `follow_redirects` would resolve and connect to the new
  location without consulting the policy.
* **Connections are pinned to a pre-validated address.** The URL handed to
  httpx carries the literal IP; the real hostname travels in the `Host`
  header and as the TLS SNI value so virtual hosting and certificate
  verification both still work.
* **Keep-alive is disabled.** httpcore keys its connection pool on the
  origin, which after pinning is the *IP* - so a pooled connection could be
  reused for a request whose SNI differs from the one it was established
  with, quietly skipping the certificate check for that hostname. Paying for
  a fresh handshake per request removes the whole class of bug.
* **Responses are streamed with a hard byte ceiling** so a hostile target
  cannot exhaust the worker by returning an endless body, whether or not it
  sends an honest Content-Length.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urljoin

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.net.ssrf import (
    PinnedDestination,
    SSRFBlocked,
    resolve_and_validate,
    validate_url,
)

logger = get_logger(__name__)

Method = Literal["GET", "HEAD"]

#: Content types Insyte will read a body for. Anything else is fetched for
#: its headers and status only - there is no reason to pull a 400 MB video
#: into a passive-intelligence pipeline.
TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/ld+json",
    "application/manifest+json",
    "application/rss+xml",
    "application/atom+xml",
    "application/yaml",
    "application/x-yaml",
    "application/graphql",
    "application/octet-stream",
)


class HttpError(Exception):
    """A collection attempt failed for a non-policy reason.

    Kept distinct from `SSRFBlocked` so callers can report "refused by
    policy" differently from "the target did not answer".
    """

    def __init__(self, message: str, *, url: str = "", kind: str = "error") -> None:
        self.kind = kind
        self.url = url
        super().__init__(message)


@dataclass(slots=True)
class SafeResponse:
    """The result of one validated GET."""

    url: str
    #: URL actually fetched after redirects (== url when there were none).
    final_url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    elapsed: float
    #: Address the socket connected to, for provenance.
    remote_address: str
    #: Redirect chain, each entry already policy-validated.
    redirect_chain: list[str] = field(default_factory=list)
    #: True when the body hit the byte ceiling and was cut short.
    truncated: bool = False
    fetched_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";", 1)[0].strip().lower()

    @property
    def charset(self) -> str:
        raw = self.headers.get("content-type") or ""
        if "charset=" in raw:
            return raw.split("charset=", 1)[1].split(";", 1)[0].strip().strip('"').lower()
        return "utf-8"

    @property
    def text(self) -> str:
        """Decoded body. Never raises - a hostile encoding is not an error."""
        for encoding in (self.charset, "utf-8", "latin-1"):
            try:
                return self.content.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                continue
        return self.content.decode("utf-8", errors="replace")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def _byte_cap_for(content_type: str) -> int:
    """Per-type body ceiling."""
    ct = content_type.lower()
    if "javascript" in ct or "ecmascript" in ct:
        return settings.HTTP_MAX_JS_BYTES
    if ct.startswith("text/css"):
        return settings.HTTP_MAX_CSS_BYTES
    if ct.startswith("text/html") or "xhtml" in ct:
        return settings.HTTP_MAX_HTML_BYTES
    return settings.HTTP_MAX_RESPONSE_BYTES


class SafeHttpClient:
    """SSRF-guarded, byte-capped, GET-only HTTP client.

    Thread-safe and intended to be shared: the concurrency semaphore is what
    keeps a fan-out of JavaScript fetches from opening sixty sockets at once.
    """

    def __init__(
        self,
        *,
        connect_timeout: float | None = None,
        read_timeout: float | None = None,
        total_timeout: float | None = None,
        max_redirects: int | None = None,
        max_concurrency: int | None = None,
        user_agent: str | None = None,
        verify: bool = True,
    ) -> None:
        self._timeout = httpx.Timeout(
            timeout=total_timeout or settings.HTTP_TOTAL_TIMEOUT,
            connect=connect_timeout or settings.HTTP_CONNECT_TIMEOUT,
            read=read_timeout or settings.HTTP_READ_TIMEOUT,
        )
        self._max_redirects = (
            settings.HTTP_MAX_REDIRECTS if max_redirects is None else max_redirects
        )
        self._user_agent = user_agent or settings.HTTP_USER_AGENT
        self._semaphore = threading.BoundedSemaphore(
            max_concurrency or settings.HTTP_MAX_CONCURRENCY
        )
        self._client = httpx.Client(
            timeout=self._timeout,
            # Manual redirect handling - see the module docstring.
            follow_redirects=False,
            verify=verify,
            # No connection reuse: see the module docstring.
            limits=httpx.Limits(
                max_keepalive_connections=0,
                max_connections=(max_concurrency or settings.HTTP_MAX_CONCURRENCY) * 2,
            ),
            headers={
                "User-Agent": self._user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                # Insyte never authenticates and never wants a session.
                "Cache-Control": "no-cache",
            },
            trust_env=False,  # ignore ambient proxy env vars
        )

    # -- lifecycle -------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeHttpClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- public API ------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        accept: str | None = None,
    ) -> SafeResponse:
        """Fetch a URL. Raises SSRFBlocked or HttpError; never returns None."""
        return self._request("GET", url, headers=headers, max_bytes=max_bytes, accept=accept)

    def head(self, url: str, *, headers: dict[str, str] | None = None) -> SafeResponse:
        return self._request("HEAD", url, headers=headers, max_bytes=0)

    def provider_get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        accept: str | None = None,
    ) -> SafeResponse:
        """Fetch a *third-party intelligence API*, with credentials allowed.

        Deliberately a separate entry point from `get`. `get` strips
        `Authorization`, `Cookie` and any other credential header, because
        the URL it is given may have come from the scan target and sending
        an API key to a target would be a credential leak. Provider URLs
        are constructed by Insyte from a fixed template, so authenticating
        to them is safe - and keeping the two paths distinct means no
        future edit to a collection module can accidentally acquire the
        ability to send secrets outward.

        The SSRF policy still applies in full.
        """
        return self._request(
            "GET",
            url,
            headers=headers,
            max_bytes=max_bytes,
            accept=accept,
            allow_credentials=True,
        )

    def try_get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        accept: str | None = None,
    ) -> SafeResponse | None:
        """`get` that returns None instead of raising.

        Collection modules fetch dozens of speculative URLs where a 404 or a
        policy refusal is a normal outcome, not an error worth unwinding a
        call stack for.
        """
        try:
            return self.get(url, headers=headers, max_bytes=max_bytes, accept=accept)
        except SSRFBlocked as exc:
            logger.info(
                "collection_blocked",
                extra={"url": url[:200], "reason": exc.reason},
            )
            return None
        except HttpError as exc:
            logger.info(
                "collection_failed",
                extra={"url": url[:200], "kind": exc.kind, "detail": str(exc)[:200]},
            )
            return None

    # -- internals -------------------------------------------------------

    def _request(
        self,
        method: Method,
        url: str,
        *,
        headers: dict[str, str] | None,
        max_bytes: int | None,
        accept: str | None = None,
        allow_credentials: bool = False,
    ) -> SafeResponse:
        if method not in ("GET", "HEAD"):  # pragma: no cover - typed away
            raise HttpError(f"method {method} is not permitted", kind="policy")

        current = url
        chain: list[str] = []

        for hop in range(self._max_redirects + 1):
            destination = resolve_and_validate(validate_url(current))
            response = self._fetch_once(
                method,
                destination,
                extra_headers=headers,
                accept=accept,
                max_bytes=max_bytes,
                original_url=current,
                allow_credentials=allow_credentials,
            )

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.header("location")
                if not location:
                    # A redirect with no Location is a dead end, not an error.
                    response.redirect_chain = chain
                    return response
                if hop >= self._max_redirects:
                    raise HttpError(
                        f"exceeded the redirect limit of {self._max_redirects}",
                        url=url,
                        kind="too_many_redirects",
                    )
                # Resolve relative Locations against the *hostname* URL, not
                # the pinned-IP URL, so the next hop is validated by name.
                next_url = urljoin(current, location.strip())
                if next_url == current:
                    raise HttpError("redirect loop", url=url, kind="redirect_loop")
                chain.append(current)
                logger.debug(
                    "redirect_followed",
                    extra={"from_url": current[:200], "to_url": next_url[:200]},
                )
                current = next_url
                continue

            response.redirect_chain = chain
            return response

        raise HttpError("redirect handling exhausted", url=url, kind="too_many_redirects")

    def _fetch_once(
        self,
        method: Method,
        destination: PinnedDestination,
        *,
        extra_headers: dict[str, str] | None,
        accept: str | None,
        max_bytes: int | None,
        original_url: str,
        allow_credentials: bool = False,
    ) -> SafeResponse:
        request_headers: dict[str, str] = {"Host": destination.host_header}
        if accept:
            request_headers["Accept"] = accept
        if extra_headers:
            for key, value in extra_headers.items():
                # Header injection guard: a value harvested from a target
                # must not be able to terminate the header block.
                if any(ch in str(value) for ch in ("\r", "\n", "\x00")):
                    continue
                lowered = key.lower()
                if lowered == "host":
                    continue
                if not allow_credentials and lowered in (
                    "authorization",
                    "cookie",
                    "x-api-key",
                    "x-apikey",
                    "api-key",
                    "apikey",
                    "x-auth-token",
                    "private-token",
                ):
                    # Target collection never sends credentials outward.
                    continue
                request_headers[key] = str(value)

        connect_url = destination.connect_url
        hostname = destination.safe_url.hostname

        acquired = self._semaphore.acquire(timeout=settings.HTTP_TOTAL_TIMEOUT * 2)
        if not acquired:
            raise HttpError(
                "collection concurrency limit reached", url=original_url, kind="throttled"
            )
        try:
            started = datetime.now(UTC)
            try:
                with self._client.stream(
                    method,
                    connect_url,
                    headers=request_headers,
                    # Present the real hostname for SNI and certificate
                    # verification even though we dialled a literal IP.
                    extensions={"sni_hostname": hostname},
                ) as stream:
                    content, truncated = self._read_capped(stream, method, max_bytes)
                    elapsed = (datetime.now(UTC) - started).total_seconds()
                    return SafeResponse(
                        url=original_url,
                        final_url=original_url,
                        status_code=stream.status_code,
                        headers={k.lower(): v for k, v in stream.headers.items()},
                        content=content,
                        elapsed=elapsed,
                        remote_address=destination.address,
                        truncated=truncated,
                    )
            except httpx.TooManyRedirects as exc:  # pragma: no cover
                raise HttpError(str(exc), url=original_url, kind="too_many_redirects") from exc
            except httpx.ConnectTimeout as exc:
                raise HttpError("connection timed out", url=original_url, kind="timeout") from exc
            except httpx.ReadTimeout as exc:
                raise HttpError("read timed out", url=original_url, kind="timeout") from exc
            except httpx.TimeoutException as exc:
                raise HttpError("request timed out", url=original_url, kind="timeout") from exc
            except httpx.ConnectError as exc:
                raise HttpError(
                    f"could not connect: {_short(exc)}", url=original_url, kind="connect_error"
                ) from exc
            except httpx.HTTPError as exc:
                raise HttpError(
                    f"transport error: {_short(exc)}", url=original_url, kind="transport_error"
                ) from exc
            except (OSError, ValueError) as exc:
                raise HttpError(
                    f"request failed: {_short(exc)}", url=original_url, kind="error"
                ) from exc
        finally:
            self._semaphore.release()

    @staticmethod
    def _read_capped(
        stream: httpx.Response, method: Method, max_bytes: int | None
    ) -> tuple[bytes, bool]:
        """Read a body up to a hard ceiling, honestly reporting truncation.

        The declared Content-Length is used only as an early-exit hint; the
        real enforcement is counting bytes as they arrive, because a hostile
        server's Content-Length is not evidence of anything.
        """
        if method == "HEAD" or max_bytes == 0:
            return b"", False

        content_type = (stream.headers.get("content-type") or "").split(";")[0].strip()
        cap = max_bytes if max_bytes is not None else _byte_cap_for(content_type)

        # Skip bodies we would never parse, but still return the headers.
        if content_type and not any(
            content_type.lower().startswith(prefix) for prefix in TEXTUAL_CONTENT_TYPES
        ):
            declared = stream.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > cap:
                return b"", True

        chunks: list[bytes] = []
        total = 0
        truncated = False
        for chunk in stream.iter_bytes(chunk_size=64 * 1024):
            remaining = cap - total
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), truncated


def _short(exc: BaseException) -> str:
    """Compact, non-leaky rendering of a transport exception."""
    text = str(exc) or exc.__class__.__name__
    return text.splitlines()[0][:160]


# ---- Shared instance --------------------------------------------------------
# One client per process. Modules take it from `get_client()` so limits and
# the SSRF policy apply uniformly and a scan cannot accidentally construct an
# unguarded httpx.Client of its own.

_client_lock = threading.Lock()
_shared_client: SafeHttpClient | None = None


def get_client() -> SafeHttpClient:
    global _shared_client
    if _shared_client is None:
        with _client_lock:
            if _shared_client is None:
                _shared_client = SafeHttpClient()
    return _shared_client


def reset_client() -> None:
    """Dispose of the shared client. Used by tests and worker shutdown."""
    global _shared_client
    with _client_lock:
        if _shared_client is not None:
            _shared_client.close()
            _shared_client = None
