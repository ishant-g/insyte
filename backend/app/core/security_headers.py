"""Security headers for Insyte's own HTTP responses.

Distinct from `modules/web/headers.py`, which grades a *scan target's*
headers - this is what protects Insyte's own frontend and API. HSTS is
opt-in (`settings.ENABLE_HSTS`) because emitting it over plain HTTP in
local development would pin the developer's browser to HTTPS for
localhost, which is exactly the kind of self-inflicted footgun this file
exists to avoid causing.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # The API returns only JSON/PDF/binary - a strict CSP with no
        # script/style sources served is appropriate and cannot break
        # anything, because this app has no HTML views to protect *or*
        # break.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        if settings.ENABLE_HSTS:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response
