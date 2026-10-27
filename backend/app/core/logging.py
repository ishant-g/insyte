"""Structured logging for Insyte.

Every log line is JSON in production so scan telemetry is queryable.
A redacting filter runs on every record: provider keys, tokens, connection
strings and anything that looks like a secret never reach the log stream,
including when they arrive inside a scan result.
"""

from __future__ import annotations

import logging
import logging.config
import re
import sys
from typing import Any

from app.core.config import settings

#: Field names whose values are always replaced, wherever they appear.
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "access_key",
        "secret_key",
        "private_key",
        "credential",
        "credentials",
        "cookie",
        "set_cookie",
        "session",
        "bearer",
        "database_url",
        "redis_url",
        "celery_broker_url",
        "raw_value",
        "secret_value",
    }
)

#: Values matched anywhere in a rendered message are replaced.
_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # URL userinfo:  scheme://user:password@host
    re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*://)[^:/@\s]+:[^@/\s]+@", re.I),
    # AWS access key ids
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    # Bearer tokens
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*", re.I),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # GitHub tokens
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b"),
    # PEM blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

REDACTED = "[REDACTED]"

#: Reserved on `logging.LogRecord`; a module must never overwrite these
#: through `extra=`, so we namespace collisions instead of crashing.
_RESERVED = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary log payload."""
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).strip().lower() in SENSITIVE_KEYS:
                out[str(key)] = REDACTED
            else:
                out[str(key)] = redact(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return [redact(v, _depth + 1) for v in list(value)[:200]]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    """Replace secret-shaped substrings inside a free-text string."""
    if not text:
        return text
    # Never let a hostile artifact blow up the log pipeline.
    if len(text) > 8000:
        text = text[:8000] + "…[truncated]"
    for pattern in _REDACT_PATTERNS:
        if pattern is _REDACT_PATTERNS[0]:
            text = pattern.sub(rf"\g<scheme>{REDACTED}@", text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


class RedactingFilter(logging.Filter):
    """Scrubs both the message and every `extra=` field on a record."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED or key.startswith("_"):
                continue
            if key.strip().lower() in SENSITIVE_KEYS:
                record.__dict__[key] = REDACTED
            else:
                record.__dict__[key] = redact(value)
        return True


class ConsoleFormatter(logging.Formatter):
    """Compact human-readable format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_")
        }
        if extras:
            rendered = " ".join(f"{k}={v!r}" for k, v in sorted(extras.items()))
            return f"{base}  {rendered}"
        return base


def configure_logging() -> None:
    """Install Insyte's logging configuration. Idempotent."""
    if settings.LOG_FORMAT == "json":
        formatter: dict[str, Any] = {
            "()": "pythonjsonlogger.json.JsonFormatter",
            "fmt": (
                "%(asctime)s %(levelname)s %(name)s %(message)s "
                "%(module)s %(funcName)s %(lineno)d"
            ),
            "rename_fields": {"asctime": "ts", "levelname": "level"},
        }
    else:
        formatter = {
            "()": f"{__name__}.ConsoleFormatter",
            "fmt": "%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
            "datefmt": "%H:%M:%S",
        }

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {"redact": {"()": f"{__name__}.RedactingFilter"}},
            "formatters": {"default": formatter},
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": sys.stdout,
                    "formatter": "default",
                    "filters": ["redact"],
                }
            },
            "root": {"handlers": ["stdout"], "level": settings.LOG_LEVEL},
            "loggers": {
                # These are chatty and add nothing to scan telemetry.
                "httpx": {"level": "WARNING"},
                "httpcore": {"level": "WARNING"},
                "sqlalchemy.engine": {
                    "level": "INFO" if settings.DB_ECHO else "WARNING"
                },
                "urllib3": {"level": "WARNING"},
                "asyncio": {"level": "WARNING"},
            },
        }
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def safe_extra(fields: dict[str, Any]) -> dict[str, Any]:
    """Namespace any key that would collide with a reserved LogRecord slot.

    `logging.makeRecord` raises on collisions (``module``, ``args``,
    ``filename`` …). Scan telemetry carries module and file names, so a
    naive ``extra={"module": ...}`` crashes the very code path it is
    meant to instrument. Prefixing is preferable to dropping the field.
    """
    out: dict[str, Any] = {}
    for key, value in fields.items():
        out[f"ctx_{key}" if key in _RESERVED else key] = value
    return out


class ScanLogAdapter(logging.LoggerAdapter):
    """Binds scan/module context onto every line a module emits.

    Modules log through this rather than the bare logger so that
    `scan_id`, `module`, and `target` are present on every record without
    each call site repeating them - which is what makes the structured
    scan telemetry in section 72 of the brief actually queryable.
    """

    def process(
        self, msg: Any, kwargs: dict[str, Any]
    ) -> tuple[Any, dict[str, Any]]:
        extra = dict(self.extra or {})
        extra.update(kwargs.get("extra") or {})
        kwargs["extra"] = safe_extra(extra)
        return msg, kwargs


def scan_logger(
    name: str, *, scan_id: str, module: str | None = None, target: str | None = None
) -> ScanLogAdapter:
    context: dict[str, Any] = {"scan_id": str(scan_id)}
    if module:
        context["module_name"] = module
    if target:
        context["target"] = target
    return ScanLogAdapter(get_logger(name), context)
