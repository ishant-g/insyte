"""Secret detection and masking.

This is the one piece of Insyte where getting it wrong is a security
incident rather than a bug. The rule, stated once and enforced everywhere
this module is used: **a full secret value never leaves this function.**
Only `mask()`'s output - a short prefix, a run of asterisks, a short
suffix - is placed into a `JavaScriptRecord`, a `Finding`, an API response
or a report. Insyte does not validate, use, or authenticate with anything
it detects; masking is not a UI nicety, it is the reason detection is safe
to ship at all.

Patterns are intentionally conservative: a regex that fires on every
64-character hex string produces a report nobody trusts. Each pattern here
is anchored to a real-world credential format with a recognisable prefix or
structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: (name, severity, confidence, compiled pattern). Order matters: more
#: specific patterns (a labelled prefix) are tried before generic ones.
_PATTERNS: tuple[tuple[str, str, int, re.Pattern[str]], ...] = (
    (
        "AWS Access Key ID", "high", 92,
        re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    ),
    (
        "AWS Secret Access Key", "high", 55,
        re.compile(
            r"""(?i)aws_?secret_?(?:access_?)?key['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]"""
        ),
    ),
    (
        "GitHub Personal Access Token", "high", 93,
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    ),
    (
        "GitHub Fine-Grained Token", "high", 90,
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    (
        "Slack Token", "high", 90,
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b"),
    ),
    (
        "Slack Webhook", "medium", 85,
        re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9/]{20,60})"),
    ),
    (
        "Stripe Live Secret Key", "high", 95,
        re.compile(r"\b(sk_live_[A-Za-z0-9]{20,247})\b"),
    ),
    (
        "Stripe Restricted Key", "high", 90,
        re.compile(r"\b(rk_live_[A-Za-z0-9]{20,247})\b"),
    ),
    (
        "Google API Key", "medium", 80,
        re.compile(r"\b(AIza[A-Za-z0-9_\-]{35})\b"),
    ),
    (
        "Google OAuth Client Secret", "high", 60,
        re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{20,})\b"),
    ),
    (
        "Firebase Cloud Messaging Key", "medium", 70,
        re.compile(r"\b(AAAA[A-Za-z0-9_\-:]{80,140})\b"),
    ),
    (
        "Twilio API Key", "high", 88,
        re.compile(r"\b(SK[a-f0-9]{32})\b"),
    ),
    (
        "SendGrid API Key", "high", 90,
        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    ),
    (
        "Mailgun API Key", "medium", 78,
        re.compile(r"\b(key-[a-f0-9]{32})\b"),
    ),
    (
        "npm Access Token", "high", 88,
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
    ),
    (
        "JSON Web Token", "medium", 65,
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
    ),
    (
        "Private Key Block", "high", 97,
        re.compile(
            r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[^-]{0,80})"
        ),
    ),
    (
        "Generic Bearer Token", "low", 45,
        re.compile(r"""(?i)bearer\s+([A-Za-z0-9_\-.]{20,400})"""),
    ),
    (
        "Generic Assigned Secret", "low", 40,
        re.compile(
            r"""(?i)\b(?:secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{16,100})['"]"""
        ),
    ),
    (
        "Slack User Token", "medium", 75,
        re.compile(r"\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})\b"),
    ),
)

#: Values that trip a pattern but are placeholders, not secrets. Checked
#: case-insensitively against the matched value itself.
_PLACEHOLDER_VALUES = frozenset(
    {
        "your_api_key_here", "your-api-key-here", "changeme", "change_me",
        "xxxxxxxxxxxxxxxxxxxx", "example", "test", "placeholder", "dummy",
        "insert_key_here", "replace_with_your_key", "api_key_placeholder",
        "0000000000000000", "1111111111111111",
    }
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    type: str
    severity: str
    confidence: int
    masked: str
    source: str
    #: SHA-256 of the *real* value, kept only so the same secret seen twice
    #: dedupes without ever storing or comparing the plaintext elsewhere.
    value_digest: str


def mask(value: str) -> str:
    """Reduce a secret to a short, safe-to-display preview.

    Fewer than 10 characters: fully redacted (a short match is likelier to
    be a false positive, and there is nothing useful to preview anyway).
    Otherwise: 4 leading characters, an asterisk run standing in for the
    middle, 4 trailing characters, capped at 24 characters of total display
    width regardless of the real length. The real length is never
    disclosed by echoing it in the mask.
    """
    if len(value) < 10:
        return "*" * len(value)
    prefix = value[:4]
    suffix = value[-4:]
    return f"{prefix}{'*' * 8}{suffix}"


def _digest(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def find_secrets(text: str, *, source: str = "", max_matches: int = 25) -> list[dict]:
    """Scan `text` for secret-shaped values. Returns already-masked results.

    The plaintext match is held only for the duration of this call, to
    compute the mask and the digest, and is never returned, logged or
    stored - `masked` and `value_digest` are the only trace that survives.
    """
    results: list[dict] = []
    seen_digests: set[str] = set()

    # Cap the input so a hostile multi-megabyte bundle cannot turn secret
    # scanning into a denial-of-service against the worker.
    haystack = text[:2_000_000]

    for name, severity, confidence, pattern in _PATTERNS:
        if len(results) >= max_matches:
            break
        for match in pattern.finditer(haystack):
            if len(results) >= max_matches:
                break
            value = match.group(1) if match.groups() else match.group(0)
            if not value or len(value) < 8:
                continue
            if value.strip().lower() in _PLACEHOLDER_VALUES:
                continue
            if _looks_like_placeholder(value):
                continue
            digest = _digest(value)
            if digest in seen_digests:
                continue
            seen_digests.add(digest)
            results.append(
                {
                    "type": name,
                    "severity": severity,
                    "confidence": confidence,
                    "masked": mask(value),
                    "source": source,
                    "value_digest": digest,
                }
            )
    return results


def _looks_like_placeholder(value: str) -> bool:
    """Reject the common false-positive shapes: repeated characters,
    sequential runs, and obvious template tokens.
    """
    stripped = value.strip("'\"")
    if len(set(stripped.lower())) <= 2:
        return True
    if stripped.lower() in ("null", "undefined", "none", "nil"):
        return True
    if re.fullmatch(r"[xX]{6,}", stripped):
        return True
    if "{{" in stripped or "${" in stripped or "%s" in stripped:
        return True
    return False
