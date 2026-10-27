"""Target parsing and normalization tests."""

from __future__ import annotations

import pytest

from app.core.target import TargetError, TargetType, is_subdomain_of, normalize_hostname, parse_target


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("example.com", TargetType.DOMAIN, "example.com"),
        ("EXAMPLE.COM", TargetType.DOMAIN, "example.com"),
        ("https://example.com/", TargetType.DOMAIN, "example.com"),
        ("http://api.dev.example.co.uk/a/b?c=1", TargetType.DOMAIN, "api.dev.example.co.uk"),
        ("//example.com", TargetType.DOMAIN, "example.com"),
        ("example.com.", TargetType.DOMAIN, "example.com"),
        ("8.8.8.8", TargetType.IPV4, "8.8.8.8"),
        ("2001:4860:4860::8888", TargetType.IPV6, "2001:4860:4860::8888"),
        ("[2001:db8::1]:443", TargetType.IPV6, "2001:db8::1"),
        ("::ffff:127.0.0.1", TargetType.IPV4, "127.0.0.1"),
        ("bucket.s3.amazonaws.com", TargetType.DOMAIN, "bucket.s3.amazonaws.com"),
        ("sub.example.com:8443", TargetType.DOMAIN, "sub.example.com"),
    ],
)
def test_accepts_valid_targets(raw: str, expected_type: TargetType, expected_value: str) -> None:
    result = parse_target(raw)
    assert result.target_type is expected_type
    assert result.value == expected_value


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "example",
        "ftp://example.com",
        "file:///etc/passwd",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "1.2.3.4.5",
        "user:pass@example.com",
        "exa mple.com",
        "a_b.example.com",
        "example..com",
        "-bad.example.com",
        "example.123",
        "::ffff:127.0.0.1%eth0",
        "fe80::1%eth0",
        "x" * 300 + ".com",
        "exam\nple.com",
        "javascript:alert(1)",
        "../../etc/passwd",
    ],
)
def test_rejects_invalid_targets(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)


def test_idn_domain_normalizes_to_punycode() -> None:
    result = parse_target("münchen.de")
    assert result.value == "xn--mnchen-3ya.de"
    assert result.unicode_value == "münchen.de"


def test_registrable_domain_and_subdomain_split() -> None:
    result = parse_target("api.dev.example.co.uk")
    assert result.registrable == "example.co.uk"
    assert result.subdomain == "api.dev"
    assert result.suffix == "co.uk"


def test_slug_is_filesystem_safe() -> None:
    result = parse_target("api.dev.example.co.uk")
    assert result.slug == "api-dev-example-co-uk"
    assert "/" not in result.slug
    assert ".." not in result.slug


def test_normalize_hostname_handles_wildcards_and_garbage() -> None:
    assert normalize_hostname("*.EXAMPLE.com.") == "*.example.com"
    assert normalize_hostname("not a hostname") is None
    assert normalize_hostname("") is None
    assert normalize_hostname(None) is None  # type: ignore[arg-type]


def test_is_subdomain_of_uses_whole_labels() -> None:
    assert is_subdomain_of("api.example.com", "example.com") is True
    assert is_subdomain_of("example.com", "example.com") is True
    assert is_subdomain_of("notexample.com", "example.com") is False
    assert is_subdomain_of("evilexample.com", "example.com") is False
