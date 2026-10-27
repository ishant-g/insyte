"""URL canonicalisation, classification and deduplication tests."""

from __future__ import annotations

from app.core.canonical import canonical_url, canonical_value


def test_dedup_hash_is_stable_across_equivalent_spellings() -> None:
    a = canonical_url("https://example.com/p?b=2&a=1")
    b = canonical_url("https://EXAMPLE.com:443/p?a=1&b=2&utm_source=newsletter")
    assert a.hash == b.hash
    assert a.normalized == b.normalized


def test_strips_tracking_params_but_keeps_real_ones() -> None:
    result = canonical_url("https://example.com/search?q=test&utm_source=x&utm_campaign=y")
    assert "utm_source" not in result.normalized
    assert "q=test" in result.normalized


def test_resolves_traversal_in_path() -> None:
    result = canonical_url("https://example.com/a/../etc/passwd")
    assert result.path == "/etc/passwd"


def test_resolves_double_encoded_traversal() -> None:
    result = canonical_url("https://example.com/a/%252e%252e%252fetc/passwd")
    assert result.path == "/etc/passwd"


def test_relative_url_resolves_against_base() -> None:
    result = canonical_url("/api/v2/users", base="https://api.example.com/app/")
    assert result is not None
    assert result.normalized == "https://api.example.com/api/v2/users"


def test_protocol_relative_url_inherits_scheme() -> None:
    result = canonical_url("//cdn.example.com/app.js", base="https://example.com/")
    assert result is not None
    assert result.scheme == "https"


def test_javascript_scheme_is_dropped() -> None:
    assert canonical_url("javascript:alert(1)") is None


def test_mailto_and_data_schemes_are_dropped() -> None:
    assert canonical_url("mailto:a@b.com") is None
    assert canonical_url("data:text/html,<script>") is None


def test_classifies_common_paths() -> None:
    assert canonical_url("https://example.com/app.js").classification.value == "javascript"
    assert canonical_url("https://example.com/bundle.js.map").classification.value == "source_map"
    assert canonical_url("https://example.com/graphql").classification.value == "graphql"
    assert canonical_url("https://example.com/api/v2/users").classification.value == "api"
    assert canonical_url("https://example.com/.env").classification.value == "configuration"
    assert canonical_url("https://example.com/wp-admin/").classification.value == "admin"
    assert canonical_url("https://example.com/swagger.json").classification.value == "api"
    assert canonical_url("https://example.com/backup.zip").classification.value == "archive"


def test_scope_detection() -> None:
    in_scope = canonical_url("https://api.example.com/x", target_host="example.com")
    out_of_scope = canonical_url("https://third-party.net/x.js", target_host="example.com")
    assert in_scope.in_scope is True
    assert out_of_scope.in_scope is False


def test_canonical_value_normalizes_by_asset_type() -> None:
    assert canonical_value("domain", "API.Example.COM.") == "api.example.com"
    assert canonical_value("asn", "as15169") == "AS15169"
    assert canonical_value("technology", " Next_JS ") == "next js"
    assert canonical_value("email", "User@Example.COM") == "user@example.com"
