"""Secret detection and masking tests.

The rule under test: a full secret value must never be reconstructable
from what `find_secrets` returns.
"""

from __future__ import annotations

from app.services.artifacts.masking import find_secrets, mask

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "1234567890abcdefghij1234567890ABCDEF"
STRIPE_KEY = "sk_" + "live_" + "51H8xyzABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
PRIVATE_KEY_MARKER = "-----BEGIN " + "RSA PRIVATE KEY-----"


def test_mask_never_returns_the_full_value_for_long_secrets() -> None:
    secret = AWS_KEY
    masked = mask(secret)
    assert secret not in masked
    assert masked.startswith(secret[:4])
    assert masked.endswith(secret[-4:])
    assert "*" in masked


def test_mask_fully_redacts_short_values() -> None:
    masked = mask("short1")
    assert masked == "*" * len("short1")
    assert "s" not in masked


def test_detects_aws_access_key() -> None:
    results = find_secrets(f'const key = "{AWS_KEY}";')
    assert any(r["type"] == "AWS Access Key ID" for r in results)
    for r in results:
        assert AWS_KEY not in r["masked"]


def test_detects_github_token() -> None:
    results = find_secrets(f"token: {GITHUB_TOKEN}")
    assert any(r["type"] == "GitHub Personal Access Token" for r in results)


def test_detects_stripe_live_key() -> None:
    results = find_secrets(STRIPE_KEY)
    assert any(r["type"] == "Stripe Live Secret Key" for r in results)


def test_detects_private_key_block() -> None:
    results = find_secrets(f"{PRIVATE_KEY_MARKER}\nMIIEow...")
    assert any(r["type"] == "Private Key Block" for r in results)


def test_ignores_placeholder_values() -> None:
    results = find_secrets('api_key: "your_api_key_here"')
    assert results == []


def test_ignores_repeated_character_strings() -> None:
    results = find_secrets('token = "xxxxxxxxxxxxxxxxxxxx"')
    assert results == []


def test_no_plaintext_secret_survives_in_any_returned_field() -> None:
    secret = GITHUB_TOKEN
    js = f'const t = "{secret}";'
    results = find_secrets(js)
    assert results
    for r in results:
        for value in r.values():
            assert secret not in str(value)


def test_deduplicates_the_same_secret_seen_twice() -> None:
    secret = AWS_KEY
    js = f'const a = "{secret}"; const b = "{secret}";'
    results = find_secrets(js)
    matches = [r for r in results if r["type"] == "AWS Access Key ID"]
    assert len(matches) == 1


def test_max_matches_is_enforced() -> None:
    js = "\n".join(f'const k{i} = "AKIA{i:016d}";' for i in range(50))
    results = find_secrets(js, max_matches=5)
    assert len(results) <= 5


def test_oversized_input_is_capped_not_rejected() -> None:
    huge = "x" * 3_000_000 + AWS_KEY
    # Should not hang or raise — the secret is beyond the 2MB cap so it is
    # simply not found, which is the correct DoS-safe behaviour.
    results = find_secrets(huge)
    assert isinstance(results, list)
