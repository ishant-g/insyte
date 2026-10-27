"""Pure-logic tests for the passive recon additions.

Covers typosquat permutation generation, takeover fingerprint matching
and the inline MurmurHash3 implementation. All three are pure functions
with no network access, so these tests run anywhere.
"""

from __future__ import annotations

from app.modules.passive.takeover import match_takeover_service
from app.modules.passive.typosquat import generate_permutations
from app.modules.web.favicon import murmur3_x86_32, shodan_favicon_hash


def test_permutations_include_core_typo_classes() -> None:
    perms = generate_permutations("example.com")
    assert "exmple.com" in perms  # omission
    assert "exxample.com" in perms  # duplication
    assert "exmaple.com" in perms  # transposition
    assert "example.net" in perms  # TLD swap


def test_permutations_exclude_original_and_duplicates() -> None:
    perms = generate_permutations("example.com")
    assert "example.com" not in perms
    assert len(perms) == len(set(perms))


def test_permutations_respect_cap() -> None:
    perms = generate_permutations("example.com", cap=10)
    assert len(perms) == 10
    assert len(generate_permutations("example.com", cap=200)) <= 200


def test_permutations_reject_bad_input() -> None:
    assert generate_permutations("") == []
    assert generate_permutations("localhost") == []
    assert generate_permutations("EXAMPLE.COM")[0].islower()


def test_permutations_skip_invalid_labels() -> None:
    for perm in generate_permutations("example.com"):
        assert ".." not in perm
        assert not perm.split(".")[0].startswith("-")


def test_takeover_fingerprints_match_known_services() -> None:
    assert match_takeover_service("assets.github.io") == "GitHub Pages"
    assert match_takeover_service("app.herokuapp.com") == "Heroku"
    assert match_takeover_service("files.s3.amazonaws.com") == "AWS S3"
    assert (
        match_takeover_service("site.s3-website.us-east-1.amazonaws.com")
        == "AWS S3 static website"
    )
    assert match_takeover_service("shop.myshopify.com") == "Shopify"
    assert match_takeover_service("blog.tumblr.com") == "Tumblr"


def test_takeover_fingerprints_ignore_ordinary_hosts() -> None:
    assert match_takeover_service("example.com") is None
    assert match_takeover_service("mail.example.com") is None
    assert match_takeover_service("") is None


def test_takeover_fingerprint_matching_is_case_insensitive() -> None:
    assert match_takeover_service("ASSETS.GITHUB.IO") == "GitHub Pages"


def test_murmur3_matches_reference_vectors() -> None:
    assert murmur3_x86_32(b"") == 0
    assert murmur3_x86_32(b"hello") == 613153351
    assert murmur3_x86_32(b"hello", seed=0) == murmur3_x86_32(b"hello")


def test_murmur3_is_stable_and_32_bit() -> None:
    digest = murmur3_x86_32(b"insyte-favicon-test-bytes")
    assert digest == murmur3_x86_32(b"insyte-favicon-test-bytes")
    assert 0 <= digest <= 0xFFFFFFFF
    assert murmur3_x86_32(b"a") != murmur3_x86_32(b"b")


def test_shodan_favicon_hash_returns_signed_int32() -> None:
    hashed = shodan_favicon_hash(b"fake-icon-bytes")
    assert -(2**31) <= hashed <= 2**31 - 1
    assert hashed == shodan_favicon_hash(b"fake-icon-bytes")
