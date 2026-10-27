"""JSONB persistence must never lose a whole wave of module results.

A scan of any target that serves binary content where text was expected
(a favicon at `/.well-known/`, an icon font, a mislabelled stylesheet)
produced a string containing NUL bytes. PostgreSQL refuses to store a
NUL in `text`/`jsonb`, so the flush raised `UntranslatableCharacter`,
the wave's transaction rolled back, and every module row was left
stuck at "running" with the scan frozen at 0% - with the failure
recovery unable to finalise it either, because it reused the same
already-rolled-back session.
"""

from __future__ import annotations

import json

import pytest

from app.services.scan.persist import _jsonable, _sanitize_text


def test_nul_byte_is_removed_so_the_column_accepts_the_value() -> None:
    # What a PNG favicon decodes to: replacement chars around raw NULs.
    body = "\ufffdPNG\r\n\x1a\n\x00\x00\x00IHDR"
    cleaned = _sanitize_text(body)

    assert "\x00" not in cleaned
    # Still readable - the scan keeps the evidence a human can look at.
    assert "PNG" in cleaned and "IHDR" in cleaned
    # And crucially, JSON-serialisable with no escape PostgreSQL rejects.
    assert "\u0000" not in json.dumps(cleaned)


def test_control_characters_and_lone_surrogates_are_removed() -> None:
    for hostile in ("a\x00b", "a\x1fb", "a\x7fb", "bad\ud800surrogate"):
        out = _sanitize_text(hostile)
        assert out == "ab" if hostile == "a\x00b" else True
        out.encode("utf-8")  # must not raise: lone surrogates cannot


def test_clean_text_is_returned_unchanged() -> None:
    for clean in ("", "hello", "line\nbreak\ttab", "café — ünïcode", '{"json": true}'):
        assert _sanitize_text(clean) == clean


def test_jsonable_sanitises_nested_structures() -> None:
    # The real shape: module `data` holding fetched response bodies.
    # `\x89` is a C1 control byte from a PNG, stripped like the NULs.
    payload = {
        "bodies": {"https://x/favicon.ico": "\x89PNG\x00\x00"},
        "metrics": {"urls_fetched": 1, "ok": True, "missing": None},
        "tags": ["a\x00b", ("c\x00d",)],
        "nested": {"deep": {"nul": "x\x00y"}},
    }

    out = _jsonable(payload)
    encoded = json.dumps(out)

    assert "\u0000" not in encoded
    assert out["bodies"]["https://x/favicon.ico"] == "PNG"
    assert out["tags"] == ["ab", ["cd"]]
    assert out["nested"]["deep"]["nul"] == "xy"
    # Non-string scalars must survive untouched.
    assert out["metrics"] == {"urls_fetched": 1, "ok": True, "missing": None}


def test_jsonable_stays_total_for_unserialisable_values() -> None:
    class Weird:
        def __str__(self) -> str:
            return "weird\x00value"

    out = _jsonable({"obj": Weird(), "when": object()})
    assert "\u0000" not in json.dumps(out)
    assert out["obj"] == "weirdvalue"


@pytest.mark.parametrize("bad", ["\x00", "\ud800", "\x1f"])
def test_no_surviving_character_is_rejected_by_postgres(bad: str) -> None:
    out = _sanitize_text(f"before{bad}after")
    assert bad not in out
    out.encode("utf-8")
