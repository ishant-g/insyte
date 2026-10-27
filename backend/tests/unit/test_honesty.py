"""Honesty behaviors: nothing important happens silently.

Covers the Phase 0/1 guarantees: key-gated modules skip visibly instead of
completing empty, module resolution warns about dropped ids, and the CVE
correlator records weak-evidence rows instead of dropping them.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.contracts import TechnologyRecord
from app.core.target import parse_target
from app.models.enums import ScanMode
from app.modules.registry import default_registry
from app.services.cve.correlator import _correlate_one
from app.services.scan.service import ScanService


def test_email_osint_skips_visibly_without_keys() -> None:
    module = next(m for m in default_registry.all() if m.id == "email_osint")
    assert module.requires_api_key is True


def test_resolve_modules_warns_on_unknown_id(db: Session) -> None:
    svc = ScanService(db)
    parsed = parse_target("example.com")
    modules, warnings = svc._resolve_modules(
        ["definitely_not_a_module"], ScanMode.PASSIVE, parsed
    )
    assert modules == []
    assert any("definitely_not_a_module" in w for w in warnings)


def test_resolve_modules_warns_on_wrong_mode(db: Session) -> None:
    svc = ScanService(db)
    parsed = parse_target("example.com")
    modules, warnings = svc._resolve_modules(
        ["javascript_intelligence"], ScanMode.PASSIVE, parsed
    )
    assert "javascript_intelligence" not in modules
    assert any("javascript_intelligence" in w and "mode" in w for w in warnings)


def test_resolve_modules_warns_on_degraded_dependency(db: Session) -> None:
    svc = ScanService(db)
    parsed = parse_target("example.com")
    # technology_intelligence depends on web_surface; selecting it alone
    # must produce a degraded-input warning rather than silent thin output.
    modules, warnings = svc._resolve_modules(
        ["technology_intelligence"], ScanMode.PASSIVE, parsed
    )
    assert "technology_intelligence" in modules
    assert any("technology_intelligence" in w for w in warnings)


class _StubNvd:
    def lookup_keyword(self, name: str, **kwargs):
        return [
            {
                "cve_id": "CVE-2024-0001",
                "description": "Example issue in an obscure library.",
            }
        ]


def test_cve_correlator_records_keyword_fallback_instead_of_dropping() -> None:
    tech = TechnologyRecord(
        name="SomeObscureLib",
        version=None,
        version_confidence=0,
    )
    # "someobscurelib" has no vendor:product mapping and no version, so the
    # old code returned [] here. Now it must record a non-definitive row.
    rows = _correlate_one(tech, _StubNvd())
    assert len(rows) == 1
    assert rows[0].definitive is False
    assert rows[0].cve_id == "CVE-2024-0001"
