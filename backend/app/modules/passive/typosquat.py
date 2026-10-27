"""Typosquatting and Lookalike Domain Discovery.

Generates plausible lookalike variants of the target domain (omitted,
duplicated and transposed characters, keyboard-adjacent substitutions,
hyphenation, TLD swaps) and checks which of them actually resolve. A
resolving lookalike is treated as potential phishing infrastructure: it
gets an observation and a finding, never a verdict, because DNS alone
cannot say who registered it or why.

DNS-only, capped at 200 candidates per scan.
"""

from __future__ import annotations

from app.core.contracts import FindingRecord, ModuleOutput, ObservationRecord
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ObservationStatus,
    ScanMode,
    Severity,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: Hard cap on generated candidates per scan - DNS resolution is the
#: expensive part, and beyond this the variants stop being plausible.
_MAX_CANDIDATES = 200

#: Cap on findings - one per resolving lookalike, but a heavily squatted
#: brand should not flood the report.
_MAX_FINDINGS = 25

#: Common TLD swaps, excluding the target's own TLD at generation time.
_TLD_SWAPS = ("com", "net", "org", "io", "co", "app", "dev", "info", "biz")

#: QWERTY adjacency used for substitution typos.
_KEYBOARD_ADJACENCY = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "i": "ujko",
    "j": "huiknm",
    "k": "jiolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfyg",
    "u": "yhji",
    "v": "cfgb",
    "w": "qeas",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
    "0": "9",
    "1": "2q",
    "2": "13qw",
    "3": "24we",
    "4": "35er",
    "5": "46rt",
    "6": "57ty",
    "7": "68yu",
    "8": "79ui",
    "9": "80io",
}


def generate_permutations(domain: str, cap: int = _MAX_CANDIDATES) -> list[str]:
    """Build lookalike domains for `domain`, most plausible first.

    Operates on the registrable domain (last two labels). Pure function -
    no DNS, no network - so it is unit-testable in isolation.
    """
    domain = (domain or "").lower().rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2 or not all(labels):
        return []
    name = ".".join(labels[:-1])
    tld = labels[-1]

    out: list[str] = []
    seen: set[str] = {domain}

    def add(candidate: str) -> None:
        candidate = candidate.lower()
        if (
            len(out) >= cap
            or candidate in seen
            or candidate == domain
            or ".." in candidate
            or candidate.startswith("-")
            or candidate.startswith(".-")
            or ".-" in candidate
        ):
            return
        seen.add(candidate)
        out.append(candidate)

    def with_tld(variant: str) -> str:
        return f"{variant}.{tld}"

    for i in range(len(name)):  # omission: exmple.com
        if len(out) >= cap:
            break
        add(with_tld(name[:i] + name[i + 1 :]))

    for i in range(len(name)):  # duplication: exaample.com
        if len(out) >= cap:
            break
        add(with_tld(name[:i] + name[i] + name[i:]))

    for i in range(len(name) - 1):  # transposition: exmaple.com
        if len(out) >= cap:
            break
        add(with_tld(name[:i] + name[i + 1] + name[i] + name[i + 2 :]))

    for i, char in enumerate(name):  # keyboard substitution: exanple.com
        if len(out) >= cap:
            break
        if char == ".":
            continue
        for replacement in _KEYBOARD_ADJACENCY.get(char, ""):
            add(with_tld(name[:i] + replacement + name[i + 1 :]))
            if len(out) >= cap:
                break

    for i in range(1, len(name)):  # hyphenation: ex-ample.com
        if len(out) >= cap:
            break
        if name[i - 1] == "." or name[i] == ".":
            continue
        add(with_tld(name[:i] + "-" + name[i:]))

    for swap in _TLD_SWAPS:  # TLD swap: example.net
        if len(out) >= cap:
            break
        if swap != tld:
            add(f"{name}.{swap}")

    return out


class TyposquatModule(IntelligenceModule):
    id = "typosquat"
    name = "Typosquat Discovery"
    description = (
        "Generates lookalike domain variants (typos, transpositions, TLD "
        "swaps) and reports which ones resolve - potential phishing "
        "infrastructure impersonating the target."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE,)
    input_types = (TargetType.DOMAIN,)
    timeout = 120.0
    order = 22

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        domain = (ctx.target.registrable or ctx.target.value or "").lower()
        if not domain:
            return output

        candidates = generate_permutations(domain)
        output.data["candidates_generated"] = len(candidates)
        if not candidates:
            return output

        try:
            import dns.exception
            import dns.resolver

            from app.modules.passive.dns_intel import RESOLVERS
        except ImportError:
            output.data["skip_reason"] = "dnspython is not installed"
            return output

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(RESOLVERS)
        resolver.timeout = 4.0
        resolver.lifetime = 6.0

        resolving: list[tuple[str, list[str]]] = []
        for candidate in candidates:
            ctx.check_cancelled()
            addresses = self._resolve_a(resolver, candidate)
            if addresses:
                resolving.append((candidate, addresses))
                output.observations.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.DOMAIN,
                        value=candidate,
                        source_type=SourceKind.PASSIVE,
                        confidence=80,
                        status=ObservationStatus.OBSERVED,
                        evidence={
                            "discovery": "lookalike domain resolves",
                            "permutation_of": domain,
                            "addresses": addresses,
                        },
                    )
                )

        output.data["resolving_count"] = len(resolving)
        output.metrics["lookalike_domains_resolving"] = len(resolving)

        for candidate, addresses in resolving[:_MAX_FINDINGS]:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.ATTACK_SURFACE,
                    severity=Severity.LOW,
                    title=f"Lookalike domain resolves: {candidate}",
                    description=(
                        f"{candidate} is a plausible typo variant of {domain} "
                        f"and currently resolves to {', '.join(addresses)}. "
                        "Resolving lookalikes are commonly used for phishing "
                        "and brand abuse; DNS alone cannot confirm malicious "
                        "intent."
                    ),
                    recommendation=(
                        "Investigate who operates the domain. If it is not "
                        "yours and looks abusive, consider defensive "
                        "registration of key variants and a takedown request."
                    ),
                    confidence=75,
                    exposure=ExposureLevel.INFERRED,
                    sources=[self.id],
                    evidence={"permutation_of": domain, "addresses": addresses},
                )
            )
        if len(resolving) > _MAX_FINDINGS:
            output.data["findings_capped"] = True
        return output

    @staticmethod
    def _resolve_a(resolver, candidate: str) -> list[str]:
        import dns.exception
        import dns.resolver

        try:
            answer = resolver.resolve(candidate, "A", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []
        except Exception:  # noqa: BLE001 - one bad lookup must not stop the sweep
            return []
        if not answer:
            return []
        addresses = []
        for record in answer:
            try:
                addresses.append(record.to_text())
            except Exception:  # noqa: BLE001 - skip unparseable records
                continue
        return addresses
