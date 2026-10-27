"""A curated allowlist of top-level domains.

Used only to filter false positives out of regex-based domain extraction
(JavaScript analysis, URL text mining) - never for target validation, where
`core.target.parse_target` defers to IDNA/hostname syntax rules instead of
a maintained list.

Deliberately excludes any TLD that collides with a common English word or a
short minified-JavaScript identifier - `.to`, `.is`, `.it`, `.me`, `.at`,
`.in`, `.id`, `.my`, `.name` and similar are real TLDs but firing on them
turns "extract domains from JS" into "extract every `x.y` property-access
chain", which is worse than useless. The list trades recall on rare ccTLDs
and a handful of gTLDs for a near-zero false positive rate on minified
code, which is the right trade for a passive detector whose output feeds
directly into finding generation.
"""

from __future__ import annotations

COMMON_TLDS: frozenset[str] = frozenset(
    ["com", "net", "org", "io", "dev", "app", "cloud", "xyz", "biz", "pro", "tech", "online", "site", "store", "shop", "icu", "club", "ninja", "agency", "solutions", "systems", "services", "ventures", "software", "digital", "consulting", "network", "domains", "hosting", "email", "cheap", "live", "news", "blog", "photography", "design", "studio", "finance", "money", "bank", "insurance", "gov", "edu", "mil", "int", "aero", "coop", "museum", "jobs", "travel", "mobi", "asia", "uk", "de", "fr", "es", "nl", "ru", "cn", "jp", "kr", "br", "mx", "ca", "au", "nz", "se", "no", "dk", "fi", "pl", "pt", "gr", "tr", "sa", "eg", "za", "ng", "ke", "ua", "by", "kz", "vn", "ph", "sg", "hk", "tw", "cz", "sk", "hu", "ro", "bg", "hr", "rs", "ch", "be", "gg", "fm", "sh", "tv", "cc"]
)


def has_known_tld(hostname: str) -> bool:
    if not hostname or "." not in hostname:
        return False
    tld = hostname.rsplit(".", 1)[-1].lower()
    return tld in COMMON_TLDS
