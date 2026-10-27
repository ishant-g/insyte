"""Per-account credential injection.

Providers read their keys through :meth:`Provider.credential` (and, for the
two two-part providers, directly from ``settings``). Historically that was
env-only. To support **per-account** keys without turning the process-global
provider singletons into per-request objects, a scan installs the running
user's decrypted keys into a :class:`~contextvars.ContextVar` for the
duration of the scan; the providers consult that override first and fall
back to the deployment's environment defaults.

The override is set inside each module worker thread (see the orchestrator),
because ``ContextVar`` values do not propagate into ``ThreadPoolExecutor``
workers automatically.

The public catalogue of which fields each provider needs (``PROVIDER_FIELDS``)
is the single source of truth shared by the API schema, the settings UI and
this resolver - add a provider's fields here once and every layer agrees.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Catalogue: provider_id -> the credential fields it accepts.
# `optional` providers work unauthenticated but a key raises their limits.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CredentialField:
    key: str  # canonical field name, e.g. "api_key", "api_id", "cx"
    label: str
    secret: bool = True  # secret fields are masked in the UI and encrypted


@dataclass(frozen=True, slots=True)
class ProviderCredentialSpec:
    provider_id: str
    name: str
    fields: tuple[CredentialField, ...]
    optional: bool = False  # provider still runs with no key, key improves it
    signup_url: str = ""
    free_tier: str = ""


PROVIDER_SPECS: tuple[ProviderCredentialSpec, ...] = (
    ProviderCredentialSpec(
        "virustotal", "VirusTotal", (CredentialField("api_key", "API key"),),
        signup_url="https://www.virustotal.com/gui/join-us",
        free_tier="Free public API key (4 req/min).",
    ),
    ProviderCredentialSpec(
        "shodan", "Shodan", (CredentialField("api_key", "API key"),),
        signup_url="https://account.shodan.io/register",
        free_tier="Free membership key covers host lookups.",
    ),
    ProviderCredentialSpec(
        "censys", "Censys",
        (CredentialField("api_id", "API ID"), CredentialField("api_secret", "API secret")),
        signup_url="https://accounts.censys.io/register",
        free_tier="Free account: 250 queries/month.",
    ),
    ProviderCredentialSpec(
        "securitytrails", "SecurityTrails", (CredentialField("api_key", "API key"),),
        signup_url="https://securitytrails.com/app/signup",
        free_tier="Free tier: 50 queries/month.",
    ),
    ProviderCredentialSpec(
        "github", "GitHub", (CredentialField("token", "Personal access token"),),
        signup_url="https://github.com/settings/tokens",
        free_tier="Free fine-grained PAT (read-only, public scope).",
    ),
    ProviderCredentialSpec(
        "urlscan", "urlscan.io", (CredentialField("api_key", "API key"),),
        optional=True,
        signup_url="https://urlscan.io/user/signup",
        free_tier="Works anonymously; a free key raises rate limits.",
    ),
    ProviderCredentialSpec(
        "otx", "AlienVault OTX", (CredentialField("api_key", "API key"),),
        optional=True,
        signup_url="https://otx.alienvault.com/",
        free_tier="Free account key; anonymous access also works.",
    ),
    ProviderCredentialSpec(
        "abuseipdb", "AbuseIPDB", (CredentialField("api_key", "API key"),),
        signup_url="https://www.abuseipdb.com/register",
        free_tier="Free plan: 1,000 checks/day.",
    ),
    ProviderCredentialSpec(
        "chaos", "Chaos (ProjectDiscovery)", (CredentialField("api_key", "API key"),),
        signup_url="https://cloud.projectdiscovery.io/",
        free_tier="Free key with a generous subdomain quota.",
    ),
    ProviderCredentialSpec(
        "greynoise", "GreyNoise", (CredentialField("api_key", "API key"),),
        optional=True,
        signup_url="https://viz.greynoise.io/signup",
        free_tier="Community API is anonymous; a key raises limits.",
    ),
    ProviderCredentialSpec(
        "opencorporates", "OpenCorporates", (CredentialField("token", "API token"),),
        optional=True,
        signup_url="https://opencorporates.com/api_accounts/new",
        free_tier="Free registration token; anonymous access is limited.",
    ),
    ProviderCredentialSpec(
        "hunterio", "Hunter.io", (CredentialField("api_key", "API key"),),
        signup_url="https://hunter.io/users/sign_up",
        free_tier="Free plan: 25 searches/month.",
    ),
    ProviderCredentialSpec(
        "google_cse", "Google Programmable Search",
        (CredentialField("api_key", "API key"), CredentialField("cx", "Search engine ID", secret=False)),
        signup_url="https://programmablesearchengine.google.com/",
        free_tier="Free: 100 queries/day.",
    ),
    ProviderCredentialSpec(
        "nvd", "NVD (NIST)", (CredentialField("api_key", "API key"),),
        optional=True,
        signup_url="https://nvd.nist.gov/developers/request-an-api-key",
        free_tier="Works without a key; a key raises the rate limit.",
    ),
    ProviderCredentialSpec(
        "hibp", "Have I Been Pwned", (CredentialField("api_key", "API key"),),
        signup_url="https://haveibeenpwned.com/API/Key",
        free_tier="Paid key required (no free tier).",
    ),
)

PROVIDER_SPEC_BY_ID: dict[str, ProviderCredentialSpec] = {s.provider_id: s for s in PROVIDER_SPECS}


def known_provider(provider_id: str) -> bool:
    return provider_id in PROVIDER_SPEC_BY_ID


def valid_fields(provider_id: str) -> set[str]:
    spec = PROVIDER_SPEC_BY_ID.get(provider_id)
    return {f.key for f in spec.fields} if spec else set()


# ---------------------------------------------------------------------------
# Per-scan override context
# ---------------------------------------------------------------------------

#: {provider_id: {field: value}} for the account whose scan is running.
_override: ContextVar[dict[str, dict[str, str]] | None] = ContextVar(
    "insyte_credential_override", default=None
)


def set_override(mapping: dict[str, dict[str, str]] | None):
    """Install per-account credentials for the current context; returns a token."""
    return _override.set(mapping or None)


def reset_override(token) -> None:
    _override.reset(token)


def override_value(provider_id: str, field: str) -> str | None:
    """Return the account-supplied value for a provider field, if any."""
    mapping = _override.get()
    if not mapping:
        return None
    return (mapping.get(provider_id) or {}).get(field) or None


def override_single(provider_id: str) -> str | None:
    """Return the account value for a single-field provider, whatever its
    field is named (``api_key`` or ``token``)."""
    mapping = _override.get()
    if not mapping:
        return None
    fields = mapping.get(provider_id) or {}
    for name in ("api_key", "token"):
        if fields.get(name):
            return fields[name]
    for value in fields.values():
        if value:
            return value
    return None
