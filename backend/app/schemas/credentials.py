"""Schemas for the per-account provider-credentials API.

A secret value is only ever *accepted* (on write), never *returned*. Reads
expose configuration status and a non-reversible hint, mirroring the
existing read-only settings surface.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CredentialFieldOut(BaseModel):
    key: str
    label: str
    secret: bool
    configured: bool
    hint: str = ""
    #: True when this field is satisfied by the deployment's environment
    #: default rather than the user's own stored value.
    from_environment: bool = False


class ProviderCredentialOut(BaseModel):
    provider_id: str
    name: str
    optional: bool
    signup_url: str
    free_tier: str
    requires_api_key: bool
    #: True when every required field is satisfied (by the user or the env).
    configured: bool
    #: True when the user has stored at least one field for this provider.
    user_configured: bool
    fields: list[CredentialFieldOut]


class CredentialsListResponse(BaseModel):
    providers: list[ProviderCredentialOut]


class SetCredentialRequest(BaseModel):
    """Set one or more fields for a provider. Empty string clears a field."""

    fields: dict[str, str] = Field(default_factory=dict)
