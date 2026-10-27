"""Per-account provider credentials.

Every route here requires authentication and operates only on the current
user's own credentials. Secret values are accepted on write and never
returned on read - the list endpoint reports configuration status and a
masked hint only.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_db
from app.schemas.credentials import (
    CredentialsListResponse,
    ProviderCredentialOut,
    SetCredentialRequest,
)
from app.services.accounts import CredentialService

router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.get("", response_model=CredentialsListResponse)
def list_credentials(user: CurrentUser, db: Session = Depends(get_db)) -> CredentialsListResponse:
    rows = CredentialService(db).list_status(user.id)
    return CredentialsListResponse(
        providers=[ProviderCredentialOut.model_validate(r) for r in rows]
    )


@router.put("/{provider_id}", response_model=CredentialsListResponse)
def set_credential(
    provider_id: str,
    payload: SetCredentialRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> CredentialsListResponse:
    svc = CredentialService(db)
    svc.set_fields(user.id, provider_id, payload.fields)
    return CredentialsListResponse(
        providers=[ProviderCredentialOut.model_validate(r) for r in svc.list_status(user.id)]
    )


@router.delete("/{provider_id}", response_model=CredentialsListResponse)
def delete_credential(
    provider_id: str,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> CredentialsListResponse:
    svc = CredentialService(db)
    svc.delete_provider(user.id, provider_id)
    return CredentialsListResponse(
        providers=[ProviderCredentialOut.model_validate(r) for r in svc.list_status(user.id)]
    )
