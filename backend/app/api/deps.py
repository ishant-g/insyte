"""Shared FastAPI dependencies."""

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from app.core.crypto import TokenError, decode_access_token
from app.core.errors import AuthError
from app.database.session import SessionLocal
from app.models.user import User


def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _user_from_bearer(authorization: str | None, db: Session) -> User | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
    except TokenError:
        return None
    sub = payload.get("sub")
    if not sub:
        return None
    try:
        user = db.get(User, uuid.UUID(str(sub)))
    except (ValueError, TypeError):
        return None
    if user is None or not user.is_active:
        return None
    return user


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User:
    """Require a valid bearer token; raise 401 otherwise."""
    user = _user_from_bearer(authorization, db)
    if user is None:
        raise AuthError("Not authenticated")
    return user


def get_optional_user(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User | None:
    """Return the user if a valid token is present, else None (no error)."""
    return _user_from_bearer(authorization, db)


CurrentUser = Annotated[User, Depends(get_current_user)]
OptionalUser = Annotated[User | None, Depends(get_optional_user)]


def verify_scan_owner(
    scan_id: uuid.UUID,
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> None:
    """Router-level guard for `/scans/{scan_id}/*` sub-resources: require a
    valid token and confirm the scan belongs to the caller (or is a legacy
    ownerless scan). Raises 401 if unauthenticated, 404 if not owned."""
    user = _user_from_bearer(authorization, db)
    if user is None:
        raise AuthError("Not authenticated")
    from app.services.scan.service import ScanService

    ScanService(db).get(scan_id, user.id)
