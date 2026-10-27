"""Module and provider catalogue, and the egress security policy."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.net.ssrf import describe_policy
from app.modules.registry import default_registry
from app.providers import describe_providers
from app.schemas.module import ModuleDescriptor, ProviderDescriptor

router = APIRouter(tags=["catalogue"])


@router.get("/modules", response_model=list[ModuleDescriptor])
def list_modules() -> list[ModuleDescriptor]:
    return [ModuleDescriptor(**m) for m in default_registry.describe_all()]


@router.get("/providers", response_model=list[ProviderDescriptor])
def list_providers() -> list[ProviderDescriptor]:
    return [ProviderDescriptor(**p) for p in describe_providers()]


@router.get("/security-policy")
def security_policy() -> dict:
    return describe_policy()
