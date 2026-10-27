"""Module catalogue and settings schemas."""

from __future__ import annotations

from pydantic import BaseModel


class ModuleDescriptor(BaseModel):
    id: str
    name: str
    description: str
    category: str
    category_label: str
    version: str
    mode_support: list[str]
    input_types: list[str]
    dependencies: list[str]
    providers: list[str]
    requires_api_key: bool
    timeout: float
    recommended: bool


class ProviderDescriptor(BaseModel):
    id: str
    name: str
    kind: str
    description: str
    homepage: str
    requires_api_key: bool
    configured: bool
    reliability: int
    intents: list[str]
