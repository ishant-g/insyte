"""Insyte API - FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.security_headers import SecurityHeadersMiddleware
from app.database.session import engine  # noqa: F401 - ensures the engine initialises

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("startup", extra={"app": settings.APP_NAME, "version": settings.APP_VERSION})
    yield
    logger.info("shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    summary=settings.APP_TAGLINE,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # Bearer-token auth travels in the Authorization header, not cookies,
    # so credentialed CORS stays off - the token is attached explicitly by
    # the client, and a wildcard-credential grant would add risk for nothing.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

register_exception_handlers(app)
app.include_router(api_router)
