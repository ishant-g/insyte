"""Exception handling: never leak internals to the client.

Every unhandled exception becomes a generic 500 with a correlation id the
client can quote back in a support request. The real exception - stack
trace, database error text, file paths - goes to the server log only. This
is what section 71 of the brief means by "never expose stack traces,
database credentials, API keys, internal filesystem paths... to the
frontend."
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.core.net.ssrf import SSRFBlocked

logger = get_logger(__name__)


class NotFoundError(Exception):
    def __init__(self, message: str = "Not found") -> None:
        self.message = message
        super().__init__(message)


class ConflictError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ValidationError(Exception):
    """A client-supplied value failed a business rule (HTTP 400)."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class AuthError(Exception):
    """Authentication/authorization failure (HTTP 401)."""

    def __init__(self, message: str = "Not authenticated") -> None:
        self.message = message
        super().__init__(message)


def _error_body(request_id: str, message: str, *, detail: object | None = None) -> dict:
    body = {"error": message, "request_id": request_id}
    if detail is not None:
        body["detail"] = detail
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    async def not_found_handler(request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=_error_body(str(uuid.uuid4()), exc.message),
        )

    @app.exception_handler(ConflictError)
    async def conflict_handler(request: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=_error_body(str(uuid.uuid4()), exc.message),
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_body(str(uuid.uuid4()), exc.message),
        )

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=_error_body(str(uuid.uuid4()), exc.message),
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(SSRFBlocked)
    async def ssrf_handler(request: Request, exc: SSRFBlocked) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_body(
                str(uuid.uuid4()), "Request refused by network egress policy.",
                detail={"reason": exc.reason},
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic's default error payload is safe to return - it names
        # fields and constraint types, not internal state. But a
        # field_validator that raises ValueError (e.g. ScanCreate.target)
        # puts the *exception object itself* in ctx.error, which plain
        # json.dumps cannot serialise - jsonable_encoder is what FastAPI's
        # own default handler uses to convert that safely to a string.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=_error_body(
                str(uuid.uuid4()), "Validation failed.", detail=jsonable_encoder(exc.errors())
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(str(uuid.uuid4()), str(exc.detail)),
        )

    @app.exception_handler(SQLAlchemyError)
    async def db_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        request_id = str(uuid.uuid4())
        logger.exception("database_error", extra={"request_id": request_id})
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_body(request_id, "A database error occurred."),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = str(uuid.uuid4())
        logger.exception(
            "unhandled_exception",
            extra={"request_id": request_id, "path": str(request.url.path)},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_body(request_id, "An unexpected error occurred."),
        )
