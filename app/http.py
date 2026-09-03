"""Tiny FastAPI-shaped helpers on top of raw Starlette.

FastAPI wasn't installable in the environment this was built in (no PyPI
egress), so this backend is built directly on Starlette — FastAPI's own
foundation — instead. This module re-implements just the two conveniences
FastAPI would otherwise give routers for free: request-body -> pydantic
validation, and structured HTTP error responses.

See docs/ARCHITECTURE.md for how to swap this for real FastAPI later
(it's a one-file change; every router function signature below is already
compatible with being wrapped by a FastAPI route instead).
"""
from typing import Type, TypeVar

from pydantic import BaseModel, ValidationError
from starlette.requests import Request

M = TypeVar("M", bound=BaseModel)


class ApiError(Exception):
    """Raise from a route handler to short-circuit to a JSON error response."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


async def parse_body(request: Request, model: Type[M]) -> M:
    """Read the request's JSON body and validate it against a pydantic model,
    raising ApiError(400) on malformed JSON or ApiError(422) with field-level
    errors on a failed validation."""
    try:
        data = await request.json()
    except Exception as exc:  # noqa: BLE001 - any JSON decode failure
        raise ApiError(400, f"request body must be valid JSON: {exc}") from exc

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ApiError(422, exc.errors()) from exc
