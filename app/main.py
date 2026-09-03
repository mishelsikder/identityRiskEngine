from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.http import ApiError
from app.routers.challenge import submit_evidence
from app.routers.claims import get_claim_session, land_claim
from app.routers.credentials import get_credential, verify_credential
from app.services.credential_issuer import credential_issuer


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def jwks(request: Request) -> JSONResponse:
    """Public key(s) for third parties ('other service') to verify issued
    credentials independently, without calling back into this service."""
    return JSONResponse(credential_issuer.jwks())


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


routes = [
    Route("/health", health, methods=["GET"]),
    Route("/.well-known/jwks.json", jwks, methods=["GET"]),
    Route("/claims", land_claim, methods=["POST"]),
    Route("/claims/{session_id}", get_claim_session, methods=["GET"]),
    Route("/claims/{session_id}/evidence", submit_evidence, methods=["POST"]),
    Route("/credentials/{credential_id}", get_credential, methods=["GET"]),
    Route("/credentials/verify", verify_credential, methods=["POST"]),
]

# Wide-open CORS: this is a backend meant to be called from a separately
# hosted prototype frontend (FigJam design -> your own build). Tighten this
# to specific origins before this goes anywhere near production.
middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
]

app = Starlette(
    routes=routes,
    middleware=middleware,
    exception_handlers={ApiError: api_error_handler},
)
