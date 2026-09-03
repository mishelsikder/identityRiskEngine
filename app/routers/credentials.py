import jwt as pyjwt
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.http import ApiError, parse_body
from app.models.credential import CredentialVerifyRequest, CredentialVerifyResponse
from app.services.credential_issuer import credential_issuer


async def get_credential(request: Request) -> JSONResponse:
    """GET /credentials/{credential_id}"""
    credential_id = request.path_params["credential_id"]
    credential = credential_issuer.get(credential_id)
    if credential is None:
        raise ApiError(404, "credential not found")
    return JSONResponse(credential.model_dump(mode="json"))


async def verify_credential(request: Request) -> JSONResponse:
    """POST /credentials/verify — what 'the other service' calls once the
    credential is out of the user's wallet: independently verify the
    signature + expiry without needing to trust anything except the
    issuer's public key (see GET /.well-known/jwks.json)."""
    body = await parse_body(request, CredentialVerifyRequest)
    try:
        claims = credential_issuer.verify(body.token)
    except pyjwt.PyJWTError as exc:
        result = CredentialVerifyResponse(valid=False, reason=str(exc))
        return JSONResponse(result.model_dump(mode="json"))
    result = CredentialVerifyResponse(valid=True, claims=claims)
    return JSONResponse(result.model_dump(mode="json"))
