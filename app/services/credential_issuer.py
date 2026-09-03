"""Verifiable Credential issuance and verification.

Issues a signed JWT (RS256) shaped roughly like a W3C Verifiable
Credential's JWT encoding: standard JWT claims (iss/sub/jti/iat/exp) plus a
``vc`` object carrying the credentialSubject. A real deployment would use a
proper VC library and a securely-managed signing key (KMS/HSM); here the
keypair is generated once and cached on disk under keys/ (gitignored) so
credentials remain verifiable across process restarts during local dev.

Uses PyJWT + `cryptography` directly (rather than python-jose) so this
module has no dependencies beyond what's commonly preinstalled.
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import config
from app.models.credential import VerifiableCredential
from app.models.verdict import AssuranceLevel


def _b64url_uint(value: int) -> str:
    """Base64url-encode an unsigned int, as required for JWK 'n'/'e' fields."""
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class CredentialIssuer:
    def __init__(self) -> None:
        config.KEYS_DIR.mkdir(parents=True, exist_ok=True)
        self._private_key, self._public_key, self._private_pem = self._load_or_create_keypair()
        self._jwk = self._build_jwk(self._public_key)
        self._issued: Dict[str, VerifiableCredential] = {}

    # -- key management ---------------------------------------------
    def _load_or_create_keypair(self):
        if config.PRIVATE_KEY_PATH.exists() and config.PUBLIC_KEY_PATH.exists():
            private_pem = config.PRIVATE_KEY_PATH.read_bytes()
            private_key = serialization.load_pem_private_key(private_pem, password=None)
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            config.PRIVATE_KEY_PATH.write_bytes(private_pem)
            config.PUBLIC_KEY_PATH.write_bytes(public_pem)
        public_key = private_key.public_key()
        return private_key, public_key, private_pem

    def _build_jwk(self, public_key) -> Dict[str, Any]:
        numbers = public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": config.JWT_ALGORITHM,
            "kid": "issuer-1",
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [self._jwk]}

    # -- issuance ------------------------------------------------------
    def issue(
        self,
        subject_id: str,
        institution: str,
        assurance_level: AssuranceLevel,
        risk_score: int,
        bot_score: int,
    ) -> VerifiableCredential:
        credential_id = f"vc_{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc)
        expiry_days = (
            config.CREDENTIAL_EXPIRY_DAYS_VERIFIED
            if assurance_level == AssuranceLevel.VERIFIED_EVIDENCE
            else config.CREDENTIAL_EXPIRY_DAYS_SELF_ASSERTED
        )
        expires = now + timedelta(days=expiry_days)

        payload = {
            "iss": config.ISSUER_URL,
            "sub": subject_id,
            "jti": credential_id,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "vc": {
                "type": ["VerifiableCredential", "StudentStatusCredential"],
                "issuer": config.ISSUER_NAME,
                "credentialSubject": {
                    "student": True,
                    "institution": institution,
                    "assurance_level": assurance_level.value,
                    "risk_score": risk_score,
                    "bot_score": bot_score,
                },
            },
        }
        token = jwt.encode(
            payload,
            self._private_pem,
            algorithm=config.JWT_ALGORITHM,
            headers={"kid": "issuer-1"},
        )

        credential = VerifiableCredential(
            credential_id=credential_id,
            token=token,
            issuer=config.ISSUER_NAME,
            subject_id=subject_id,
            institution=institution,
            student=True,
            assurance_level=assurance_level.value,
            risk_score=risk_score,
            bot_score=bot_score,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
        )
        self._issued[credential_id] = credential
        return credential

    def get(self, credential_id: str) -> Optional[VerifiableCredential]:
        return self._issued.get(credential_id)

    # -- verification ----------------------------------------------------
    def verify(self, token: str) -> Dict[str, Any]:
        """Raises jwt.PyJWTError subclasses on invalid/expired tokens."""
        return jwt.decode(
            token,
            self._public_key,
            algorithms=[config.JWT_ALGORITHM],
            issuer=config.ISSUER_URL,
        )


# Process-wide singleton so the same key + in-memory credential registry is
# used across requests.
credential_issuer = CredentialIssuer()
