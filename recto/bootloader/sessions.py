"""Session JWT helpers: EdDSA encode/verify against registered phone keys.

The bootloader caches session JWTs (one per `(service, secret)` pair)
issued by the phone. This module wraps `pyjwt`'s EdDSA support to:

- Encode a JWT issuance request for the phone to sign (the bootloader
  doesn't actually encode -- the phone does -- but this module defines
  the canonical claim shape).
- Verify a JWT received from the phone against the registered public
  key.
- Verify a per-operation signature against a session JWT (the phone
  signs operations within a session using the same Ed25519 key, NOT
  the session JWT itself; the JWT just authorizes the bootloader to
  cache approval).

Imports of `cryptography` and `jwt` are lazy at function level so that
importing this module without the [v0_4] extra installed produces a
clear runtime error rather than ImportError at module load time.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

from recto.bootloader import BootloaderError

__all__ = [
    "SessionClaims",
    "verify_jwt",
    "verify_signature",
    "build_session_issuance_payload",
    "build_sign_request_payload",
]


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """Decoded JWT claims for a session. Mirrors RFC 7519 standard
    fields plus Recto-specific extensions under the "recto:" prefix."""

    iss: str  # phone-public-key fingerprint (b64u of BLAKE2s-128 of pubkey)
    sub: str  # "{service}:{secret}"
    aud: str  # bootloader_id
    exp: int  # unix ts
    iat: int  # unix ts
    jti: str  # uuid4
    recto_scope: tuple[str, ...]
    recto_max_uses: int

    @property
    def service(self) -> str:
        return self.sub.split(":", 1)[0]

    @property
    def secret(self) -> str:
        return self.sub.split(":", 1)[1]

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.exp


def _public_key_from_b64u(public_key_b64u: str):
    """Decode a base64url Ed25519 public key into a cryptography key
    object. Raises BootloaderError on import or decode failure."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `cryptography`; install via "
            "`pip install recto[v0_4]`."
        ) from exc
    padding = "=" * (-len(public_key_b64u) % 4)
    raw = base64.urlsafe_b64decode(public_key_b64u + padding)
    if len(raw) != 32:
        raise BootloaderError(
            f"public key must decode to 32 bytes; got {len(raw)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_jwt(token: str, *, public_key_b64u: str, audience: str) -> SessionClaims:
    """Verify a session JWT signed by the phone.

    Returns parsed claims on success. Raises BootloaderError on:
    - Bad signature (key mismatch)
    - Expired token
    - Wrong audience
    - Missing required claims
    - Malformed JWT structure
    """
    try:
        import jwt
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `pyjwt`; install via "
            "`pip install recto[v0_4]`."
        ) from exc

    pub_key = _public_key_from_b64u(public_key_b64u)
    try:
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["EdDSA"],
            audience=audience,
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "jti"],
                "verify_aud": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_signature": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise BootloaderError("session JWT expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise BootloaderError(
            f"session JWT audience mismatch (expected {audience!r})"
        ) from exc
    except jwt.InvalidSignatureError as exc:
        raise BootloaderError("session JWT signature invalid") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise BootloaderError(f"session JWT missing claim: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise BootloaderError(f"session JWT malformed: {exc}") from exc

    return SessionClaims(
        iss=str(claims["iss"]),
        sub=str(claims["sub"]),
        aud=str(claims["aud"]),
        exp=int(claims["exp"]),
        iat=int(claims["iat"]),
        jti=str(claims["jti"]),
        recto_scope=tuple(claims.get("recto:scope", ())),
        recto_max_uses=int(claims.get("recto:max_uses", 0)),
    )


def verify_signature(
    *, payload: bytes, signature_b64u: str, public_key_b64u: str
) -> bool:
    """Verify an Ed25519 signature over a payload.

    Returns True on valid, False on invalid. Does NOT raise on
    invalid-signature -- callers usually want to convert the verdict
    into a deny response, not propagate an exception. Raises
    BootloaderError only on import/decode failures.
    """
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `cryptography`; install via "
            "`pip install recto[v0_4]`."
        ) from exc

    pub_key = _public_key_from_b64u(public_key_b64u)
    padding = "=" * (-len(signature_b64u) % 4)
    sig = base64.urlsafe_b64decode(signature_b64u + padding)
    if len(sig) != 64:
        return False
    try:
        pub_key.verify(sig, payload)
        return True
    except InvalidSignature:
        return False


def build_session_issuance_payload(
    *,
    service: str,
    secret: str,
    bootloader_id: str,
    lifetime_seconds: int,
    max_uses: int,
) -> dict[str, Any]:
    """The canonical claim shape the phone should encode into the JWT
    when issuing a session. The phone receives this from the bootloader
    via the pending-request mechanism, fills in `iat` / `exp` / `jti`,
    signs, and returns.

    Returned dict is JSON-serializable with sorted keys for
    canonicalization.
    """
    return {
        "sub": f"{service}:{secret}",
        "aud": bootloader_id,
        "recto:scope": ["sign"],
        "recto:max_uses": max_uses,
        "recto:lifetime_seconds": lifetime_seconds,
    }


def build_sign_request_payload(
    *,
    service: str,
    secret: str,
    payload_hash_b64u: str,
    requested_at_unix: int,
    request_id: str,
) -> dict[str, Any]:
    """The canonical shape the phone signs when responding to a single
    sign request. The phone signs the BLAKE2b-256 hash of the payload,
    not the raw payload, so the wire format doesn't have to carry the
    full data being signed (which might be large)."""
    return {
        "request_id": request_id,
        "service": service,
        "secret": secret,
        "payload_hash_b64u": payload_hash_b64u,
        "requested_at_unix": requested_at_unix,
    }
