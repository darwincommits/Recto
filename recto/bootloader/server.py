"""HTTPS server for the v0.4 bootloader.

Implements the endpoint set defined in `docs/v0.4-protocol.md`:

- POST /v0.4/register
- GET  /v0.4/registration_challenge
- POST /v0.4/issue_session
- GET  /v0.4/pending?phone_id=<id>
- POST /v0.4/respond/<request_id>

Uses stdlib `http.server.ThreadingHTTPServer` + `ssl.SSLContext`. No
extra HTTP-framework dependency. The server is single-process (one
bootloader per service, owned by the launcher); concurrency comes from
the threading mixin handling each request on its own thread.

State access is delegated to `recto.bootloader.state.StateStore`, which
is internally thread-safe. The handler holds a reference to the store
and a few config values via class attributes set at server creation.

Threat model notes are in module docstrings of `state.py` and
`sessions.py`. This module enforces the wire-protocol contract; it does
NOT do rate limiting, brute-force defense, or replay protection beyond
the JWT `jti` and challenge expiry. Production hardening is followup
work tracked in the v0.4 deferred-items list.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from recto.bootloader import (
    BootloaderError,
    PendingRequestNotFoundError,
    RegistrationExpiredError,
    UnknownPhoneError,
)
from recto.bootloader.sessions import (
    build_session_issuance_payload,
    verify_jwt,
    verify_signature,
)
from recto.bootloader.state import (
    PendingRequest,
    PhoneRegistration,
    Session,
    StateStore,
)

__all__ = [
    "BootloaderHandler",
    "BootloaderConfig",
    "ChallengeStore",
    "create_server",
]

PROTOCOL_VERSION = 1


class BootloaderConfig:
    """Server-side config values shared across requests.

    Lives on the handler class as a class attribute (set by
    `create_server`). Threading.local would be overkill -- these
    values don't change during the bootloader's lifetime."""

    bootloader_id: str = ""
    state: StateStore | None = None
    challenges: "ChallengeStore | None" = None
    default_session_lifetime_seconds: int = 86400  # 24h
    default_session_max_uses: int = 1000


class ChallengeStore:
    """In-memory store of one-time challenges.

    Two challenge types share the same TTL store:
    - Registration challenges (60s TTL, single use).
    - Pairing codes (300s TTL, single use, 6-digit human-readable).

    Not persisted. On bootloader restart, all in-flight challenges are
    invalidated -- the operator re-runs `recto v0.4 register` to get
    a fresh code.
    """

    def __init__(self) -> None:
        self._challenges: dict[str, int] = {}  # value -> expires_at_unix
        self._pairing_codes: dict[str, int] = {}  # code -> expires_at_unix

    def issue_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]:
        c = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        exp = int(time.time()) + ttl_seconds
        self._challenges[c] = exp
        return c, exp

    def consume_challenge(self, c: str) -> bool:
        """Return True if the challenge exists and is unexpired; remove
        it on success (single-use)."""
        self._purge()
        exp = self._challenges.pop(c, None)
        return exp is not None and time.time() < exp

    def issue_pairing_code(self, ttl_seconds: int = 300) -> tuple[str, int]:
        # 6-digit human-readable; collision risk acceptable for personal-use.
        code = f"{secrets.randbelow(1_000_000):06d}"
        exp = int(time.time()) + ttl_seconds
        self._pairing_codes[code] = exp
        return code, exp

    def consume_pairing_code(self, code: str) -> bool:
        self._purge()
        exp = self._pairing_codes.pop(code, None)
        return exp is not None and time.time() < exp

    def _purge(self) -> None:
        now = time.time()
        self._challenges = {c: e for c, e in self._challenges.items() if e > now}
        self._pairing_codes = {c: e for c, e in self._pairing_codes.items() if e > now}


class BootloaderHandler(BaseHTTPRequestHandler):
    """HTTP request handler implementing the v0.4 endpoint set."""

    # Override the default banner to not leak Python version.
    server_version = "RectoBootloader/0.4"
    sys_version = ""

    config: BootloaderConfig = BootloaderConfig()

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        try:
            url = urlparse(self.path)
            if url.path == "/v0.4/registration_challenge":
                self._handle_registration_challenge(url)
            elif url.path == "/v0.4/pending":
                self._handle_pending(url)
            elif url.path == "/v0.4/health":
                self._handle_health()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
        except BootloaderError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bootloader_error", "detail": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal", "detail": type(e).__name__},
            )

    def do_POST(self) -> None:
        try:
            url = urlparse(self.path)
            body = self._read_json_body()
            if url.path == "/v0.4/register":
                self._handle_register(body)
            elif url.path == "/v0.4/issue_session":
                self._handle_issue_session(body)
            elif url.path.startswith("/v0.4/respond/"):
                request_id = url.path[len("/v0.4/respond/"):]
                self._handle_respond(request_id, body)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
        except BootloaderError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bootloader_error", "detail": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal", "detail": type(e).__name__},
            )

    # ------------------------------------------------------------------
    # GET /v0.4/health
    # ------------------------------------------------------------------

    def _handle_health(self) -> None:
        cfg = self.config
        self._send_json(HTTPStatus.OK, {
            "ok": True,
            "bootloader_id": cfg.bootloader_id,
            "v0_4_protocol": PROTOCOL_VERSION,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/registration_challenge
    # ------------------------------------------------------------------

    def _handle_registration_challenge(self, url) -> None:
        cfg = self.config
        if cfg.challenges is None:
            raise BootloaderError("challenge store not initialized")
        # Optional pairing-code gating: if `code=` query param is present,
        # the operator-issued pairing code must match.
        params = parse_qs(url.query)
        if "code" in params:
            if not cfg.challenges.consume_pairing_code(params["code"][0]):
                raise RegistrationExpiredError("pairing code expired or invalid")
        challenge, expires_at = cfg.challenges.issue_challenge()
        self._send_json(HTTPStatus.OK, {
            "challenge_b64u": challenge,
            "expires_at_unix": expires_at,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/register
    # ------------------------------------------------------------------

    def _handle_register(self, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None or cfg.challenges is None:
            raise BootloaderError("server not initialized")
        proof = body.get("registration_proof") or {}
        challenge = proof.get("challenge", "")
        sig = proof.get("signature_b64u", "")
        public_key_b64u = body.get("public_key_b64u", "")
        device_label = body.get("device_label", "(unnamed)")
        algos = tuple(body.get("supported_algorithms", ["ed25519"]))
        if body.get("v0_4_protocol") != PROTOCOL_VERSION:
            raise BootloaderError(
                f"protocol version mismatch: server={PROTOCOL_VERSION}, "
                f"phone={body.get('v0_4_protocol')!r}"
            )
        if not cfg.challenges.consume_challenge(challenge):
            raise RegistrationExpiredError("registration challenge expired or invalid")
        # Verify the phone's signature over the challenge using the
        # claimed public key. This proves possession of the private
        # key without disclosing it.
        ok = verify_signature(
            payload=challenge.encode("ascii"),
            signature_b64u=sig,
            public_key_b64u=public_key_b64u,
        )
        if not ok:
            raise BootloaderError("registration proof signature invalid")
        reg = PhoneRegistration.new(
            device_label=str(device_label),
            public_key_b64u=public_key_b64u,
            supported_algorithms=algos,
        )
        cfg.state.register_phone(reg)
        self._send_json(HTTPStatus.CREATED, {
            "registered": True,
            "phone_id": reg.phone_id,
            "bootloader_id": cfg.bootloader_id,
            # Empty managed_secrets for now; the operator wires services
            # to specific phone_ids via service.yaml's
            # spec.secrets[].config.phone_id field (TBD once the launcher
            # side lands).
            "managed_secrets": [],
        })

    # ------------------------------------------------------------------
    # POST /v0.4/issue_session
    # ------------------------------------------------------------------

    def _handle_issue_session(self, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        phone_id = body.get("phone_id", "")
        token = body.get("session_token_jwt", "")
        phone = cfg.state.get_phone(phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        # Verify the JWT signature against the phone's public key, and
        # parse the claims.
        claims = verify_jwt(
            token,
            public_key_b64u=phone.public_key_b64u,
            audience=cfg.bootloader_id,
        )
        sess = Session(
            service=claims.service,
            secret=claims.secret,
            phone_id=phone_id,
            jwt=token,
            expires_at_unix=claims.exp,
            issued_at_unix=claims.iat,
            max_uses=claims.recto_max_uses,
            uses_so_far=0,
        )
        cfg.state.put_session(sess)
        self._send_json(HTTPStatus.CREATED, {
            "session_id": claims.jti,
            "expires_at_unix": claims.exp,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/pending?phone_id=<id>
    # ------------------------------------------------------------------

    def _handle_pending(self, url) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        params = parse_qs(url.query)
        phone_ids = params.get("phone_id", [])
        if not phone_ids:
            raise BootloaderError("phone_id query parameter required")
        phone_id = phone_ids[0]
        if cfg.state.get_phone(phone_id) is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        pending = cfg.state.list_pending_for_phone(phone_id)
        self._send_json(HTTPStatus.OK, {
            "requests": [self._pending_to_wire(p) for p in pending],
        })

    @staticmethod
    def _pending_to_wire(p: PendingRequest) -> dict[str, Any]:
        context: dict[str, Any] = {
            "child_pid": p.child_pid,
            "child_argv0": p.child_argv0,
            "requested_at_unix": p.requested_at_unix,
            "operation_description": p.operation_description,
            "payload_hash_b64u": p.payload_hash_b64u,
        }
        # ETH-specific context fields. Emitted only when actually set so
        # non-ETH kinds keep an unchanged wire shape (kept-keys minimal,
        # easier to assert in tests). Mirrors the C# PendingRequestContext
        # additions in Recto.Shared.Protocol.V04.
        if p.kind == "eth_sign":
            context["eth_chain_id"] = p.eth_chain_id
            context["eth_message_kind"] = p.eth_message_kind
            context["eth_address"] = p.eth_address
            context["eth_derivation_path"] = p.eth_derivation_path
            if p.eth_message_text is not None:
                context["eth_message_text"] = p.eth_message_text
            if p.eth_typed_data_json is not None:
                context["eth_typed_data_json"] = p.eth_typed_data_json
            if p.eth_transaction_json is not None:
                context["eth_transaction_json"] = p.eth_transaction_json
        # BTC-specific context fields. Same pattern as ETH — emitted only
        # for `btc_sign` kind so non-BTC wire shape is unchanged.
        if p.kind == "btc_sign":
            context["btc_network"] = p.btc_network
            context["btc_message_kind"] = p.btc_message_kind
            context["btc_address"] = p.btc_address
            context["btc_derivation_path"] = p.btc_derivation_path
            if p.btc_message_text is not None:
                context["btc_message_text"] = p.btc_message_text
            if p.btc_psbt_base64 is not None:
                context["btc_psbt_base64"] = p.btc_psbt_base64
            # Wave-7 multi-coin: emit btc_coin so the phone can pick the
            # right preamble + address format. Default null at the wire
            # layer so v0.5 phones (which would silently treat absent
            # field as Bitcoin) don't break.
            if p.btc_coin is not None and p.btc_coin != "btc":
                context["btc_coin"] = p.btc_coin
        # ED25519-chain context (kind == "ed_sign", wave-8). Same
        # emit-only-when-set pattern as ETH/BTC so non-ed wire shape
        # is unchanged. Mirrors the C# `PendingRequestContext` ED
        # additions in `Recto.Shared.Protocol.V04`.
        if p.kind == "ed_sign":
            context["ed_chain"] = p.ed_chain
            context["ed_message_kind"] = p.ed_message_kind
            context["ed_address"] = p.ed_address
            context["ed_derivation_path"] = p.ed_derivation_path
            if p.ed_message_text is not None:
                context["ed_message_text"] = p.ed_message_text
            if p.ed_payload_hex is not None:
                context["ed_payload_hex"] = p.ed_payload_hex
        return {
            "request_id": p.request_id,
            "kind": p.kind,
            "service": p.service,
            "secret": p.secret,
            "context": context,
        }

    # ------------------------------------------------------------------
    # POST /v0.4/respond/<request_id>
    # ------------------------------------------------------------------

    def _handle_respond(self, request_id: str, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        req = cfg.state.take_pending(request_id)
        if req is None:
            raise PendingRequestNotFoundError(
                f"request_id {request_id!r} not found"
            )
        decision = body.get("decision", "")
        if decision == "denied":
            # Operator declined; surface to whoever is awaiting the
            # response. The waiting mechanism (an in-process Future or
            # similar) is the launcher's responsibility; the bootloader
            # just marks the pending as resolved-with-denial.
            self._notify_resolved(req, ok=False, signature_b64u=None,
                                  eth_signature_rsv=None,
                                  btc_signature_base64=None,
                                  reason=body.get("reason", "denied"))
            self._send_json(HTTPStatus.OK, {"resolved": True})
            return
        if decision != "approved":
            raise BootloaderError(f"unknown decision {decision!r}")
        sig = body.get("signature_b64u", "")
        phone = cfg.state.get_phone(req.phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone {req.phone_id!r} no longer registered")
        # Verify the phone's signature over the payload hash.
        # The phone signs the BLAKE2b-256 hash, not the raw payload,
        # so we verify against the hash bytes.
        # For kind=="eth_sign" this Ed25519 envelope still applies — it
        # proves the response came from the paired phone. The Ethereum
        # secp256k1 r||s||v signature rides alongside as an opaque
        # forwarded value (see protocol RFC §"Approval response").
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ok = verify_signature(
            payload=hash_bytes,
            signature_b64u=sig,
            public_key_b64u=phone.public_key_b64u,
        )
        if not ok:
            self._notify_resolved(req, ok=False, signature_b64u=None,
                                  eth_signature_rsv=None,
                                  btc_signature_base64=None,
                                  reason="signature verification failed")
            raise BootloaderError("approved-response signature invalid")
        # Extract the Ethereum signature when the kind is eth_sign. Per
        # the protocol RFC the bootloader does NOT validate the secp256k1
        # signature itself — that's the consumer's responsibility (smart
        # contract on chain, off-chain verifier, capability-JWT scope
        # enforcer, etc.). We just enforce a structural shape so a
        # malformed rsv doesn't propagate downstream silently.
        eth_sig = None
        if req.kind == "eth_sign":
            eth_sig = body.get("eth_signature_rsv")
            if not isinstance(eth_sig, str) or not eth_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="eth_signature_rsv missing on eth_sign approval")
                raise BootloaderError(
                    "eth_sign approval missing eth_signature_rsv"
                )
            cleaned = eth_sig[2:] if eth_sig.startswith(("0x", "0X")) else eth_sig
            # personal_sign + typed_data return a 65-byte r||s||v signature
            # (130 hex chars). transaction returns the FULL signed raw-tx
            # bytes (0x02 || rlp([fields..., yParity, r, s])) which varies
            # in length depending on the access-list size and the byte
            # widths of the signed integers (typical simple ETH transfer
            # is ~108-114 bytes / ~216-228 hex chars; an EIP-1559 tx with
            # accessList entries can be much longer). For transaction we
            # accept any length above a sane minimum and let the consumer
            # (RPC node / eth_sendRawTransaction) do the heavy validation.
            kind = req.eth_message_kind or "personal_sign"
            if kind == "transaction":
                if len(cleaned) < 200:
                    self._notify_resolved(req, ok=False, signature_b64u=None,
                                          eth_signature_rsv=None,
                                          btc_signature_base64=None,
                                          reason="eth_signature_rsv too short for transaction")
                    raise BootloaderError(
                        f"eth_signature_rsv for transaction must be at least 200 hex chars (signed-tx is too short to be valid), got {len(cleaned)}"
                    )
            else:
                if len(cleaned) != 130:
                    self._notify_resolved(req, ok=False, signature_b64u=None,
                                          eth_signature_rsv=None,
                                          btc_signature_base64=None,
                                          reason="eth_signature_rsv wrong length")
                    raise BootloaderError(
                        f"eth_signature_rsv for {kind} must be 130 hex chars after optional 0x prefix, got {len(cleaned)}"
                    )
            try:
                bytes.fromhex(cleaned)
            except ValueError as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="eth_signature_rsv not hex")
                raise BootloaderError(
                    f"eth_signature_rsv must be hex, got {exc}"
                ) from exc
        # Same shape for btc_sign: structure-check only, opaque forward.
        # BIP-137 compact signatures are 65 raw bytes base64-encoded,
        # which is 88 chars (with padding) or 87 chars (without).
        # Some encoders strip trailing `=` padding; accept both.
        btc_sig = None
        if req.kind == "btc_sign":
            btc_sig = body.get("btc_signature_base64")
            if not isinstance(btc_sig, str) or not btc_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 missing on btc_sign approval")
                raise BootloaderError(
                    "btc_sign approval missing btc_signature_base64"
                )
            try:
                decoded = base64.b64decode(btc_sig.strip(), validate=False)
            except Exception as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 not base64")
                raise BootloaderError(
                    f"btc_signature_base64 must be valid base64, got {exc}"
                ) from exc
            if len(decoded) != 65:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 wrong decoded length")
                raise BootloaderError(
                    f"btc_signature_base64 must decode to 65 bytes, got {len(decoded)}"
                )
            header = decoded[0]
            if header < 27 or header > 42:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 header byte out of range")
                raise BootloaderError(
                    f"BIP-137 header byte must be in 27..42, got {header}"
                )
        # Same shape for ed_sign: structure-check only, opaque forward.
        # Raw ed25519 signatures are exactly 64 bytes (R||S). The
        # response also carries ed_pubkey_hex (32-byte ed25519 public
        # key, 64 hex chars) because XRP addresses are HASH160s and
        # can't recover their pubkey — for protocol uniformity all
        # three ed25519 chains carry the pubkey explicitly. The
        # bootloader does NOT verify the ed25519 signature itself —
        # that's the consumer's responsibility (chain RPC node /
        # off-chain attestation verifier / capability-scope enforcer).
        ed_sig: str | None = None
        ed_pub: str | None = None
        if req.kind == "ed_sign":
            ed_sig = body.get("ed_signature_base64")
            if not isinstance(ed_sig, str) or not ed_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 missing on ed_sign approval")
                raise BootloaderError(
                    "ed_sign approval missing ed_signature_base64"
                )
            try:
                ed_decoded = base64.b64decode(ed_sig.strip(), validate=False)
            except Exception as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 not base64")
                raise BootloaderError(
                    f"ed_signature_base64 must be valid base64, got {exc}"
                ) from exc
            if len(ed_decoded) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 wrong decoded length")
                raise BootloaderError(
                    f"ed_signature_base64 must decode to 64 bytes, got {len(ed_decoded)}"
                )
            ed_pub = body.get("ed_pubkey_hex")
            if not isinstance(ed_pub, str) or not ed_pub:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex missing on ed_sign approval")
                raise BootloaderError(
                    "ed_sign approval missing ed_pubkey_hex"
                )
            ed_pub_clean = ed_pub.strip()
            ed_pub_clean = ed_pub_clean[2:] if ed_pub_clean.startswith(("0x", "0X")) else ed_pub_clean
            if len(ed_pub_clean) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex wrong length")
                raise BootloaderError(
                    f"ed_pubkey_hex must be 64 hex chars (32-byte ed25519 pubkey) "
                    f"after optional 0x prefix, got {len(ed_pub_clean)}"
                )
            try:
                bytes.fromhex(ed_pub_clean)
            except ValueError as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex not hex")
                raise BootloaderError(
                    f"ed_pubkey_hex must be hex, got {exc}"
                ) from exc
            # Normalize ed_pub to the un-prefixed form for downstream
            # forwarding so consumers don't have to re-strip.
            ed_pub = ed_pub_clean
        self._notify_resolved(req, ok=True, signature_b64u=sig,
                              eth_signature_rsv=eth_sig,
                              btc_signature_base64=btc_sig,
                              ed_signature_base64=ed_sig,
                              ed_pubkey_hex=ed_pub, reason=None)
        self._send_json(HTTPStatus.OK, {"resolved": True})

    def _notify_resolved(
        self,
        req: PendingRequest,
        *,
        ok: bool,
        signature_b64u: str | None,
        reason: str | None,
        eth_signature_rsv: str | None = None,
        btc_signature_base64: str | None = None,
        ed_signature_base64: str | None = None,
        ed_pubkey_hex: str | None = None,
    ) -> None:
        """Surface a request resolution to the waiting launcher.

        Production wires this through an in-process map of
        request_id -> threading.Event / Future. For v0.4.0 this is
        intentionally a no-op stub -- the integration hook lives on
        the BootloaderConfig and tests inject their own callable.

        ``eth_signature_rsv`` is populated only when ``req.kind ==
        "eth_sign"`` and the operator approved; ``btc_signature_base64``
        only when ``req.kind == "btc_sign"`` and approved;
        ``ed_signature_base64`` + ``ed_pubkey_hex`` only when ``req.kind
        == "ed_sign"`` and approved. The launcher forwards all of these
        to the consumer (smart contract / off-chain verifier / wallet
        performing on-chain verification) without further validation.
        ``signature_b64u`` is the Ed25519 paired-phone identity proof
        and is populated for every approval regardless of kind.
        """
        notify_fn = getattr(self.config, "notify_resolved_fn", None)
        if notify_fn is not None:
            # Be tolerant of older notify_fn signatures that don't
            # accept the new kwargs. Try the full signature first; if
            # the callable doesn't accept ed_*, retry without them;
            # if it doesn't accept btc_signature_base64, retry without
            # it (eth-only signatures from the wave-2 batch); if it
            # doesn't accept eth_signature_rsv either, retry with only
            # the v0.4.0 base 4-arg shape.
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    ed_signature_base64=ed_signature_base64,
                    ed_pubkey_hex=ed_pubkey_hex,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            notify_fn(req=req, ok=ok, signature_b64u=signature_b64u,
                      reason=reason)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BootloaderError(f"invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise BootloaderError("body must be a JSON object")
        return data

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Override default stderr logging to use Recto's logging
        # convention. The bootloader runs as a service; default
        # http.server logging would flood AppStdout.
        # For v0.4.0 we silently drop access logs; v0.4.1+ adds a
        # configurable access log path.
        return


def create_server(
    *,
    bind_host: str,
    bind_port: int,
    state: StateStore,
    bootloader_id: str | None = None,
    challenges: ChallengeStore | None = None,
    notify_resolved_fn: Any = None,
    ssl_context: Any = None,
) -> ThreadingHTTPServer:
    """Construct (but do not start) a bootloader HTTPServer.

    Caller is responsible for `server.serve_forever()` and shutdown.
    The handler class is mutated with the runtime config; if you need
    multiple bootloaders in the same process (rare), copy
    BootloaderHandler and pass that copy to a fresh ThreadingHTTPServer.

    `ssl_context` is an `ssl.SSLContext` already loaded with the cert
    chain. None means HTTP (NOT recommended; useful only for tests).
    """
    server = ThreadingHTTPServer((bind_host, bind_port), BootloaderHandler)
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    BootloaderHandler.config = BootloaderConfig()
    BootloaderHandler.config.bootloader_id = (
        bootloader_id if bootloader_id is not None else str(uuid.uuid4())
    )
    BootloaderHandler.config.state = state
    BootloaderHandler.config.challenges = (
        challenges if challenges is not None else ChallengeStore()
    )
    if notify_resolved_fn is not None:
        BootloaderHandler.config.notify_resolved_fn = notify_resolved_fn  # type: ignore[attr-defined]
    return server
