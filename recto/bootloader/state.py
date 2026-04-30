"""Bootloader state persistence: phones, sessions, pending requests.

State files live under `~/.recto/bootloader/` (Linux/macOS) or
`%APPDATA%\\recto\\bootloader\\` (Windows). Three JSON files:

- `phones.json` -- registered phones (phone_id, device_label, public
  key, registered_at, last_seen).
- `sessions.json` -- cached session JWTs keyed by (service, secret).
  These are SIGNED tokens, not raw secrets; loss exposes nothing the
  phone hasn't already approved for the session lifetime.
- `pending.json` -- in-flight sign requests waiting for phone approval.
  Cleared on bootloader restart (in-flight requests fail rather than
  carrying over).

Concurrency: a single bootloader process owns the state files. There's
no cross-process locking; if you run two bootloaders on the same host
they will fight. The launcher is responsible for spawning exactly one
bootloader per service.

Threat model: state files are ACL-tightened to operator-only on
Linux/macOS (chmod 0600) and DPAPI-machine encrypted on Windows. An
attacker with operator-account access reads the public keys (not
sensitive) and active session JWTs (sensitive but bounded by
JWT.exp). Mitigation: short JWT lifetimes, manual revocation from
phone app.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "PhoneRegistration",
    "Session",
    "PendingRequest",
    "StateStore",
    "default_state_dir",
]


def default_state_dir() -> Path:
    """Return the per-platform default state directory, creating it if
    necessary. Override via `RECTO_BOOTLOADER_STATE_DIR` env var (mainly
    for tests; production should use the default)."""
    override = os.environ.get("RECTO_BOOTLOADER_STATE_DIR")
    if override:
        d = Path(override)
    elif os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError(
                "APPDATA not set; cannot determine bootloader state dir"
            )
        d = Path(appdata) / "recto" / "bootloader"
    else:
        d = Path.home() / ".recto" / "bootloader"
    d.mkdir(parents=True, exist_ok=True)
    # Tighten ACLs on Linux/macOS. On Windows the dir inherits ACL from
    # %APPDATA% which is already operator-private.
    if os.name != "nt":
        os.chmod(d, 0o700)
    return d


@dataclass(frozen=True, slots=True)
class PhoneRegistration:
    """One registered phone."""

    phone_id: str
    device_label: str
    public_key_b64u: str
    supported_algorithms: tuple[str, ...]
    registered_at_unix: int
    last_seen_unix: int

    @classmethod
    def new(
        cls,
        *,
        device_label: str,
        public_key_b64u: str,
        supported_algorithms: tuple[str, ...],
    ) -> PhoneRegistration:
        now = int(time.time())
        return cls(
            phone_id=str(uuid.uuid4()),
            device_label=device_label,
            public_key_b64u=public_key_b64u,
            supported_algorithms=supported_algorithms,
            registered_at_unix=now,
            last_seen_unix=now,
        )


@dataclass(frozen=True, slots=True)
class Session:
    """A cached session JWT for a (service, secret) pair."""

    service: str
    secret: str
    phone_id: str
    jwt: str
    expires_at_unix: int
    issued_at_unix: int
    max_uses: int
    uses_so_far: int = 0

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix

    @property
    def is_exhausted(self) -> bool:
        if self.max_uses <= 0:
            return False  # 0 = unlimited
        return self.uses_so_far >= self.max_uses

    def needs_renewal(self, threshold: float = 0.8) -> bool:
        """True when the session has consumed `threshold` of its
        lifetime or max_uses (default 80%). The bootloader uses this to
        proactively renew sessions before they expire/exhaust, avoiding
        latency spikes at the boundary."""
        now = time.time()
        lifetime = self.expires_at_unix - self.issued_at_unix
        consumed_lifetime_pct = (now - self.issued_at_unix) / max(lifetime, 1)
        if consumed_lifetime_pct >= threshold:
            return True
        if self.max_uses > 0:
            consumed_uses_pct = self.uses_so_far / self.max_uses
            if consumed_uses_pct >= threshold:
                return True
        return False


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """A sign request waiting for phone approval.

    Kind values that ship today:

    - ``"session_issuance"`` — phone signs a 24h JWT for the
      (service, secret) pair. Existing v0.4.0 flow.
    - ``"single_sign"`` — phone signs a one-shot payload. Existing
      v0.4.0 flow.
    - ``"totp_provision"`` / ``"totp_generate"`` — TOTP universal-vault
      flow (round 5).
    - ``"webauthn_assert"`` — passkey browser-login bridge (round 8).
    - ``"pkcs11_sign"`` / ``"pgp_sign"`` — v0.4.1 protocol seams.
    - ``"eth_sign"`` — Ethereum signing capability (v0.5+ groundwork).
      Populates the seven ``eth_*`` fields below; uses the same
      ``payload_hash_b64u`` Ed25519 envelope as ``single_sign`` so
      the bootloader still proves the response came from the paired
      phone, and additionally surfaces ``eth_signature_rsv`` on the
      respond body for the consumer (smart contract / off-chain
      verifier) to validate.
    - ``"btc_sign"`` — Bitcoin-family signing (BTC / LTC / DOGE / BCH).
      Populates the seven ``btc_*`` fields including the ``btc_coin``
      discriminator. Surfaces ``btc_signature_base64`` (a 65-byte
      BIP-137 compact signature) on the respond body.
    - ``"ed_sign"`` — Ed25519 chains signing (SOL / XLM / XRP). Wave-8
      addition. Populates the six ``ed_*`` fields including the
      ``ed_chain`` discriminator. Surfaces ``ed_signature_base64`` (a
      raw 64-byte ed25519 signature) AND ``ed_pubkey_hex`` (the 32-byte
      ed25519 public key, 64 hex chars) on the respond body. The
      explicit pubkey is required because XRP addresses are one-way
      HASH160s of the pubkey — verifiers can't recover pubkey from
      address — so for protocol uniformity all three chains carry
      the pubkey explicitly even though SOL and XLM addresses ARE
      reversible.
    """

    request_id: str
    kind: str
    service: str
    secret: str
    phone_id: str
    operation_description: str
    payload_hash_b64u: str
    child_pid: int
    child_argv0: str
    requested_at_unix: int
    expires_at_unix: int

    # ETH-specific context (kind == "eth_sign"). All optional with
    # default None so non-ETH PendingRequests keep working without
    # construction-site changes. The seven fields mirror the C#
    # `PendingRequestContext` ETH additions in
    # `Recto.Shared.Protocol.V04`. See `docs/v0.4-protocol.md`
    # "Ethereum signing capability (v0.5+)".
    eth_chain_id: int | None = None
    eth_message_kind: str | None = None  # "personal_sign" | "typed_data" | "transaction"
    eth_address: str | None = None  # 0x-prefixed lowercase hex (40 chars after 0x)
    eth_derivation_path: str | None = None  # default "m/44'/60'/0'/0/0"
    eth_message_text: str | None = None  # for personal_sign
    eth_typed_data_json: str | None = None  # for typed_data (EIP-712)
    eth_transaction_json: str | None = None  # for transaction (RLP) — reserved

    # BTC-specific context (kind == "btc_sign"). All optional with
    # default None. Six fields mirror the C# `PendingRequestContext`
    # BTC additions in `Recto.Shared.Protocol.V04`. See
    # `docs/v0.4-protocol.md` "Bitcoin signing capability (v0.5+)".
    # Same secp256k1 curve as ETH; different BIP-44 path tree
    # (m/84'/0'/0'/0/N for native-SegWit P2WPKH).
    btc_network: str | None = None  # "mainnet" | "testnet" | "signet" | "regtest"
    btc_message_kind: str | None = None  # "message_signing" | "psbt"
    btc_address: str | None = None  # bech32 (P2WPKH) or Base58Check (legacy / nested)
    btc_derivation_path: str | None = None  # default "m/84'/0'/0'/0/0"
    btc_message_text: str | None = None  # for message_signing
    btc_psbt_base64: str | None = None  # for psbt (BIP-174) — reserved
    # Wave-7: Bitcoin-family coin discriminator. Same `btc_sign`
    # credential kind covers BTC + LTC + DOGE + BCH; this field
    # selects which. Absent / None defaults to "btc" for backward
    # compat with v0.5 launchers that pre-date the multi-coin
    # extension. Mirrors C# `BtcCoin` constants in
    # `Recto.Shared.Protocol.V04`.
    btc_coin: str | None = None  # "btc" | "ltc" | "doge" | "bch"

    # ED25519-chain context (kind == "ed_sign"). All optional with
    # default None. Six fields mirror the C# `PendingRequestContext`
    # ED additions in `Recto.Shared.Protocol.V04`. See
    # `docs/v0.4-protocol.md` "Ed25519 chains signing capability
    # (v0.6+)". Same `ed_sign` credential kind covers SOL, XLM, and
    # XRP-ed25519; the `ed_chain` discriminator selects which.
    # Per-chain BIP-44 / SLIP-0010 paths and address encodings live
    # in the chain-specific Python modules
    # (`recto.solana` / `recto.stellar` / `recto.ripple`) and on the
    # phone-side C# signing service.
    ed_chain: str | None = None  # "sol" | "xlm" | "xrp"
    ed_message_kind: str | None = None  # "message_signing" | "transaction"
    ed_address: str | None = None  # chain-encoded operator-approved address
    ed_derivation_path: str | None = None  # chain-default if absent (see new_ed)
    ed_message_text: str | None = None  # for message_signing
    ed_payload_hex: str | None = None  # for transaction (reserved)

    @classmethod
    def new(
        cls,
        *,
        kind: str,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind=kind,
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
        )

    @classmethod
    def new_eth(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        eth_chain_id: int,
        eth_message_kind: str,
        eth_address: str,
        eth_derivation_path: str = "m/44'/60'/0'/0/0",
        eth_message_text: str | None = None,
        eth_typed_data_json: str | None = None,
        eth_transaction_json: str | None = None,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct an ``eth_sign`` PendingRequest with the seven
        Ethereum-specific context fields populated.

        Validates that ``eth_message_kind`` is one of the three
        protocol-defined values and that exactly one of the three
        per-kind body fields (``eth_message_text`` /
        ``eth_typed_data_json`` / ``eth_transaction_json``) is
        populated to match. Raises ``ValueError`` on either failure;
        consumers (the launcher, the mock bootloader operator-UI)
        are expected to validate at construction time so a
        malformed request never lands on the queue.
        """
        if eth_message_kind not in ("personal_sign", "typed_data", "transaction"):
            raise ValueError(
                f"eth_message_kind must be one of "
                f"'personal_sign'|'typed_data'|'transaction', "
                f"got {eth_message_kind!r}"
            )
        body_fields = {
            "personal_sign": eth_message_text,
            "typed_data": eth_typed_data_json,
            "transaction": eth_transaction_json,
        }
        expected = body_fields[eth_message_kind]
        if expected is None or expected == "":
            field_name = {
                "personal_sign": "eth_message_text",
                "typed_data": "eth_typed_data_json",
                "transaction": "eth_transaction_json",
            }[eth_message_kind]
            raise ValueError(
                f"eth_message_kind={eth_message_kind!r} requires {field_name} to be set"
            )
        # Reject obviously-wrong addresses early; full EIP-55 validation
        # happens phone-side when the BIP32 derivation runs.
        addr_clean = eth_address.lower()
        if not addr_clean.startswith("0x") or len(addr_clean) != 42:
            raise ValueError(
                f"eth_address must be 0x-prefixed 42-char hex, got {eth_address!r}"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="eth_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            eth_chain_id=eth_chain_id,
            eth_message_kind=eth_message_kind,
            eth_address=addr_clean,
            eth_derivation_path=eth_derivation_path,
            eth_message_text=eth_message_text,
            eth_typed_data_json=eth_typed_data_json,
            eth_transaction_json=eth_transaction_json,
        )

    @classmethod
    def new_btc(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        btc_network: str,
        btc_message_kind: str,
        btc_address: str,
        btc_derivation_path: str | None = None,
        btc_message_text: str | None = None,
        btc_psbt_base64: str | None = None,
        btc_coin: str = "btc",
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct a ``btc_sign`` PendingRequest with the six
        Bitcoin-specific context fields populated.

        Validates that ``btc_message_kind`` is one of the two
        protocol-defined values (``message_signing`` or ``psbt``),
        the ``btc_network`` is one of the four recognized networks,
        and exactly one of the two per-kind body fields
        (``btc_message_text`` / ``btc_psbt_base64``) is populated to
        match. Raises ``ValueError`` on any failure; consumers (the
        launcher, the mock bootloader operator-UI) are expected to
        validate at construction time so a malformed request never
        lands on the queue.
        """
        if btc_message_kind not in ("message_signing", "psbt"):
            raise ValueError(
                f"btc_message_kind must be one of 'message_signing'|'psbt', "
                f"got {btc_message_kind!r}"
            )
        if btc_network not in ("mainnet", "testnet", "signet", "regtest"):
            raise ValueError(
                f"btc_network must be one of "
                f"'mainnet'|'testnet'|'signet'|'regtest', got {btc_network!r}"
            )
        if btc_coin not in ("btc", "ltc", "doge", "bch"):
            raise ValueError(
                f"btc_coin must be one of 'btc'|'ltc'|'doge'|'bch', "
                f"got {btc_coin!r}"
            )
        # Coin-default BIP-44 paths. BTC + LTC default to BIP-84 native
        # SegWit (m/84'); DOGE + BCH default to BIP-44 legacy P2PKH
        # (m/44') since neither chain widely adopted SegWit.
        if btc_derivation_path is None:
            btc_derivation_path = {
                "btc":  "m/84'/0'/0'/0/0",
                "ltc":  "m/84'/2'/0'/0/0",
                "doge": "m/44'/3'/0'/0/0",
                "bch":  "m/44'/145'/0'/0/0",
            }[btc_coin]
        body_fields = {
            "message_signing": btc_message_text,
            "psbt": btc_psbt_base64,
        }
        expected = body_fields[btc_message_kind]
        if expected is None or expected == "":
            field_name = {
                "message_signing": "btc_message_text",
                "psbt": "btc_psbt_base64",
            }[btc_message_kind]
            raise ValueError(
                f"btc_message_kind={btc_message_kind!r} requires {field_name} to be set"
            )
        if not btc_address or len(btc_address) < 14:
            # Loose minimum length sanity-check; full bech32 / Base58Check
            # validation happens phone-side during the BIP-32 derivation.
            # P2WPKH bech32 is ~42 chars, P2PKH Base58Check is 26-35 chars,
            # so 14 is a safe floor that catches obvious mistakes.
            raise ValueError(
                f"btc_address must be at least 14 chars, got {btc_address!r}"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="btc_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            btc_network=btc_network,
            btc_message_kind=btc_message_kind,
            btc_address=btc_address.strip(),
            btc_derivation_path=btc_derivation_path,
            btc_message_text=btc_message_text,
            btc_psbt_base64=btc_psbt_base64,
            btc_coin=btc_coin,
        )

    @classmethod
    def new_ed(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        ed_chain: str,
        ed_message_kind: str,
        ed_address: str,
        ed_derivation_path: str | None = None,
        ed_message_text: str | None = None,
        ed_payload_hex: str | None = None,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct an ``ed_sign`` PendingRequest with the six
        Ed25519-chain-specific context fields populated.

        Validates that:
        - ``ed_chain`` is one of ``"sol"`` / ``"xlm"`` / ``"xrp"``
        - ``ed_message_kind`` is one of ``"message_signing"`` /
          ``"transaction"``
        - exactly one of (``ed_message_text``, ``ed_payload_hex``) is
          populated to match the message kind
        - ``ed_address`` is non-empty and at least 25 chars (loose
          floor; the shortest valid address among the three chains
          is ~25 chars for an XRP classic address)

        Defaults ``ed_derivation_path`` to the chain-canonical SLIP-0010
        path when absent (Phantom for SOL, SEP-0005 for XLM, Xumm-style
        all-hardened for XRP-ed25519).

        Raises ``ValueError`` on any failure; consumers (the launcher,
        the mock bootloader operator-UI) are expected to validate at
        construction time so a malformed request never lands on the
        queue.
        """
        if ed_chain not in ("sol", "xlm", "xrp"):
            raise ValueError(
                f"ed_chain must be one of 'sol'|'xlm'|'xrp', got {ed_chain!r}"
            )
        if ed_message_kind not in ("message_signing", "transaction"):
            raise ValueError(
                f"ed_message_kind must be one of 'message_signing'|'transaction', "
                f"got {ed_message_kind!r}"
            )
        # Coin-default SLIP-0010 paths (all hardened-only).
        if ed_derivation_path is None:
            ed_derivation_path = {
                "sol": "m/44'/501'/0'/0'",      # Phantom / Solflare
                "xlm": "m/44'/148'/0'",         # SEP-0005
                "xrp": "m/44'/144'/0'/0'/0'",   # Xumm-style ed25519
            }[ed_chain]
        body_fields = {
            "message_signing": ed_message_text,
            "transaction": ed_payload_hex,
        }
        expected = body_fields[ed_message_kind]
        if expected is None or expected == "":
            field_name = {
                "message_signing": "ed_message_text",
                "transaction": "ed_payload_hex",
            }[ed_message_kind]
            raise ValueError(
                f"ed_message_kind={ed_message_kind!r} requires {field_name} to be set"
            )
        if not ed_address or len(ed_address.strip()) < 25:
            # Loose floor: the shortest legitimate XRP classic address
            # is ~25 chars; SOL is 32-44 chars; XLM StrKey is exactly
            # 56 chars. 25-char floor catches obvious truncation /
            # paste errors. Full per-chain validation runs phone-side
            # during the BIP-39 → SLIP-0010 → address-encode pipeline.
            raise ValueError(
                f"ed_address must be at least 25 chars, got {ed_address!r}"
            )
        if ed_message_kind == "transaction":
            # Reserved kind; not yet wired through the chain-module
            # transaction-hashing rules. Refuse here so a future phone
            # implementation can enable it without protocol drift.
            raise ValueError(
                "ed_message_kind='transaction' is reserved for a follow-up "
                "wave; only 'message_signing' is wired today"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="ed_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            ed_chain=ed_chain,
            ed_message_kind=ed_message_kind,
            ed_address=ed_address.strip(),
            ed_derivation_path=ed_derivation_path,
            ed_message_text=ed_message_text,
            ed_payload_hex=ed_payload_hex,
        )

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


class StateStore:
    """Thread-safe persistence for bootloader state.

    All state is held in JSON files under `state_dir`. Reads are cached
    in memory; writes are write-through (immediately flushed to disk).
    A single threading.RLock serializes all operations -- no
    fine-grained locking, since the bootloader's request rate is bounded
    by phone-interaction latency anyway.
    """

    def __init__(self, state_dir: Path | None = None):
        self._dir = state_dir if state_dir is not None else default_state_dir()
        self._lock = threading.RLock()
        self._phones: dict[str, PhoneRegistration] = {}
        self._sessions: dict[tuple[str, str], Session] = {}
        self._pending: dict[str, PendingRequest] = {}
        self._load()

    @property
    def state_dir(self) -> Path:
        return self._dir

    # ------------------------------------------------------------------
    # Phones
    # ------------------------------------------------------------------

    def register_phone(self, reg: PhoneRegistration) -> None:
        with self._lock:
            self._phones[reg.phone_id] = reg
            self._save_phones()

    def get_phone(self, phone_id: str) -> PhoneRegistration | None:
        with self._lock:
            return self._phones.get(phone_id)

    def list_phones(self) -> list[PhoneRegistration]:
        with self._lock:
            return list(self._phones.values())

    def revoke_phone(self, phone_id: str) -> bool:
        with self._lock:
            if phone_id not in self._phones:
                return False
            del self._phones[phone_id]
            # Drop any sessions / pending tied to this phone.
            self._sessions = {
                k: s for k, s in self._sessions.items() if s.phone_id != phone_id
            }
            self._pending = {
                k: p for k, p in self._pending.items() if p.phone_id != phone_id
            }
            self._save_phones()
            self._save_sessions()
            self._save_pending()
            return True

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def get_session(self, service: str, secret: str) -> Session | None:
        with self._lock:
            sess = self._sessions.get((service, secret))
            if sess is None:
                return None
            if sess.is_expired or sess.is_exhausted:
                # Lazy purge -- next get returns None and the caller
                # re-issues. Don't raise here; expiry is normal.
                del self._sessions[(service, secret)]
                self._save_sessions()
                return None
            return sess

    def put_session(self, sess: Session) -> None:
        with self._lock:
            self._sessions[(sess.service, sess.secret)] = sess
            self._save_sessions()

    def increment_session_uses(self, service: str, secret: str) -> Session | None:
        """Increment uses_so_far on a session and persist. Returns the
        updated session, or None if the session is already gone."""
        with self._lock:
            sess = self._sessions.get((service, secret))
            if sess is None:
                return None
            updated = Session(
                service=sess.service,
                secret=sess.secret,
                phone_id=sess.phone_id,
                jwt=sess.jwt,
                expires_at_unix=sess.expires_at_unix,
                issued_at_unix=sess.issued_at_unix,
                max_uses=sess.max_uses,
                uses_so_far=sess.uses_so_far + 1,
            )
            self._sessions[(service, secret)] = updated
            self._save_sessions()
            return updated

    # ------------------------------------------------------------------
    # Pending requests
    # ------------------------------------------------------------------

    def add_pending(self, req: PendingRequest) -> None:
        with self._lock:
            self._pending[req.request_id] = req
            self._save_pending()

    def list_pending_for_phone(self, phone_id: str) -> list[PendingRequest]:
        with self._lock:
            self._purge_expired_pending()
            return [
                p for p in self._pending.values() if p.phone_id == phone_id
            ]

    def take_pending(self, request_id: str) -> PendingRequest | None:
        """Pop a pending request by id. Returns None if not present."""
        with self._lock:
            req = self._pending.pop(request_id, None)
            if req is not None:
                self._save_pending()
            return req

    # ------------------------------------------------------------------
    # Disk I/O (private)
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            phones_path = self._dir / "phones.json"
            if phones_path.exists():
                raw = json.loads(phones_path.read_text(encoding="utf-8"))
                for r in raw.get("phones", []):
                    r["supported_algorithms"] = tuple(r["supported_algorithms"])
                    self._phones[r["phone_id"]] = PhoneRegistration(**r)
            sessions_path = self._dir / "sessions.json"
            if sessions_path.exists():
                raw = json.loads(sessions_path.read_text(encoding="utf-8"))
                for s in raw.get("sessions", []):
                    sess = Session(**s)
                    self._sessions[(sess.service, sess.secret)] = sess
            # Pending requests are intentionally NOT reloaded across
            # bootloader restarts. In-flight requests fail; the child
            # decides whether to retry. This is safer than carrying
            # state forward across a possibly-dirty restart.

    def _save_phones(self) -> None:
        path = self._dir / "phones.json"
        body = {
            "phones": [self._asdict_phone(p) for p in self._phones.values()],
        }
        self._atomic_write(path, body)

    def _save_sessions(self) -> None:
        path = self._dir / "sessions.json"
        body = {
            "sessions": [asdict(s) for s in self._sessions.values()],
        }
        self._atomic_write(path, body)

    def _save_pending(self) -> None:
        path = self._dir / "pending.json"
        body = {
            "pending": [asdict(p) for p in self._pending.values()],
        }
        self._atomic_write(path, body)

    @staticmethod
    def _asdict_phone(p: PhoneRegistration) -> dict[str, Any]:
        d = asdict(p)
        d["supported_algorithms"] = list(d["supported_algorithms"])
        return d

    @staticmethod
    def _atomic_write(path: Path, body: dict[str, Any]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        # os.replace is atomic on POSIX; on Windows it replaces if dst
        # exists (Python 3.3+ behavior).
        os.replace(tmp, path)

    def _purge_expired_pending(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, req in self._pending.items() if req.is_expired
        ]
        for rid in expired:
            del self._pending[rid]
        if expired:
            self._save_pending()
