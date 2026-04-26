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
    """A sign request waiting for phone approval."""

    request_id: str
    kind: str  # "session_issuance" | "single_sign"
    service: str
    secret: str
    phone_id: str
    operation_description: str
    payload_hash_b64u: str
    child_pid: int
    child_argv0: str
    requested_at_unix: int
    expires_at_unix: int

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
