"""NSSM (Non-Sucking Service Manager) wrapper used by the CLI.

NSSM is the Windows-service registrar Recto wraps in v0.1: NSSM owns
the OS-level service definition, Recto sits inside it as the
launcher/supervisor. The CLI's `recto status` and `recto migrate-from-nssm`
subcommands need to read and (in the migrate case) modify NSSM's
per-service config. This module is the thin shell-out layer.

Why shell out to nssm.exe instead of reading the registry directly:

NSSM's config IS stored in the registry under
`HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\Parameters`, so we
COULD use `winreg`. But NSSM owns the schema; if NSSM ever changes how
it stores fields (e.g. new field types, renamed keys), our registry
reads break. Shelling out to `nssm.exe get/set` keeps us downstream of
NSSM's own contract — whatever the current NSSM does is by definition
correct.

Design:

`NssmClient` is a thin wrapper. All subprocess calls flow through a
single `runner` callable so tests inject a stub (`FakeRunner` in
`tests/test_nssm.py`). Production uses `subprocess.run`.

Outputs from `nssm.exe get` are UTF-16-LE-decoded on Windows because
NSSM emits wide-string output by default. We `errors="replace"` rather
than raising on bad bytes — a malformed character in a service config
shouldn't crash a status check.

`get_all` reads the seven canonical NSSM fields the migrate path needs:
AppPath, AppParameters, AppDirectory, AppEnvironmentExtra, AppExit,
DisplayName, Description. AppParameters is "the args" (NSSM's name);
AppEnvironmentExtra is the "KEY=value\\nKEY2=value2"-style block of
extra env vars stored as a multi-string.

This module is Windows-only at runtime (the underlying nssm.exe is a
Windows binary), but importing on non-Windows is allowed so the rest
of the package can be unit-tested cross-platform.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "NSSM_FIELDS",
    "NssmClient",
    "NssmConfig",
    "NssmError",
    "NssmNotInstalledError",
    "NssmServiceNotFoundError",
    "NssmStatus",
    "default_runner",
    "split_environment_extra",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class NssmError(Exception):
    """Base class for NSSM-related failures from this module."""


class NssmNotInstalledError(NssmError):
    """nssm.exe was not found on PATH.

    Either NSSM isn't installed, or it lives somewhere not on PATH.
    Tell the operator to install NSSM (https://nssm.cc/) or pass the
    explicit path via the NssmClient(nssm_exe=...) constructor arg.
    """


class NssmServiceNotFoundError(NssmError):
    """The named service does not exist in NSSM's registry.

    Distinct from NSSM-itself-missing (NssmNotInstalledError) and
    NSSM-said-no (generic NssmError) so the CLI can produce a tailored
    "did you mean X?" message.
    """


# ---------------------------------------------------------------------------
# Status enum + config dataclass
# ---------------------------------------------------------------------------


class NssmStatus:
    """String constants for the values `nssm status` can return.

    Not a real enum so we can compare loosely against whatever NSSM
    actually emits (case-folding etc.) without having to add new enum
    members for every variant. The seven values below cover what
    `nssm status <name>` returns; anything else is preserved as the
    raw output string and the caller can decide how to interpret.
    """

    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_STOPPED = "SERVICE_STOPPED"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"


# Canonical NSSM fields the migrate path reads. Stored as a tuple so
# callers can iterate; not all fields are populated for every service.
NSSM_FIELDS: tuple[str, ...] = (
    "AppPath",
    "AppParameters",
    "AppDirectory",
    "AppEnvironmentExtra",
    "AppExit",
    "DisplayName",
    "Description",
)


@dataclass(frozen=True, slots=True)
class NssmConfig:
    """Snapshot of an NSSM service's config.

    Each field corresponds to a NSSM `get` call. Missing fields land
    as empty strings (NSSM returns empty string for unset string
    fields). `app_environment_extra` is the parsed KEY=value list.
    """

    service: str
    app_path: str = ""
    app_parameters: str = ""
    app_directory: str = ""
    app_environment_extra: tuple[str, ...] = ()
    app_exit: str = ""
    display_name: str = ""
    description: str = ""
    raw: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Subprocess runner indirection (so tests can inject a stub)
# ---------------------------------------------------------------------------


SubprocessRunner = Callable[..., subprocess.CompletedProcess[bytes]]
"""subprocess.run-shaped callable. Returning bytes (not str) so the
caller controls decoding — NSSM emits UTF-16-LE on Windows, which the
default subprocess.run text handling gets wrong."""


def default_runner(
    args: Sequence[str],
    *,
    capture_output: bool = True,
    timeout: float | None = 10.0,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    """Default subprocess.run wrapper. Always captures bytes, never text."""
    return subprocess.run(
        list(args),
        capture_output=capture_output,
        timeout=timeout,
        check=check,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# AppEnvironmentExtra parsing
# ---------------------------------------------------------------------------


def split_environment_extra(raw: str) -> list[tuple[str, str]]:
    """Parse NSSM's AppEnvironmentExtra value into [(KEY, value), ...].

    NSSM stores the field as a multi-string in the registry; `nssm get`
    renders it as one entry per line. Each line is `KEY=value`. Blank
    lines are skipped. A line with no `=` is skipped with no warning
    (NSSM doesn't emit those, but we're defensive).

    Why we use partition instead of split('=', 1): partition gives us
    a clean three-tuple even when the value itself contains '='
    (common for connection strings, base64 blobs, etc.).
    """
    out: list[tuple[str, str]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not key:
            continue
        out.append((key, value))
    return out


# ---------------------------------------------------------------------------
# NssmClient
# ---------------------------------------------------------------------------


class NssmClient:
    """Thin wrapper around the nssm.exe CLI.

    Args:
        nssm_exe: Path to nssm.exe. None (default) means look it up via
            shutil.which; raise NssmNotInstalledError if not found.
            Tests pass an explicit non-None value (matched against the
            stub runner's recorded calls).
        runner: subprocess.run-shaped callable. Tests inject a stub.
    """

    def __init__(
        self,
        *,
        nssm_exe: str | None = None,
        runner: SubprocessRunner = default_runner,
    ) -> None:
        self._explicit_path = nssm_exe
        self._runner = runner

    @property
    def nssm_exe(self) -> str:
        """Resolved path to nssm.exe. Looked up lazily so a test that
        never actually invokes nssm doesn't need it on PATH."""
        if self._explicit_path is not None:
            return self._explicit_path
        found = shutil.which("nssm") or shutil.which("nssm.exe")
        if found is None:
            raise NssmNotInstalledError(
                "nssm.exe not found on PATH. Install NSSM "
                "(https://nssm.cc/) or pass nssm_exe=... explicitly."
            )
        return found

    # ------------------------------------------------------------------
    # Public commands
    # ------------------------------------------------------------------

    def status(self, service: str) -> str:
        """Return the raw status string from `nssm status <service>`.

        Typical values match NssmStatus.* constants; unknown values are
        returned verbatim so the caller can decide what to do.
        """
        result = self._run("status", service)
        return _decode_nssm(result.stdout).strip()

    def get(self, service: str, field_name: str) -> str:
        """Read a single NSSM field. Returns the field value as a
        string, with trailing whitespace stripped.

        Raises NssmServiceNotFoundError if the service doesn't exist.
        """
        result = self._run("get", service, field_name)
        if result.returncode != 0:
            stderr = _decode_nssm(result.stderr).lower()
            if "service" in stderr and ("not" in stderr or "exist" in stderr):
                raise NssmServiceNotFoundError(
                    f"NSSM service {service!r} not found"
                )
            raise NssmError(
                f"nssm get {service} {field_name} failed "
                f"(rc={result.returncode}): {_decode_nssm(result.stderr).strip()}"
            )
        return _decode_nssm(result.stdout).rstrip()

    def get_all(self, service: str) -> NssmConfig:
        """Read every field in NSSM_FIELDS into one NssmConfig.

        Used by `recto migrate-from-nssm` to snapshot the existing
        config before retargeting it. Each field's read is independent;
        missing fields land as empty strings. AppEnvironmentExtra is
        parsed into the tuple of (KEY, value) pairs that the migrate
        command iterates.
        """
        raw: dict[str, str] = {}
        for fname in NSSM_FIELDS:
            try:
                raw[fname] = self.get(service, fname)
            except NssmServiceNotFoundError:
                # Re-raise on the first miss; all subsequent fields
                # would fail the same way.
                raise
        env_lines = raw.get("AppEnvironmentExtra", "")
        env_kv = tuple(f"{k}={v}" for k, v in split_environment_extra(env_lines))
        return NssmConfig(
            service=service,
            app_path=raw.get("AppPath", ""),
            app_parameters=raw.get("AppParameters", ""),
            app_directory=raw.get("AppDirectory", ""),
            app_environment_extra=env_kv,
            app_exit=raw.get("AppExit", ""),
            display_name=raw.get("DisplayName", ""),
            description=raw.get("Description", ""),
            raw=raw,
        )

    def set(self, service: str, field_name: str, value: str) -> None:
        """Write a single NSSM field.

        Idempotent — NSSM's `set` is upsert. The migrate command uses
        this to retarget AppPath and AppParameters after generating
        the YAML.
        """
        result = self._run("set", service, field_name, value)
        if result.returncode != 0:
            raise NssmError(
                f"nssm set {service} {field_name} ...: rc={result.returncode}: "
                f"{_decode_nssm(result.stderr).strip()}"
            )

    def reset(self, service: str, field_name: str) -> None:
        """Clear a single NSSM field.

        The migrate command calls this on AppEnvironmentExtra after
        importing the entries to credman, so the secrets stop sitting
        in the registry as plaintext.
        """
        result = self._run("reset", service, field_name)
        if result.returncode != 0:
            raise NssmError(
                f"nssm reset {service} {field_name}: rc={result.returncode}: "
                f"{_decode_nssm(result.stderr).strip()}"
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        cmd: list[str] = [self.nssm_exe, *args]
        return self._runner(cmd)


def _decode_nssm(buf: bytes | str) -> str:
    """NSSM emits UTF-16-LE on Windows; some patched builds use UTF-8.

    Try UTF-16-LE first (the official build's default), fall back to
    UTF-8, and finally cp1252 with errors='replace' so we never raise
    over an encoding hiccup. On non-Windows (tests) we also accept
    plain str input.
    """
    if isinstance(buf, str):
        return buf
    if not buf:
        return ""
    # UTF-16-LE: NSSM strips a BOM but emits paired bytes. If the input
    # length is odd, it's not UTF-16; skip straight to UTF-8.
    if len(buf) % 2 == 0:
        try:
            return buf.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    try:
        return buf.decode("utf-8")
    except UnicodeDecodeError:
        return buf.decode("cp1252", errors="replace") if sys.platform == "win32" else buf.decode("latin-1", errors="replace")
