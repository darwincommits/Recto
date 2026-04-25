"""Launcher: read service.yaml, fetch secrets, spawn the child, supervise.

The launcher is the entry point that NSSM (or systemd / launchd in v0.3+)
points at: `python -m recto launch service.yaml`. It reads the validated
ServiceConfig, resolves each declared SecretSource via the registry in
`recto.secrets`, fetches secrets, composes the child env, and hands off
to subprocess.Popen.

Design notes
------------

This v0.1 cut is synchronous from the launcher's perspective: launch()
spawns the child and polls its exit-vs-healthz-trip status until either
fires, then returns the child's exit code. The supervisor pieces — restart
policy, healthz probe loop, webhook event dispatch — live in their own
modules and either wire in here (recto.healthz, recto.restart, both
shipped) or remain TODO(v0.1) hook points (recto.comms). Splitting them
up keeps each module unit-testable in isolation: the launcher's contract
is "given a config and a way to spawn, run the child correctly"; the
restart module's contract is "given an exit code and a policy, decide
whether to relaunch"; the probe's contract is "tell the launcher when
the child has gone unresponsive"; the comms module's eventual contract
is "post webhook events when lifecycle things happen."

Secret material handling
------------------------

v0.1 only handles `DirectSecret` (string-valued) materials. When a
SecretSource returns a `SigningCapability` — produced by v0.4 hardware-
enclave backends — the launcher refuses to start with a clear error
pointing at ROADMAP.md v0.4. We never silently downgrade or stringify
a SigningCapability.

Secrets win on env-var collision with `spec.env`; the contract is
"explicit env entries are static defaults, secrets are the authoritative
runtime value." The base process env (os.environ) is the lowest layer.

If a secret has `required: false` and the source returns an empty
`DirectSecret`, the launcher injects the empty string verbatim. We do
NOT skip injection — that would leave the env var inheriting from the
parent process, which is footgun-shaped. Users who want "absent if
missing" should not declare the secret at all.

Why we don't pass shell=True
----------------------------

The YAML's `exec` + `args` are the canonical command shape; piping them
through a shell would re-introduce quoting bugs that this schema design
specifically avoids. NSSM-style behavior (no shell, exact argv) is the
contract.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from recto.config import HealthzSpec, ServiceConfig, ServiceSpec
from recto.healthz import HealthzProbe
from recto.restart import MaxAttemptsReachedError, next_delay, should_restart
from recto.secrets import (
    DirectSecret,
    SecretMaterial,
    SecretSource,
    SigningCapability,
    resolve_source,
)

__all__ = [
    "LauncherError",
    "SecretInjectionError",
    "build_child_env",
    "launch",
    "resolve_sources",
    "run",
]


PopenFactory = Callable[..., "subprocess.Popen[Any]"]
"""Subprocess.Popen-shaped callable. Tests inject a stub; production uses
subprocess.Popen directly. The stub is expected to accept (cmd, env=...,
cwd=...) and return an object with .poll() and .wait() and .terminate()
and .kill() methods (subprocess.Popen's interface)."""


ProbeFactory = Callable[[HealthzSpec], HealthzProbe]
"""HealthzSpec -> HealthzProbe. Tests inject a stub that records start()/
stop() and lets the test trip restart_required deterministically. Production
uses HealthzProbe directly."""


class LauncherError(Exception):
    """Top-level launcher failure. Subclasses pin down the cause."""


class SecretInjectionError(LauncherError):
    """A secret could not be resolved or injected into the child env.

    Distinct from `SecretNotFoundError` (the source's "I don't have it")
    and `UnknownSecretSourceError` (no backend registered): this covers
    cases where the source returned an unexpected material type, or
    declared a missing source binding at the launcher level.
    """


def resolve_sources(config: ServiceConfig) -> dict[str, SecretSource]:
    """Build {source_name: SecretSource} for every source referenced in spec.secrets.

    Each unique `source:` value in the spec is resolved once via the
    `recto.secrets` registry. The resulting instances are reused across
    all secrets that share a source, so a CredManSource opens its handle
    once per launch, not once per fetched secret.
    """
    needed = {s.source for s in config.spec.secrets}
    return {name: resolve_source(name, config.metadata.name) for name in needed}


def build_child_env(
    spec: ServiceSpec,
    sources: Mapping[str, SecretSource],
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Compose the env-var dict that the child will inherit.

    Layering (later wins):
    1. `base_env` — defaults to a copy of os.environ. Tests pass an
       explicit dict to keep behavior deterministic.
    2. `spec.env` — static env entries from the YAML.
    3. Injected secrets — fetched from the corresponding SecretSource
       and written to `secret.target_env`.

    Raises:
        SecretInjectionError: secret declares a source that's missing
            from `sources`, or the source returned an unsupported
            material type.
        SecretNotFoundError: a `required: true` secret is missing in
            its backend. Re-raised from SecretSource.fetch.
        NotImplementedError: a SecretSource returned SigningCapability;
            v0.1 launcher does not yet support that path. The error
            message points at ROADMAP.md v0.4.
    """
    env: dict[str, str] = dict(base_env if base_env is not None else os.environ)
    env.update(spec.env)
    for s in spec.secrets:
        source = sources.get(s.source)
        if source is None:
            raise SecretInjectionError(
                f"secret {s.name!r} declares source {s.source!r} but no "
                f"matching SecretSource was provided to the launcher; this "
                f"is a launcher-internal bug — resolve_sources should have "
                f"populated it"
            )
        # SecretSpec.required is the canonical truth; override any same-named
        # entry in s.config. Backends look at config['required'] to decide
        # whether to raise vs return DirectSecret('').
        fetch_config = dict(s.config)
        fetch_config["required"] = s.required
        material: SecretMaterial = source.fetch(s.name, fetch_config)

        if isinstance(material, SigningCapability):
            raise NotImplementedError(
                f"secret {s.name!r}: source {s.source!r} returned a "
                f"SigningCapability (algorithm={material.algorithm!r}). The "
                f"v0.1 launcher only handles DirectSecret. SigningCapability "
                f"support — exposing a local-socket sign-helper to the child "
                f"process — is the v0.4 hardware-enclave milestone. See "
                f"ROADMAP.md."
            )
        if not isinstance(material, DirectSecret):
            raise SecretInjectionError(
                f"secret {s.name!r}: source {s.source!r} returned unsupported "
                f"material type {type(material).__name__}; expected "
                f"DirectSecret"
            )
        env[s.target_env] = material.value
    return env


def launch(
    config: ServiceConfig,
    *,
    sources: Mapping[str, SecretSource] | None = None,
    popen: PopenFactory = subprocess.Popen,
    base_env: Mapping[str, str] | None = None,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
) -> int:
    """Run the supervised child. Returns the child's exit code.

    Args:
        config: Validated ServiceConfig (from `recto.config.load_config`).
        sources: Optional pre-built {source_name: SecretSource} mapping.
            If None, the launcher resolves sources from the registry via
            `resolve_sources(config)`. Tests pass an explicit dict to
            inject stubs.
        popen: subprocess.Popen-shaped factory. Tests inject a stub.
        base_env: Base env-var mapping that the child env layers on top
            of. Defaults to os.environ. Tests pass an explicit dict.

    Returns:
        The child process's exit code, as returned by .wait().

    Raises:
        SecretInjectionError, SecretNotFoundError, UnknownSecretSourceError,
        NotImplementedError: see build_child_env / resolve_sources.

    Notes:
        Lifecycle-bracketed sources (`supports_lifecycle() is True`) get
        init() called once before any fetch and teardown() called in a
        finally block on exit. Failures during teardown are logged but
        do not mask the child's exit code or any prior exception.
    """
    if sources is None:
        sources = resolve_sources(config)

    with _bracket_lifecycle(config, sources):
        return _spawn_and_wait(
            config,
            sources,
            popen,
            base_env,
            probe_factory=probe_factory,
            poll_interval_seconds=poll_interval_seconds,
            terminate_grace_seconds=terminate_grace_seconds,
        )


# ---------------------------------------------------------------------------
# Internals shared by launch() and run()
# ---------------------------------------------------------------------------


@contextmanager
def _bracket_lifecycle(
    config: ServiceConfig, sources: Mapping[str, SecretSource]
) -> Iterator[None]:
    """init() lifecycle-stateful sources before the body, teardown() after.

    Used by both launch() (single spawn) and run() (restart loop). Failures
    in teardown are logged via _emit_event but do not propagate — best-
    effort cleanup, never mask the body's exit code or exception.
    """
    initialized: list[SecretSource] = []
    try:
        for src in sources.values():
            if src.supports_lifecycle():
                src.init()
                initialized.append(src)
        yield
    finally:
        for src in initialized:
            try:
                src.teardown()
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                _emit_event(
                    config,
                    "source.teardown_failed",
                    {"source": src.name, "error": type(exc).__name__},
                )


def _spawn_and_wait(
    config: ServiceConfig,
    sources: Mapping[str, SecretSource],
    popen: PopenFactory,
    base_env: Mapping[str, str] | None,
    *,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
) -> int:
    """Build child env, spawn, wait for exit OR healthz unhealthy signal.

    Lifecycle bracketing of SecretSource is the caller's job (launch /
    run handle it). This function owns the per-spawn HealthzProbe
    lifetime: builds one if `config.spec.healthz.enabled`, starts it
    after Popen, stops it before returning regardless of how the child
    exits.

    If the probe trips `restart_required` while the child is still
    running, the launcher terminates the child (with a
    `terminate_grace_seconds` graceful window before SIGKILL on POSIX /
    forcible kill on Windows) and returns the resulting exit code. The
    restart-policy machinery in run() then decides whether to relaunch.

    Args:
        probe_factory: HealthzSpec -> HealthzProbe. Tests inject a stub
            that records start()/stop() and lets the test trip
            restart_required deterministically.
        poll_interval_seconds: how often to check proc.poll() and
            probe.restart_required. 0.5s is fine for production; tests
            pass 0 to spin as fast as possible.
        terminate_grace_seconds: SIGTERM-then-wait window before forcing
            SIGKILL. Production default 5.0s; tests use small values.

    TODO(v0.1): webhook dispatch on lifecycle events — recto.comms
    subscribes to events emitted via _emit_event() and posts to
    config.spec.comms[].url.
    """
    env = build_child_env(config.spec, sources, base_env=base_env)
    cmd: list[str] = [config.spec.exec, *config.spec.args]
    cwd: str | None = config.spec.working_dir or None

    _emit_event(
        config,
        "child.spawn",
        {
            "cmd": cmd,
            "cwd": cwd,
            "secrets_injected": [s.target_env for s in config.spec.secrets],
        },
    )

    proc = popen(cmd, env=env, cwd=cwd)

    probe: HealthzProbe | None = None
    if config.spec.healthz.enabled:
        probe = probe_factory(config.spec.healthz)
        probe.start()

    healthz_signaled = False
    try:
        rc = _wait_for_exit_or_unhealthy(
            proc,
            probe,
            poll_interval_seconds=poll_interval_seconds,
            terminate_grace_seconds=terminate_grace_seconds,
        )
        if probe is not None and probe.restart_required.is_set():
            healthz_signaled = True
    finally:
        if probe is not None:
            probe.stop()

    _emit_event(
        config,
        "child.exit",
        {"returncode": rc, "healthz_signaled": healthz_signaled},
    )
    return rc


def _wait_for_exit_or_unhealthy(
    proc: subprocess.Popen[Any],
    probe: HealthzProbe | None,
    *,
    poll_interval_seconds: float,
    terminate_grace_seconds: float,
) -> int:
    """Block until the child exits or the probe signals unhealthy.

    Returns the child's exit code in either case. If the probe trips
    first, the child is terminated; we then wait for it to actually
    exit and return its (typically non-zero) returncode.
    """
    while True:
        rc = proc.poll()
        if rc is not None:
            return int(rc)
        if probe is not None and probe.restart_required.is_set():
            # Healthz says restart. SIGTERM the child, give it a grace
            # window, then SIGKILL if it didn't shut down cleanly.
            proc.terminate()
            try:
                rc = proc.wait(timeout=terminate_grace_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
            return int(rc)
        time.sleep(poll_interval_seconds)


# ---------------------------------------------------------------------------
# Restart loop — production entry point
# ---------------------------------------------------------------------------


def run(
    config: ServiceConfig,
    *,
    sources: Mapping[str, SecretSource] | None = None,
    popen: PopenFactory = subprocess.Popen,
    base_env: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
) -> int:
    """Run the supervised child with the configured restart policy.

    This is the entry point NSSM (and the v0.3+ systemd / launchd unit
    files) point at via `python -m recto launch service.yaml`. After
    each child exit, consults `config.spec.restart` to decide whether
    to relaunch and how long to wait.

    Compared to `launch()`:
    - `launch()` is a one-shot — single spawn, single wait, single
      lifecycle bracket around init/teardown. Useful for tests and
      `recto launch --once` debug invocations.
    - `run()` resolves sources and brackets init/teardown ONCE around
      the whole loop, then re-spawns the child as policy dictates.
      Long-lived backends (Vault session, hardware-enclave handle)
      stay open across restarts.

    Args:
        config: Validated ServiceConfig.
        sources, popen, base_env: see launch().
        sleep: time.sleep-shaped callable. Tests inject a fake to avoid
            real waits.

    Returns:
        The exit code of the LAST child invocation (whether the policy
        decided "no restart" or `max_attempts_reached` fired).
    """
    if sources is None:
        sources = resolve_sources(config)

    with _bracket_lifecycle(config, sources):
        attempt = 0
        last_rc = 0
        while True:
            last_rc = _spawn_and_wait(
                config,
                sources,
                popen,
                base_env,
                probe_factory=probe_factory,
                poll_interval_seconds=poll_interval_seconds,
                terminate_grace_seconds=terminate_grace_seconds,
            )
            if not should_restart(last_rc, config.spec.restart):
                _emit_event(
                    config,
                    "run.final_exit",
                    {"returncode": last_rc, "restart_attempts": attempt},
                )
                return last_rc
            attempt += 1
            try:
                delay = next_delay(attempt, config.spec.restart)
            except MaxAttemptsReachedError:
                _emit_event(
                    config,
                    "max_attempts_reached",
                    {
                        "max_attempts": config.spec.restart.max_attempts,
                        "last_returncode": last_rc,
                    },
                )
                return last_rc
            _emit_event(
                config,
                "restart.attempt",
                {
                    "attempt": attempt,
                    "delay_seconds": delay,
                    "previous_returncode": last_rc,
                    "backoff": config.spec.restart.backoff,
                },
            )
            sleep(delay)


# ---------------------------------------------------------------------------
# Event logging — placeholder until recto.comms ships
# ---------------------------------------------------------------------------


def _emit_event(config: ServiceConfig, kind: str, ctx: dict[str, Any]) -> None:
    """Structured stdout log line. JSON for grep-ability under NSSM's
    AppStdout / AppStderr capture.

    The contract is intentionally narrow: no SecretMaterial values flow
    through this function (the dataclass __repr__ prevents accidents
    even if one slipped in). When recto.comms ships, it'll subscribe
    to the same event stream — same kinds, same ctx shape — and post
    to webhooks in addition to stdout.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),  # noqa: UP017
        "service": config.metadata.name,
        "kind": kind,
        "ctx": ctx,
    }
    try:
        line = json.dumps(record, default=str)
    except (TypeError, ValueError) as exc:
        # Defensive: a non-JSON-serializable value snuck into ctx. Log a
        # diagnostic without the offending value rather than crash.
        line = json.dumps(
            {
                "ts": record["ts"],
                "service": record["service"],
                "kind": "internal.event_serialize_failed",
                "ctx": {"original_kind": kind, "error": str(exc)},
            }
        )
    print(line, file=sys.stdout, flush=True)
