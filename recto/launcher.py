"""Launcher: read service.yaml, fetch secrets, spawn the child, supervise.

Hosts launch() (one-shot), build_child_env, resolve_sources, plus the
internals shared with run(). `run()` and the longer-form event emitter
live in `recto._launcher_run` to keep this file under the cross-mount
Write-tool truncation threshold encountered during v0.1.

Hard rules in this file:
- Secrets never serialized through _emit_event (caller is responsible).
- SigningCapability raises NotImplementedError pointing at v0.4.
- spec.env entries lose to fetched secrets on env-var collision.
- shell=False everywhere; YAML's exec+args is the canonical command.
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

from recto.comms import CommsDispatcher
from recto.config import HealthzSpec, ServiceConfig, ServiceSpec
from recto.healthz import HealthzProbe
from recto.secrets import (
    DirectSecret,
    SecretMaterial,
    SecretSource,
    SigningCapability,
    resolve_source,
)

__all__ = [
    "DispatcherFactory",
    "LauncherError",
    "PopenFactory",
    "ProbeFactory",
    "SecretInjectionError",
    "build_child_env",
    "launch",
    "resolve_sources",
    "run",
]


PopenFactory = Callable[..., "subprocess.Popen[Any]"]
ProbeFactory = Callable[[HealthzSpec], HealthzProbe]
DispatcherFactory = Callable[
    [ServiceConfig, Mapping[str, str]], "CommsDispatcher | None"
]


class LauncherError(Exception):
    """Top-level launcher failure. Subclasses pin down the cause."""


class SecretInjectionError(LauncherError):
    """A secret could not be resolved or injected into the child env.

    Distinct from `SecretNotFoundError` (the source's "I don't have it")
    and `UnknownSecretSourceError` (no backend registered).
    """


def resolve_sources(config: ServiceConfig) -> dict[str, SecretSource]:
    """Build {source_name: SecretSource} for every source referenced.

    Each unique `source:` value is resolved once via the registry so
    one CredManSource handle covers every secret that shares a source.
    """
    needed = {s.source for s in config.spec.secrets}
    return {name: resolve_source(name, config.metadata.name) for name in needed}


def build_child_env(
    spec: ServiceSpec,
    sources: Mapping[str, SecretSource],
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Compose the env-var dict the child inherits.

    Layering (later wins): base_env -> spec.env -> resolved secrets.
    Secrets always override spec.env entries with the same target_env.
    SigningCapability returns raise NotImplementedError; the v0.4
    hardware-enclave seam is not connected in v0.1.
    """
    env: dict[str, str] = dict(base_env if base_env is not None else os.environ)
    env.update(spec.env)
    for s in spec.secrets:
        source = sources.get(s.source)
        if source is None:
            raise SecretInjectionError(
                f"secret {s.name!r} declares source {s.source!r} but no "
                f"matching SecretSource was provided to the launcher; "
                f"this is a launcher-internal bug - resolve_sources "
                f"should have populated it"
            )
        fetch_config = dict(s.config)
        fetch_config["required"] = s.required
        material: SecretMaterial = source.fetch(s.name, fetch_config)
        if isinstance(material, SigningCapability):
            raise NotImplementedError(
                f"secret {s.name!r}: source {s.source!r} returned a "
                f"SigningCapability (algorithm={material.algorithm!r}). "
                f"v0.1 launcher only handles DirectSecret. "
                f"SigningCapability support ships in v0.4. See ROADMAP.md."
            )
        if not isinstance(material, DirectSecret):
            raise SecretInjectionError(
                f"secret {s.name!r}: source {s.source!r} returned "
                f"unsupported material type {type(material).__name__}; "
                f"expected DirectSecret"
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
    dispatcher_factory: DispatcherFactory | None = None,
) -> int:
    """Run the supervised child once. Returns the child's exit code.

    See run() for the restart-loop variant. dispatcher_factory=None
    uses the default factory (CommsDispatcher when spec.comms is
    non-empty, else None).
    """
    if sources is None:
        sources = resolve_sources(config)
    with _bracket_lifecycle(config, sources):
        env = build_child_env(config.spec, sources, base_env=base_env)
        dispatcher = _build_dispatcher(config, env, dispatcher_factory)
        return _spawn_and_wait(
            config,
            env,
            popen,
            probe_factory=probe_factory,
            poll_interval_seconds=poll_interval_seconds,
            terminate_grace_seconds=terminate_grace_seconds,
            dispatcher=dispatcher,
        )


# ---------------------------------------------------------------------------
# Internals shared by launch() and run()
# ---------------------------------------------------------------------------


@contextmanager
def _bracket_lifecycle(
    config: ServiceConfig, sources: Mapping[str, SecretSource]
) -> Iterator[None]:
    """init() lifecycle-stateful sources before, teardown() after.

    Failures in teardown go to stdout via _emit_event (no dispatcher;
    teardown_failed is internal-only) but never propagate. Best-effort.
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
            except Exception as exc:  # noqa: BLE001
                _emit_event(
                    config,
                    "source.teardown_failed",
                    {"source": src.name, "error": type(exc).__name__},
                )


def _build_dispatcher(
    config: ServiceConfig,
    env: Mapping[str, str],
    dispatcher_factory: DispatcherFactory | None,
) -> CommsDispatcher | None:
    """Construct CommsDispatcher (or accept None opt-out).

    Tests pass a dispatcher_factory; production passes None and the
    default factory builds a real CommsDispatcher iff spec.comms
    is non-empty.
    """
    if dispatcher_factory is not None:
        return dispatcher_factory(config, env)
    if not config.spec.comms:
        return None

    def _emit_failure(kind: str, ctx: dict[str, Any]) -> None:
        # Re-emit dispatch failures to stdout WITHOUT going through the
        # dispatcher (would create an infinite loop on a flapping webhook).
        _emit_event(config, kind, ctx, dispatcher=None)

    return CommsDispatcher(config, env=env, emit_failure=_emit_failure)


def _spawn_and_wait(
    config: ServiceConfig,
    env: Mapping[str, str],
    popen: PopenFactory,
    *,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
    dispatcher: CommsDispatcher | None = None,
) -> int:
    """Spawn one child with the given env, wait for exit OR healthz unhealthy.

    Owns the per-spawn HealthzProbe lifetime. SIGTERMs the child if the
    probe trips while still running, with terminate_grace_seconds before
    SIGKILL. Returns the resulting exit code in either case.
    """
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
        dispatcher=dispatcher,
    )

    proc = popen(cmd, env=dict(env), cwd=cwd)

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
        dispatcher=dispatcher,
    )
    return rc


def _wait_for_exit_or_unhealthy(
    proc: subprocess.Popen[Any],
    probe: HealthzProbe | None,
    *,
    poll_interval_seconds: float,
    terminate_grace_seconds: float,
) -> int:
    """Block until child exits or probe signals unhealthy.

    Returns the child's exit code in either case. If the probe trips
    first, terminate the child and wait for actual exit.
    """
    while True:
        rc = proc.poll()
        if rc is not None:
            return int(rc)
        if probe is not None and probe.restart_required.is_set():
            proc.terminate()
            try:
                rc = proc.wait(timeout=terminate_grace_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
            return int(rc)
        time.sleep(poll_interval_seconds)


def _emit_event(
    config: ServiceConfig,
    kind: str,
    ctx: dict[str, Any],
    *,
    dispatcher: CommsDispatcher | None = None,
) -> None:
    """Structured stdout log line + optional webhook dispatch.

    JSON to stdout for grep-ability under NSSM's AppStdout / AppStderr.
    When dispatcher is non-None, the same (kind, ctx) is forwarded for
    webhook delivery; the dispatcher applies its own notify_on_event
    filter before posting.

    The contract is intentionally narrow: no SecretMaterial values
    flow through this function.
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
        line = json.dumps(
            {
                "ts": record["ts"],
                "service": record["service"],
                "kind": "internal.event_serialize_failed",
                "ctx": {"original_kind": kind, "error": str(exc)},
            }
        )
    print(line, file=sys.stdout, flush=True)
    if dispatcher is not None:
        dispatcher.dispatch(kind, ctx)


# Restart-loop entry point lives in _launcher_run to dodge the
# cross-mount Write-tool truncation. Re-exported under recto.launcher.run
# so callers don't need to know about the split.
from recto._launcher_run import run  # noqa: E402, F401
