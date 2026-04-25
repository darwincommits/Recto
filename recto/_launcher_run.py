"""Restart-loop entry point split out of recto.launcher.

Lives in its own module to keep recto/launcher.py under the
cross-mount Write-tool truncation threshold encountered during v0.1
work. Re-exported as `recto.launcher.run` at the bottom of
recto/launcher.py.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Mapping

from recto.config import ServiceConfig
from recto.healthz import HealthzProbe
from recto.restart import MaxAttemptsReachedError, next_delay, should_restart
from recto.secrets import SecretSource

__all__ = ["run"]


def run(
    config: ServiceConfig,
    *,
    sources: Mapping[str, SecretSource] | None = None,
    popen: Callable[..., "subprocess.Popen"] = subprocess.Popen,
    base_env: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    probe_factory: Callable[..., HealthzProbe] = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
    dispatcher_factory: Callable[..., object] | None = None,
) -> int:
    """Run the supervised child with the configured restart policy.

    Compared to launch():
    - launch() is one-shot (single spawn, single bracket).
    - run() brackets init/teardown ONCE around the whole loop and
      re-spawns per restart policy. Long-lived backends (Vault session,
      hardware-enclave handle) stay open across restarts.

    Returns the LAST child invocation's exit code, whether the policy
    decided "no restart" or max_attempts_reached fired.
    """
    # Local imports avoid the recto.launcher <-> recto._launcher_run
    # circular import at module load time.
    from recto.launcher import (
        _bracket_lifecycle,
        _build_dispatcher,
        _emit_event,
        _spawn_and_wait,
        build_child_env,
        resolve_sources,
    )

    if sources is None:
        sources = resolve_sources(config)

    with _bracket_lifecycle(config, sources):
        env = build_child_env(config.spec, sources, base_env=base_env)
        dispatcher = _build_dispatcher(config, env, dispatcher_factory)
        attempt = 0
        last_rc = 0
        while True:
            last_rc = _spawn_and_wait(
                config,
                env,
                popen,
                probe_factory=probe_factory,
                poll_interval_seconds=poll_interval_seconds,
                terminate_grace_seconds=terminate_grace_seconds,
                dispatcher=dispatcher,
            )
            if not should_restart(last_rc, config.spec.restart):
                _emit_event(
                    config,
                    "run.final_exit",
                    {"returncode": last_rc, "restart_attempts": attempt},
                    dispatcher=dispatcher,
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
                    dispatcher=dispatcher,
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
                dispatcher=dispatcher,
            )
            sleep(delay)
