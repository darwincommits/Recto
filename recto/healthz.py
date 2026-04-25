"""HTTP liveness probe for the supervised child process.

Why we have this even though NSSM restarts crashed processes
------------------------------------------------------------

NSSM's `AppExit` and `AppRestartDelay` settings cover process EXIT —
when the child crashes outright. They do not cover a child that has
silently deadlocked: imports complete, the HTTP server is bound, but
some background thread holding the request-handling lock has wedged.
The process is "Running" from the OS perspective forever. Recto's
healthz probe is the second line of defense: by polling the child's
own /healthz (or equivalent) endpoint, we detect deadlocks the OS
can't see.

Design
------

`HealthzProbe` owns a daemon thread. After `restart_grace_seconds` of
quiet (give the child time to bind its socket), it polls `url` every
`interval_seconds` with a `timeout_seconds` budget. After
`failure_threshold` CONSECUTIVE failures, it sets `restart_required`.
The launcher's run-loop reads that event and treats it as a synthetic
non-zero exit, restarting the child via the same restart-policy
machinery used for exit-code-driven restarts.

The probe is intentionally simple: GET the URL, treat any 2xx/3xx as
healthy, treat anything else (including network errors and timeouts)
as a failure. No body inspection. Apps that want richer health
semantics return a 5xx status when degraded and a 2xx when ready.

Test strategy
-------------

The probe loop is split into a stateless `tick()` method (one probe
iteration, returns healthy/unhealthy) and a `_loop()` method that
chains ticks under thread + sleep semantics. Unit tests call `tick()`
directly with an injected fetch callable — deterministic, fast, no
real HTTP / real threads. Integration tests can drive `start()` /
`stop()` against a stub HTTP server.

v0.1 supports `type: http` only. `tcp` and `exec` are deferred to v0.2
per ARCHITECTURE.md; instantiating the probe with those types raises
NotImplementedError so the schema stays forward-compatible.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from collections.abc import Callable

from recto.config import HealthzSpec

__all__ = [
    "HealthzProbe",
    "default_http_fetch",
]


HttpFetch = Callable[[str, float], int]
"""(url, timeout_seconds) -> HTTP status code. Returns 0 on any failure
(network error, timeout, malformed response, etc.). Tests inject a
deterministic stub; production uses default_http_fetch."""


def default_http_fetch(url: str, timeout_seconds: float) -> int:
    """Default HTTP probe fetcher backed by stdlib urllib.

    Returns the HTTP status code on a successful round-trip; returns 0
    on any failure (TCP refused, DNS fail, timeout, redirect-loop, etc.).
    Treats anything that wasn't a clean response as "the child is not
    responding," which is the semantic the loop wants.
    """
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        # The server responded with an error status — that's still a
        # "response," and the loop classifies 4xx/5xx as failures via
        # the 200<=status<400 check. Surface the actual code.
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0


class HealthzProbe:
    """Threaded HTTP liveness probe.

    Lifecycle:
        probe = HealthzProbe(config.spec.healthz)
        probe.start()             # begins polling in a daemon thread
        ... (launcher does its work) ...
        if probe.restart_required.is_set():
            ... handle restart ...
        probe.stop()              # signals loop, joins thread

    Or in unit tests:
        probe = HealthzProbe(spec, fetch=stub_fetch)
        probe.tick()              # synchronous one-shot
        assert probe.consecutive_failures == 1
    """

    def __init__(
        self,
        spec: HealthzSpec,
        *,
        fetch: HttpFetch = default_http_fetch,
    ):
        self.spec = spec
        self._fetch = fetch
        self.restart_required = threading.Event()
        """Set by the loop when consecutive failures cross failure_threshold.
        Launcher polls this between operations to decide whether to
        synthesize a restart."""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._consecutive_failures = 0

    @property
    def consecutive_failures(self) -> int:
        """Read-only view for callers / tests."""
        return self._consecutive_failures

    def tick(self) -> bool:
        """Run one probe iteration synchronously.

        Returns True if the probe round-trip succeeded with a healthy
        status (2xx or 3xx); False otherwise. Updates internal state
        (`consecutive_failures`, `restart_required`).

        Pure logic, no sleep, no thread. Tests use this directly.
        """
        try:
            status = self._fetch(self.spec.url, float(self.spec.timeout_seconds))
        except Exception:  # noqa: BLE001 — any exception == probe failure
            healthy = False
        else:
            healthy = 200 <= status < 400

        if healthy:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.spec.failure_threshold:
                self.restart_required.set()
        return healthy

    def start(self) -> None:
        """Spawn the background probe loop.

        No-op if `spec.enabled` is False. Raises NotImplementedError on
        tcp/exec types — those are v0.2 work.
        """
        if not self.spec.enabled:
            return
        if self.spec.type != "http":
            raise NotImplementedError(
                f"healthz type {self.spec.type!r} is not supported in v0.1; "
                f"only 'http' is implemented. tcp + exec ship in v0.2."
            )
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="recto.healthz"
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to stop and join the thread.

        Idempotent — calling stop() on a never-started or already-
        stopped probe is a no-op. The timeout is generous; the loop
        wakes up promptly because all sleeps are
        `threading.Event.wait()` with a timeout.
        """
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        """Body of the probe thread.

        Sleeps `restart_grace_seconds` first (the child needs time to
        bind its socket after spawn), then ticks every
        `interval_seconds` until either `_stop` is set or
        `restart_required` is signaled.
        """
        # Initial grace period — the stop event short-circuits the
        # sleep so launcher.stop() doesn't have to wait through it.
        if self._stop.wait(timeout=float(self.spec.restart_grace_seconds)):
            return
        while not self._stop.is_set():
            self.tick()
            if self.restart_required.is_set():
                return
            if self._stop.wait(timeout=float(self.spec.interval_seconds)):
                return
