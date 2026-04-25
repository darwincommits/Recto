"""Tests for recto.healthz.

Strategy: drive HealthzProbe.tick() directly with a stub fetch callable.
Avoids real HTTP, real threads, real sleeps — keeps tests deterministic
and fast. The thread / sleep machinery in _loop() is exercised by a
single integration-style test that uses interval=0 so the loop ticks
as fast as Python's GIL allows, then stops it via stop().
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from recto.config import HealthzSpec
from recto.healthz import HealthzProbe, default_http_fetch


def make_spec(
    *,
    enabled: bool = True,
    type_: str = "http",
    url: str = "http://localhost:5000/healthz",
    interval_seconds: int = 30,
    timeout_seconds: int = 5,
    failure_threshold: int = 3,
    restart_grace_seconds: int = 10,
) -> HealthzSpec:
    return HealthzSpec(
        enabled=enabled,
        type=type_,
        url=url,
        interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        failure_threshold=failure_threshold,
        restart_grace_seconds=restart_grace_seconds,
    )


def stub_fetch(*statuses: int) -> Callable[[str, float], int]:
    """Build a fetch callable that returns the given statuses in order.
    After exhausting the sequence, repeats the LAST value (so a long
    test doesn't have to specify forever)."""
    seq = list(statuses)

    def _fetch(_url: str, _timeout: float) -> int:
        if not seq:
            return 0
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return _fetch


# ---------------------------------------------------------------------------
# tick() — single-iteration probe semantics
# ---------------------------------------------------------------------------


class TestTickHealthy:
    def test_200_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(200))
        assert probe.tick() is True
        assert probe.consecutive_failures == 0
        assert probe.restart_required.is_set() is False

    def test_201_counts_as_healthy(self) -> None:
        # Any 2xx is healthy.
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(201))
        assert probe.tick() is True

    def test_301_counts_as_healthy(self) -> None:
        # 3xx is healthy too — the child responded.
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(301))
        assert probe.tick() is True

    def test_399_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(399))
        assert probe.tick() is True


class TestTickFailing:
    def test_500_counts_as_failure(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(500))
        assert probe.tick() is False
        assert probe.consecutive_failures == 1

    def test_404_counts_as_failure(self) -> None:
        # Most apps wouldn't expose /healthz returning 404, but if it
        # happens — the child is misconfigured, treat as failure.
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(404))
        assert probe.tick() is False

    def test_zero_status_counts_as_failure(self) -> None:
        # default_http_fetch returns 0 for network errors; stub mirrors that.
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(0))
        assert probe.tick() is False

    def test_fetch_raising_counts_as_failure(self) -> None:
        # Any exception from fetch is swallowed and counts as a failure.
        def boom(_url: str, _timeout: float) -> int:
            raise RuntimeError("connection refused")

        probe = HealthzProbe(make_spec(), fetch=boom)
        assert probe.tick() is False
        assert probe.consecutive_failures == 1


class TestConsecutiveFailureCounting:
    def test_failure_threshold_triggers_restart_required(self) -> None:
        probe = HealthzProbe(
            make_spec(failure_threshold=3),
            fetch=stub_fetch(500),
        )
        probe.tick()
        assert probe.restart_required.is_set() is False
        probe.tick()
        assert probe.restart_required.is_set() is False
        probe.tick()  # third consecutive failure → fires
        assert probe.restart_required.is_set() is True
        assert probe.consecutive_failures == 3

    def test_success_resets_failure_counter(self) -> None:
        # Two failures, then one success, then we need three MORE failures
        # to trip — failure_threshold counts CONSECUTIVE failures.
        statuses = iter([500, 500, 200, 500, 500, 500])

        def _fetch(_url: str, _t: float) -> int:
            return next(statuses)

        probe = HealthzProbe(make_spec(failure_threshold=3), fetch=_fetch)
        probe.tick()  # fail
        probe.tick()  # fail
        assert probe.consecutive_failures == 2
        probe.tick()  # success — reset to 0
        assert probe.consecutive_failures == 0
        assert probe.restart_required.is_set() is False
        probe.tick()  # fail
        probe.tick()  # fail
        assert probe.restart_required.is_set() is False
        probe.tick()  # third consecutive — trips
        assert probe.restart_required.is_set() is True

    def test_threshold_of_one_trips_immediately(self) -> None:
        probe = HealthzProbe(
            make_spec(failure_threshold=1), fetch=stub_fetch(500)
        )
        probe.tick()
        assert probe.restart_required.is_set() is True


# ---------------------------------------------------------------------------
# start() / stop() — disabled probe + unsupported types
# ---------------------------------------------------------------------------


class TestStartStop:
    def test_start_is_noop_when_disabled(self) -> None:
        probe = HealthzProbe(make_spec(enabled=False))
        probe.start()
        # No thread should have spawned.
        assert probe._thread is None  # noqa: SLF001 — test inspecting internal
        probe.stop()  # idempotent on never-started probe

    def test_start_raises_for_tcp_type(self) -> None:
        # tcp + exec are v0.2; v0.1 only does http. Construct via a
        # raw HealthzSpec that bypasses __post_init__'s url-required check
        # by setting type=tcp + url="" + enabled=True. HealthzSpec __post_init__
        # only requires url for type=http, so type=tcp+url="" is valid by
        # the schema even though the launcher refuses it.
        spec = HealthzSpec(enabled=True, type="tcp", url="")
        probe = HealthzProbe(spec)
        with pytest.raises(NotImplementedError) as exc:
            probe.start()
        assert "v0.2" in str(exc.value) or "http" in str(exc.value)

    def test_stop_is_idempotent(self) -> None:
        probe = HealthzProbe(make_spec(enabled=False))
        probe.stop()
        probe.stop()  # no-op
        probe.stop()  # still no-op


# ---------------------------------------------------------------------------
# _loop() — integration-style: real thread, fast tick interval
# ---------------------------------------------------------------------------


class TestLoopIntegration:
    def test_loop_stops_promptly_on_stop_signal(self) -> None:
        # interval=1 (smallest the schema allows; validates > 0). With
        # restart_grace=0 the first probe is immediate; the second is
        # 1 second later, but stop() should short-circuit that wait via
        # Event.wait() so the thread joins promptly.
        spec = HealthzSpec(
            enabled=True,
            type="http",
            url="http://localhost/x",
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=1_000_000,  # don't trip via failure path
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, fetch=stub_fetch(200))
        probe.start()
        # Let the loop tick a few times.
        import time
        time.sleep(0.05)
        probe.stop(timeout=2.0)
        # If we got here, the thread joined within the timeout.
        assert probe._thread is not None  # noqa: SLF001
        assert not probe._thread.is_alive()  # noqa: SLF001

    def test_loop_signals_restart_required_on_persistent_failures(self) -> None:
        # failure_threshold=2 + interval=1 means the probe trips after
        # ~1 second (fail at t=0, fail at t=1).
        spec = HealthzSpec(
            enabled=True,
            type="http",
            url="http://localhost/x",
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=2,
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, fetch=stub_fetch(500))
        probe.start()
        # The probe should signal restart_required within a moment.
        signaled = probe.restart_required.wait(timeout=2.0)
        probe.stop(timeout=2.0)
        assert signaled is True


# ---------------------------------------------------------------------------
# default_http_fetch — only sanity checks (no real network)
# ---------------------------------------------------------------------------


class TestDefaultHttpFetch:
    def test_returns_0_on_unreachable_host(self) -> None:
        # 192.0.2.0/24 is reserved for documentation; nothing should bind there.
        # A short timeout + that host should yield 0 (URLError or timeout).
        rc = default_http_fetch("http://192.0.2.1:1/", timeout_seconds=0.1)
        assert rc == 0

    def test_returns_0_on_invalid_url_scheme(self) -> None:
        # An invalid scheme should also be handled gracefully (URLError).
        rc = default_http_fetch("not-a-real-url", timeout_seconds=0.1)
        assert rc == 0
