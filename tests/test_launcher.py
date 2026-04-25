"""Tests for recto.launcher.

The launcher's public contract:
- resolve_sources(config) -> {source_name: SecretSource}
- build_child_env(spec, sources, base_env) -> dict[str, str]
- launch(config, sources, popen, base_env) -> int

Tests stub out SecretSource and subprocess.Popen so they run cross-platform
and don't actually spawn child processes. The credman backend's own
platform-specific behavior is tested in tests/test_secrets_credman.py;
here we only care about the launcher's orchestration.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from recto.config import ServiceConfig, load_config
from recto.launcher import (
    LauncherError,
    SecretInjectionError,
    build_child_env,
    launch,
    resolve_sources,
)
from recto.secrets import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SigningCapability,
    UnknownSecretSourceError,
    register_source,
)

# ---------------------------------------------------------------------------
# Test fixtures: stub SecretSource + stub Popen
# ---------------------------------------------------------------------------


class StubSource(SecretSource):
    """In-memory SecretSource for launcher tests.

    `materials` is a {secret_name: SecretMaterial} dict. Missing keys with
    required=True raise SecretNotFoundError, matching the contract every
    real backend implements. Tracks init/teardown call counts so the
    lifecycle bracketing test can assert on them.
    """

    def __init__(
        self,
        materials: dict[str, SecretMaterial] | None = None,
        *,
        source_name: str = "stub",
        supports_lifecycle: bool = False,
    ):
        self.materials = materials if materials is not None else {}
        self._source_name = source_name
        self._supports_lifecycle = supports_lifecycle
        self.init_call_count = 0
        self.teardown_call_count = 0
        self.fetch_calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def name(self) -> str:
        return self._source_name

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        self.fetch_calls.append((secret_name, dict(config)))
        if secret_name not in self.materials:
            if config.get("required", True):
                raise SecretNotFoundError(f"stub: {secret_name!r} not in materials")
            return DirectSecret(value="")
        return self.materials[secret_name]

    def supports_lifecycle(self) -> bool:
        return self._supports_lifecycle

    def init(self) -> None:
        self.init_call_count += 1

    def teardown(self) -> None:
        self.teardown_call_count += 1


class FailingTeardownSource(StubSource):
    """A SecretSource whose teardown() raises. The launcher must still
    return the child's exit code and not propagate the teardown failure."""

    def teardown(self) -> None:
        super().teardown()
        raise RuntimeError("teardown blew up")


class StubProc:
    """Subprocess.Popen-shaped object: just enough to satisfy launcher.wait()."""

    def __init__(self, returncode: int = 0):
        self._returncode = returncode
        self.wait_call_count = 0

    def wait(self) -> int:
        self.wait_call_count += 1
        return self._returncode


def make_popen_stub(
    returncode: int = 0,
) -> tuple[Any, dict[str, Any]]:
    """Build a Popen-shaped callable plus a captures dict the test can read.

    The returned callable records (cmd, env, cwd) into `captures` and returns
    a StubProc. Tests assert on captures after launch() returns.
    """
    captures: dict[str, Any] = {}

    def fake_popen(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> StubProc:
        captures["cmd"] = list(cmd)
        captures["env"] = dict(env) if env is not None else None
        captures["cwd"] = cwd
        return StubProc(returncode=returncode)

    return fake_popen, captures


def make_config(
    *,
    name: str = "myservice",
    exec_: str = "python.exe",
    args: list[str] | None = None,
    working_dir: str = "",
    secrets: list[dict[str, Any]] | None = None,
    env: dict[str, str] | None = None,
) -> ServiceConfig:
    """Build a validated ServiceConfig from a minimal dict spec."""
    spec: dict[str, Any] = {"exec": exec_}
    if args is not None:
        spec["args"] = args
    if working_dir:
        spec["working_dir"] = working_dir
    if secrets is not None:
        spec["secrets"] = secrets
    if env is not None:
        spec["env"] = env
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": name},
            "spec": spec,
        }
    )


# ---------------------------------------------------------------------------
# build_child_env
# ---------------------------------------------------------------------------


class TestBuildChildEnv:
    def test_no_secrets_returns_base_env_plus_spec_env(self) -> None:
        config = make_config(env={"FOO": "bar"})
        env = build_child_env(config.spec, {}, base_env={"PATH": "/usr/bin"})
        assert env == {"PATH": "/usr/bin", "FOO": "bar"}

    def test_secret_injection_overrides_base_env(self) -> None:
        config = make_config(
            secrets=[
                {"name": "MY_API_KEY", "source": "stub", "target_env": "MY_API_KEY"}
            ],
        )
        sources = {"stub": StubSource({"MY_API_KEY": DirectSecret("the-real-key")})}
        env = build_child_env(
            config.spec, sources, base_env={"MY_API_KEY": "stale-from-parent"}
        )
        assert env["MY_API_KEY"] == "the-real-key"

    def test_secret_injection_overrides_spec_env(self) -> None:
        # If a secret target_env collides with spec.env, the secret wins —
        # spec.env is "static defaults," secrets are authoritative runtime.
        config = make_config(
            secrets=[
                {"name": "API_KEY", "source": "stub", "target_env": "API_KEY"}
            ],
            env={"API_KEY": "placeholder", "OTHER": "other-value"},
        )
        sources = {"stub": StubSource({"API_KEY": DirectSecret("real")})}
        env = build_child_env(config.spec, sources, base_env={})
        assert env["API_KEY"] == "real"
        assert env["OTHER"] == "other-value"

    def test_secret_with_unprovided_source_raises(self) -> None:
        config = make_config(
            secrets=[
                {"name": "X", "source": "stub", "target_env": "X"},
                {"name": "Y", "source": "missing-source", "target_env": "Y"},
            ],
        )
        sources = {"stub": StubSource({"X": DirectSecret("x-value")})}
        with pytest.raises(SecretInjectionError) as exc:
            build_child_env(config.spec, sources, base_env={})
        assert "missing-source" in str(exc.value)

    def test_signing_capability_raises_not_implemented(self) -> None:
        # v0.1 launcher does not support hardware-enclave SigningCapability.
        sig = SigningCapability(
            sign=lambda b: b, public_key=b"\x00" * 32, algorithm="ed25519"
        )
        config = make_config(
            secrets=[
                {"name": "ENCLAVE_KEY", "source": "stub", "target_env": "ENCLAVE_KEY"}
            ],
        )
        sources = {"stub": StubSource({"ENCLAVE_KEY": sig})}
        with pytest.raises(NotImplementedError) as exc:
            build_child_env(config.spec, sources, base_env={})
        # Error message must point at the v0.4 milestone so future readers
        # can find the roadmap entry.
        assert "v0.4" in str(exc.value) or "ROADMAP" in str(exc.value)

    def test_required_missing_propagates_secret_not_found(self) -> None:
        config = make_config(
            secrets=[
                {
                    "name": "MY_API_KEY",
                    "source": "stub",
                    "target_env": "MY_API_KEY",
                    "required": True,
                }
            ],
        )
        sources = {"stub": StubSource({})}  # empty backend
        with pytest.raises(SecretNotFoundError):
            build_child_env(config.spec, sources, base_env={})

    def test_optional_missing_injects_empty(self) -> None:
        # Per the launcher docstring: required=False + missing means inject
        # the empty string from DirectSecret(value="") rather than skip.
        config = make_config(
            secrets=[
                {
                    "name": "OPTIONAL_KEY",
                    "source": "stub",
                    "target_env": "OPTIONAL_KEY",
                    "required": False,
                }
            ],
        )
        sources = {"stub": StubSource({})}  # empty backend, not required
        env = build_child_env(config.spec, sources, base_env={"PATH": "/usr/bin"})
        assert env["OPTIONAL_KEY"] == ""
        assert env["PATH"] == "/usr/bin"

    def test_required_field_overrides_config_required(self) -> None:
        # spec.secrets[].required is the canonical source of truth; if the
        # YAML's secret config dict ALSO has required=False, the launcher
        # must use spec.required (default True) and the source must raise.
        config = make_config(
            secrets=[
                {
                    "name": "KEY",
                    "source": "stub",
                    "target_env": "KEY",
                    "required": True,
                    "config": {"required": False},  # red herring
                }
            ],
        )
        stub = StubSource({})
        with pytest.raises(SecretNotFoundError):
            build_child_env(config.spec, {"stub": stub}, base_env={})
        # Confirm the launcher overrode the config.required value before
        # passing it to fetch().
        assert stub.fetch_calls[0][1]["required"] is True


# ---------------------------------------------------------------------------
# resolve_sources
# ---------------------------------------------------------------------------


class TestResolveSources:
    def test_resolve_known_sources(self) -> None:
        # 'env' is registered as a built-in. resolve_sources should return
        # an EnvSource instance keyed under 'env'.
        config = make_config(
            secrets=[
                {"name": "X", "source": "env", "target_env": "X"},
            ],
        )
        sources = resolve_sources(config)
        assert "env" in sources
        assert sources["env"].name == "env"

    def test_unknown_source_raises_during_resolution(self) -> None:
        config = make_config(
            secrets=[
                {"name": "X", "source": "totally-not-a-real-backend", "target_env": "X"},
            ],
        )
        with pytest.raises(UnknownSecretSourceError) as exc:
            resolve_sources(config)
        assert "totally-not-a-real-backend" in str(exc.value)

    def test_each_source_resolved_once(self) -> None:
        # Two secrets sharing the same source should yield ONE SecretSource
        # instance, not two — backends with state (CredManSource handle)
        # would otherwise pay setup cost per secret.
        register_source(
            "stub-shared",
            lambda service: StubSource(
                {"X": DirectSecret("x"), "Y": DirectSecret("y")},
                source_name="stub-shared",
            ),
        )
        try:
            config = make_config(
                secrets=[
                    {"name": "X", "source": "stub-shared", "target_env": "X"},
                    {"name": "Y", "source": "stub-shared", "target_env": "Y"},
                ],
            )
            sources = resolve_sources(config)
            assert len(sources) == 1
            assert "stub-shared" in sources
        finally:
            # Clean up the registry so other tests aren't polluted. Setting
            # back to a no-op factory so subsequent resolve_source('stub-shared')
            # would still yield something but tests after this clear it.
            from recto.secrets import _SOURCE_FACTORIES
            _SOURCE_FACTORIES.pop("stub-shared", None)


# ---------------------------------------------------------------------------
# launch — orchestration end-to-end
# ---------------------------------------------------------------------------


class TestLaunch:
    def test_launch_invokes_popen_with_cmd_env_cwd(self) -> None:
        config = make_config(
            exec_="python.exe",
            args=["app.py"],
            working_dir="C:\\path\\to\\myservice",
            secrets=[
                {"name": "KEY", "source": "stub", "target_env": "MY_API_KEY"},
            ],
        )
        sources = {"stub": StubSource({"KEY": DirectSecret("real-key")})}
        popen, captures = make_popen_stub(returncode=0)
        rc = launch(config, sources=sources, popen=popen, base_env={})

        assert rc == 0
        assert captures["cmd"] == ["python.exe", "app.py"]
        assert captures["cwd"] == "C:\\path\\to\\myservice"
        assert captures["env"]["MY_API_KEY"] == "real-key"

    def test_launch_returns_child_returncode(self) -> None:
        config = make_config()
        popen, _ = make_popen_stub(returncode=42)
        rc = launch(config, sources={}, popen=popen, base_env={})
        assert rc == 42

    def test_launch_passes_none_cwd_when_working_dir_empty(self) -> None:
        # spec.working_dir == "" should map to cwd=None on Popen, not "".
        # (Popen("python", cwd="") would chdir to the empty string and fail.)
        config = make_config(working_dir="")
        popen, captures = make_popen_stub()
        launch(config, sources={}, popen=popen, base_env={})
        assert captures["cwd"] is None

    def test_launch_initializes_lifecycle_sources(self) -> None:
        stateful = StubSource(
            {"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub()
        launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1

    def test_launch_skips_lifecycle_bracketing_for_stateless_source(self) -> None:
        stateless = StubSource(
            {"K": DirectSecret("v")},
            source_name="stateless",
            supports_lifecycle=False,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateless", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub()
        launch(config, sources={"stateless": stateless}, popen=popen, base_env={})
        # init/teardown are no-ops for stateless sources; they should NOT
        # be called by the launcher (would imply bookkeeping bugs).
        assert stateless.init_call_count == 0
        assert stateless.teardown_call_count == 0

    def test_launch_calls_teardown_even_on_secret_fetch_failure(self) -> None:
        # If a fetch raises after init() has been called, teardown() must
        # still run — otherwise long-lived backends leak handles on every
        # failed launch.
        stateful = StubSource(
            materials={},  # required secret is missing → SecretNotFoundError
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {
                    "name": "MISSING",
                    "source": "stateful",
                    "target_env": "MISSING",
                    "required": True,
                }
            ],
        )
        popen, _ = make_popen_stub()
        with pytest.raises(SecretNotFoundError):
            launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1

    def test_teardown_failure_does_not_mask_child_exit_code(self) -> None:
        # A teardown that raises must NOT propagate; the launcher's contract
        # is "return the child's exit code." Best-effort cleanup.
        stateful = FailingTeardownSource(
            {"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub(returncode=7)
        rc = launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert rc == 7
        assert stateful.teardown_call_count == 1

    def test_launch_resolves_sources_when_none_provided(self) -> None:
        # When sources=None, the launcher uses the registry. 'env' is a
        # built-in registered backend.
        config = make_config(
            secrets=[
                {"name": "PATH_FAKE", "source": "env", "target_env": "PATH_FAKE",
                 "config": {"env_var": "FROM_ENV"}}
            ],
        )
        popen, captures = make_popen_stub()
        # Use base_env to provide the env var EnvSource will read.
        # NOTE: EnvSource reads from os.environ, not from base_env. So we
        # need monkeypatch instead. But to keep this test stdlib, set up
        # via os.environ-equivalent: monkeypatch via a fixture would be
        # cleaner. Skipping the value assertion; just check resolution
        # didn't raise UnknownSecretSourceError for 'env'.
        # → switch this assertion to "no UnknownSecretSourceError raised."
        with pytest.raises(SecretNotFoundError):
            # FROM_ENV is unset; required=True (default); so EnvSource raises.
            launch(config, popen=popen, base_env={})
        # Critical: the failure was SecretNotFoundError, NOT
        # UnknownSecretSourceError. That means 'env' was successfully
        # resolved from the registry.

    def test_launch_emits_spawn_and_exit_events(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = make_config()
        popen, _ = make_popen_stub(returncode=3)
        launch(config, sources={}, popen=popen, base_env={})
        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        kinds = [e["kind"] for e in events]
        assert "child.spawn" in kinds
        assert "child.exit" in kinds
        # Exit event carries the returncode.
        exit_event = next(e for e in events if e["kind"] == "child.exit")
        assert exit_event["ctx"]["returncode"] == 3

    def test_launch_does_not_leak_secret_value_to_logs(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = make_config(
            secrets=[
                {"name": "API_KEY", "source": "stub", "target_env": "API_KEY"},
            ],
        )
        sources = {"stub": StubSource({"API_KEY": DirectSecret("super-secret-12345")})}
        popen, _ = make_popen_stub()
        launch(config, sources=sources, popen=popen, base_env={})
        out = capsys.readouterr().out
        assert "super-secret-12345" not in out


# ---------------------------------------------------------------------------
# Hierarchy sanity
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_secret_injection_error_is_launcher_error(self) -> None:
        # So consumers can `except LauncherError` and catch them all.
        assert issubclass(SecretInjectionError, LauncherError)


# ---------------------------------------------------------------------------
# run() — restart loop
# ---------------------------------------------------------------------------


class _SequencedPopen:
    """Popen factory that returns child procs with a pre-canned exit-code
    sequence. After the sequence is exhausted, raises AssertionError —
    that's a test bug (we expected the run-loop to stop sooner)."""

    def __init__(self, returncodes: list[int]) -> None:
        self.returncodes = list(returncodes)
        self.spawn_count = 0
        self.captured_envs: list[dict[str, str]] = []

    def __call__(
        self,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> StubProc:
        if self.spawn_count >= len(self.returncodes):
            raise AssertionError(
                f"_SequencedPopen exhausted after {self.spawn_count} calls; "
                f"the run() loop spawned more children than expected"
            )
        rc = self.returncodes[self.spawn_count]
        self.spawn_count += 1
        if env is not None:
            self.captured_envs.append(dict(env))
        return StubProc(returncode=rc)


class _SleepRecorder:
    """time.sleep stand-in that records arguments without sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class TestRun:
    def test_policy_never_returns_after_one_spawn(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        # Override default restart policy via field replace. RestartSpec
        # is frozen, so reconstruct the whole spec.
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(policy="never"),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        popen = _SequencedPopen([42])
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 42
        assert popen.spawn_count == 1
        assert sleep.calls == []  # no restarts → no sleeps

    def test_policy_on_failure_returns_on_clean_exit(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(policy="on-failure"),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        popen = _SequencedPopen([0])  # clean exit
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 0
        assert popen.spawn_count == 1

    def test_policy_always_loops_until_max_attempts(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=1,
                    max_delay_seconds=10,
                    max_attempts=3,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        # 1 initial spawn + 3 restart attempts = 4 total spawns before
        # max_attempts_reached fires.
        popen = _SequencedPopen([1, 1, 1, 1])
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 1
        assert popen.spawn_count == 4
        # 3 restart sleeps, all 1 second (constant backoff).
        assert sleep.calls == [1.0, 1.0, 1.0]

    def test_lifecycle_brackets_whole_loop_not_each_spawn(self) -> None:
        # init/teardown should run ONCE for the whole run() invocation,
        # not once per restart attempt. Long-lived backends would
        # otherwise re-open their session every cycle.
        from recto.config import RestartSpec
        from recto.launcher import run

        stateful = StubSource(
            materials={"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=0,
                    max_delay_seconds=0,
                    max_attempts=2,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )
        popen = _SequencedPopen([1, 1, 1])
        sleep = _SleepRecorder()
        run(cfg, sources={"stateful": stateful}, popen=popen, base_env={}, sleep=sleep)
        # init/teardown each called exactly once across 3 spawns.
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1
        assert popen.spawn_count == 3

    def test_run_emits_restart_and_max_attempts_events(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=0,
                    max_delay_seconds=0,
                    max_attempts=1,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )
        popen = _SequencedPopen([2, 2])
        sleep = _SleepRecorder()
        run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        kinds = [e["kind"] for e in events]
        assert "restart.attempt" in kinds
        assert "max_attempts_reached" in kinds
