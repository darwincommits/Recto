# Changelog

All notable changes to Recto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Recto adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffold: LICENSE (Apache 2.0), README, .gitignore, pyproject.toml, CHANGELOG.
- ARCHITECTURE.md design doc covering YAML schema, pluggable secret-source backends, NSSM relationship, threat model.
- ROADMAP.md phased shipping plan (v0.1 -> v0.4).
- CLAUDE.md memory file for AI assistants working on the project.
- `recto.secrets.SecretSource` abstract base class + `SecretMaterial` sealed type (forward-compatible with v0.4 hardware-enclave backends).
- `recto.secrets.env.EnvSource` passthrough backend reading from `os.environ`.
- `recto.config.load_config` YAML loader + schema validator with aggregated `ConfigValidationError` reporting (every problem surfaces in a single raise rather than one-at-a-time). Locks `apiVersion: recto/v1`.
- `recto.secrets.credman.CredManSource` Windows Credential Manager backend via `ctypes` against `advapi32.{CredReadW,CredWriteW,CredDeleteW,CredEnumerateW}`. Uses `recto:{service}:{secret}` target-name convention so `recto credman list <service>` can filter cleanly.
- Plugin registry in `recto.secrets`: `register_source(name, factory)` / `resolve_source(name, service)` / `registered_sources()`. Built-in `env` and `credman` register on import. Adding a new backend now requires zero changes to `recto.launcher` or to consumer service.yaml beyond the `source:` selector.
- `recto.launcher.launch` orchestrator: loads `ServiceConfig`, resolves declared sources via the registry, fetches secrets, composes child env (base_env -> spec.env -> secrets, later wins), spawns child via `subprocess.Popen`, brackets lifecycle-stateful sources with `init()` / `teardown()`, and returns the child's exit code. Handles `DirectSecret` only; `SigningCapability` raises `NotImplementedError` pointing at the v0.4 milestone. Emits `child.spawn` / `child.exit` JSON events to stdout (the seam where `recto.comms` will hook webhook dispatch in subsequent v0.1 work).
- `recto.launcher.run` restart-loop wrapper: drives `recto.restart` policy decisions across child exits, brackets lifecycle init/teardown ONCE around the whole loop (so long-lived backends stay open across restarts), emits `restart.attempt` / `max_attempts_reached` / `run.final_exit` events.
- `recto.restart` policy module: pure functions `should_restart(returncode, policy)` and `next_delay(attempt, policy)` driving exponential / linear / constant backoff with `max_delay_seconds` cap and `MaxAttemptsReachedError` exhaustion signal. Stateless, trivially unit-testable.
- `recto.healthz.HealthzProbe` HTTP liveness probe: threaded daemon polling `spec.healthz.url` every `interval_seconds`, signaling `restart_required` after `failure_threshold` consecutive failures. v0.1 supports `type: http` only; tcp + exec deferred to v0.2.
- Test suite: 145 tests across config validation, secret-source backends, launcher orchestration (one-shot + restart-loop + healthz wiring), restart policy, and healthz probe. All cross-platform; subprocess.Popen, SecretSource, and HealthzProbe stubbed so no real children spawn or HTTP requests fly.
- `recto.launcher._spawn_and_wait` integrates HealthzProbe: starts a probe per spawn (when `spec.healthz.enabled`), polls child exit AND probe `restart_required` event in tandem, terminates child via SIGTERM-then-SIGKILL when the probe signals unhealthy. Probe lifetime is bracketed in a `try/finally` so a stop-failure cannot leak a thread or mask the child's exit code. `child.exit` event now carries a `healthz_signaled` flag so downstream comms know whether the exit was natural or probe-driven. `probe_factory` / `poll_interval_seconds` / `terminate_grace_seconds` are injectable through `launch()` and `run()` for tests.

### Changed
- `recto/__init__.py` surface comment updated to mention launcher + config + register_source as part of the v0.1 public API.

- `recto.comms.CommsDispatcher` webhook event dispatcher. Posts JSON events to every `spec.comms[]` sink whose category passes the `restart.notify_on_event` filter. Categories: `restart`, `health_failure`, `max_attempts_reached`, `secret_rotation` (reserved), `*` (wildcard). Template interpolation supports `${env:VAR}` (read from the composed child env, including resolved secrets), `${service.name}` / `${service.description}`, `${event.kind}` / `${event.summary}` / `${event.context_json}`. Failure-tolerant: webhook timeouts, 4xx, 5xx, transport errors, and even broken `emit_failure` callbacks are swallowed and surfaced via `comms.dispatch_failed` rather than bubbled up to the launcher's main loop. Stdlib only — `urllib.request`, no extra deps.
- `recto.launcher` wired to `CommsDispatcher`. `_spawn_and_wait` now takes a pre-built `env` (built once by `launch()` / `run()` inside `_bracket_lifecycle`), so secret fetches happen once per `run()` and the same env feeds both child processes and webhook header interpolation. New `dispatcher_factory` kwarg on `launch()` and `run()` lets tests inject stubs; production passes None and the default factory builds a real `CommsDispatcher` iff `spec.comms` is non-empty.
- Test suite grew to 189: 36 new tests in `tests/test_comms.py` covering interpolation, event filtering (each notify category, wildcard, `child.exit` healthz_signaled split), payload shape, header interpolation from env, secret-value redaction in body, and exhaustive failure soft-handling. 8 new tests in `tests/test_launcher_comms.py` covering the launch()/run() <-> dispatcher wiring contract: factory-injection, env-with-resolved-secrets-flows-to-dispatcher, single-factory-call-per-run() lifecycle, and the boundary where `_emit_event` does NOT wrap dispatcher.dispatch (relies on `CommsDispatcher`'s own soft-failure).

### Changed
- `recto.launcher.run` lives in `recto/_launcher_run.py` and is re-exported from `recto.launcher`. Split out to dodge a Cowork cross-mount Write-tool truncation we hit when launcher.py exceeded ~19KB. Public import surface (`from recto.launcher import run`) is unchanged.

### Notes for next-up v0.1 work
- `recto.cli` exposes `recto launch <yaml>`, `recto credman {set,list,delete}`, `recto status`, `recto migrate-from-nssm`.
- Delete `recto/_launcher_part2.py` (left behind during the comms work; can't be removed via the Cowork sandbox bash, see the Gotchas note in CLAUDE.md).
