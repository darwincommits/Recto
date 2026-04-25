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
- Test suite: 139 tests across config validation, secret-source backends, launcher orchestration (one-shot + restart-loop), restart policy, and healthz probe. All cross-platform; subprocess.Popen and SecretSource stubbed so no real children spawn.

### Changed
- `recto/__init__.py` surface comment updated to mention launcher + config + register_source as part of the v0.1 public API.

### Notes for next-up v0.1 work
- `recto.comms` (webhook dispatch) subscribes to events emitted by `recto.launcher._emit_event(...)` and posts to `spec.comms[].url` with template interpolation. Hook point is marked `TODO(v0.1)` in `recto.launcher`.
- `recto.cli` exposes `recto launch <yaml>`, `recto credman {set,list,delete}`, `recto status`, `recto migrate-from-nssm`.
- Wire `HealthzProbe` into `launcher.run` so a probe-driven restart synthesizes a non-zero exit and feeds the same restart-policy machinery.
