# Changelog

All notable changes to Recto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Recto adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.2 healthz
- TCP healthz probe (`spec.healthz.type: tcp`): opens a TCP connection to
  `host:port` with `timeout_seconds`; success is healthy. Lighter-weight
  than HTTP for services that don't expose a `/healthz` endpoint but DO
  listen on a port.
- Exec healthz probe (`spec.healthz.type: exec`): runs `command` (list
  of args) with `timeout_seconds`; exit code matching
  `expected_exit_code` (default 0) is healthy. Useful for services with
  a bespoke health check (database connection test, custom CLI tool,
  etc.). Stdout/stderr captured (not surfaced) so health checks stay
  quiet on the launcher's own stream.
- New `recto.healthz.ProbeCheck` callable type and `default_tcp_check`
  / `default_exec_check` / `default_http_check` default implementations.
  `HealthzProbe` now accepts a general `check=` parameter alongside the
  v0.1 HTTP-only `fetch=` seam (which is preserved for backward
  compatibility).
- `HealthzSpec` schema additions: `host: str`, `port: int` (tcp-only),
  `command: tuple[str, ...]`, `expected_exit_code: int` (exec-only).
  Validation is type-aware: tcp+enabled requires `host` + `port`
  (1..65535); exec+enabled requires non-empty `command`.

### Changed — v0.2 healthz
- `recto.healthz.HealthzProbe` dispatches on `spec.healthz.type` to pick
  the default check; HTTP path unchanged. Backward compatibility:
  passing `fetch=` to a probe still works for v0.1-era HTTP tests.
  Passing both `fetch=` and `check=` raises `TypeError` so callers don't
  accidentally double-up.

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

- `recto.cli` argparse-based command-line interface. Subcommands:
  - `recto launch <yaml> [--once]` — load + validate the YAML and call
    `recto.launcher.run` (or `launch` with `--once`). Returns the
    child's exit code; YAML errors surface as exit 1 with the
    aggregated `ConfigValidationError` message on stderr.
  - `recto credman set <service> <name> [--value V]` — install a
    secret in Windows Credential Manager. Without `--value`, prompts
    via `getpass` so the value never appears on the command line and
    is not echoed. Empty prompt input is refused; `--value ""` is the
    explicit override for "I really mean empty".
  - `recto credman list <service>` — list installed secret names for
    a service, sorted, one per line. Empty inventory is exit 0 (not
    an error).
  - `recto credman delete <service> <name>` — remove an installed
    secret. Exit 1 with a clear message if the credential doesn't
    exist.
  - `recto status <service>` — shell out to `nssm status <service>`
    and print the result. Exit 0 on `SERVICE_RUNNING`, 1 otherwise —
    suitable as a poll target.
  - `recto migrate-from-nssm <service> [--yaml-out path]
    [--python-exe path] [--dry-run]` — read NSSM config via `nssm get`
    for every canonical field, install AppEnvironmentExtra entries to
    Credential Manager, write a generated service.yaml with a
    `secrets:` block referencing those credman targets, retarget NSSM
    AppPath at `python.exe`, set AppParameters to
    `-m recto launch <yaml>`, and reset AppEnvironmentExtra so the
    plaintext entries are gone. `--dry-run` prints the plan with secret
    values masked as `<redacted>` and makes no changes. Idempotent:
    re-running on a migrated service is a no-op (CredWriteW upserts;
    NSSM `set` is idempotent on identical values).
- `recto.nssm.NssmClient` thin wrapper around `nssm.exe` for the
  status / get / set / reset operations the CLI needs. Bytes-mode
  subprocess capture with UTF-16-LE -> UTF-8 -> cp1252 decode fallback
  (NSSM emits wide strings on Windows; some patched builds use UTF-8).
  All shell-outs flow through a single `runner` callable so tests
  inject a stub. `NssmConfig` snapshot dataclass + `split_environment_extra`
  parser for the multi-line `KEY=value` block.
- `recto/__main__.py` so `python -m recto …` mirrors the
  console-script entry point at `recto = recto.cli:main`.
- Test suite grew to 239 (+50 from v0.1 cli work): 22 new tests in
  `tests/test_nssm.py` covering AppEnvironmentExtra parsing,
  status/get/set/reset, get_all field aggregation, service-not-found
  vs generic-error split, and decoder edge cases; 28 new tests in
  `tests/test_cli.py` covering argparse shape per subcommand,
  launch dispatch + invalid-config + missing-file paths, credman
  set/list/delete with FakeCredManSource, status running/stopped/
  nssm-missing, and migrate-from-nssm dry-run + apply (with secret
  redaction in plan output, NSSM retarget assertions, and round-trip
  parsing of the generated YAML).

### Notes for next-up work
- v0.2 progress: TCP + exec health checks shipped (this entry).
  Remaining v0.2 scope: admin UI, GitOps reconcile (`recto apply`),
  Win32 Job Object resource limits, OpenTelemetry traces, pytest-cov
  >80% on launcher critical path.
- Test suite grew to 266 (+27 from v0.1 cli work): 19 new tests in
  `tests/test_healthz.py` covering tcp + exec dispatch, default
  implementations against real sockets / real subprocesses, and the
  legacy `fetch=` backward-compat seam; 8 new tests in
  `tests/test_config.py` covering tcp + exec schema validation
  (host/port/command required when enabled, type-specific defaults,
  custom expected_exit_code).
