# Changelog

All notable changes to Recto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Recto adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.2.2 integration-prep gap fixes
- `recto.adminui.EventBuffer.derived_state()` and four new fields in
  the `/api/status` payload — `restart_count`, `last_spawn_ts`,
  `last_exit_returncode`, `last_healthz_signaled_ts` — derived from
  the existing event stream. The embedded HTML index renders them
  in the Status tab with relative-time formatting (`5m ago`,
  `2h ago`). 7 new tests in `tests/test_adminui.py`.
- `recto migrate-from-nssm --keep-as-env=NAME[,NAME...]` flag plus
  `recto._migrate.partition_env_entries()` helper. Routes named
  AppEnvironmentExtra keys into the generated YAML's `spec.env:`
  block instead of Credential Manager. Default (no flag) keeps
  v0.1 behavior — every entry treated as a secret. `generate_service_yaml`
  now emits a `spec.env:` block when plain-env entries are present.
  10 new tests in `tests/test_cli.py`.
- `recto events <yaml> [--kind K] [--limit N] [--restart-history]`
  CLI subcommand. Reads the YAML to find `spec.admin_ui.bind`,
  GETs `host:port/api/events` (or `/api/restart-history`), prints
  the JSON. Falls back gracefully when admin_ui is disabled or the
  server isn't reachable — points the operator at NSSM's AppStdout
  log file. Useful during incidents when the admin UI itself is
  down. 10 new tests in `tests/test_cli.py`.
- `docs/comms-receiver.md` documents the convention for consumer
  services receiving Recto's lifecycle event POSTs:
  `POST /api/recto/events`, JSON body shape, headers, expected
  response, idempotency. Includes a stdlib reference handler plus
  nginx and Caddy reverse-proxy snippets.

### Changed — v0.2.2
- Test count: 376 → 400 (+24 across the four gap fixes).
- v0.2.1 docs commit (`docs/install.md`, `docs/upgrade-from-nssm.md`,
  `docs/integration-gaps.md`, `examples/sample.service.yaml`)
  remains as v0.2.1 -- this v0.2.2 patch builds on top.

### Added — v0.2.1 docs (operator runbook + sample YAML)
- `examples/sample.service.yaml` — minimal-but-realistic
  service.yaml demonstrating every `spec` section: secrets,
  env, healthz (with tcp + exec variants commented), restart
  policy, comms webhooks with template-interpolated headers,
  resource_limits, admin_ui, and the opt-in telemetry block.
  Generic placeholder names (`myservice`, `MY_API_KEY`,
  `hooks.example.com`) so it works as a copy-paste reference for
  any consumer service. Validates clean against `load_config`.
- `docs/install.md` — quick install guide. Requirements, `pip
  install recto` (with `[otel]` extra notes), version verify, and
  a 30-second smoke recipe that exercises the launcher + admin UI
  without needing NSSM or Credential Manager.
- `docs/upgrade-from-nssm.md` — operator runbook for migrating an
  existing NSSM-wrapped service to Recto. Nine-step flow:
  backup -> stop -> dry-run -> apply migration -> verify
  CredMan -> hand-edit YAML for healthz/comms/admin_ui ->
  `recto apply` reconcile -> start -> verify. Plus failure
  modes, rollback via `reg import`, and what doesn't migrate
  automatically (`AppExit`, `AppRestartDelay`, `AppRotate*`,
  service-dependency chains).
- `docs/integration-gaps.md` — internal memo flagging four small
  Recto-side improvements that would smooth the first-consumer
  migration: non-secret env handling in `migrate-from-nssm`, a
  documented "receive Recto events" convention for consumer
  services, richer fields in the admin UI's `/api/status`
  payload, and a `recto events <service>` CLI dump for incident
  response when the admin UI is down. None block the first
  migration; all are <50 lines each.

### Fixed — v0.2.1 cleanup
- `recto/comms.py` no longer carries a leading UTF-8 BOM. Python's
  import machinery handled the BOM transparently, but `compile()`
  from a string and various tooling chokes on it. Three-byte fix,
  no behavior change. Surfaced during the v0.2 coverage-audit
  compile sweep.
- `tests/test_secrets_credman.py::TestListNames::test_lists_only_this_service`
  and `tests/test_config.py::TestMetadata::test_name_with_underscore_and_hyphen_ok`
  no longer use operator-environment-specific service names as
  fixture data. Replaced with generic placeholders (`otherservice`,
  `my-service_web`). Test semantics identical; fixture names no
  longer leak operator context into the public OSS tree.

### Added — v0.2 coverage (pytest-cov >80% gate)
- `[tool.coverage.run]` and `[tool.coverage.report]` sections in
  `pyproject.toml`. `source = ["recto"]`; `omit` covers the
  transitional `_launcher_part2.py` stub. `exclude_lines` covers
  `pragma: no cover`, `raise NotImplementedError`,
  `if __name__ == "__main__":`, and `if TYPE_CHECKING:` blocks.
- `# pragma: no cover` markers on the four Win32-only `_*` methods of
  `JobLimit` (lines previously at 60% on Linux), the four `_win_*`
  helper functions in `recto.secrets.credman` (54% on Linux), the
  OTel-SDK-installed branch of `TelemetryClient._build_tracer` (72%),
  and `recto/__main__.py`'s `if __name__ == "__main__":` block (0%).
  These paths only run on the actual target platform (Windows /
  OTel-installed); the cross-platform Linux suite covers them via
  `FakeJobLimit` / `FakeCredManSource` / `FakeTelemetryClient`
  subclass overrides, and Darwin's full-Windows smoke run exercises
  the real ctypes / OTel paths.

### Changed — v0.2 coverage
- Coverage now reports **91%** total across the cross-platform
  critical path (376 tests, baseline before pragmas was 84%).
  Per-module: `__init__.py` 100, `_launcher_run.py` 98,
  `_migrate.py` 100, `adminui.py` 93, `cli.py` 84, `comms.py` 89,
  `config.py` 89, `healthz.py` 95, `launcher.py` 93, `nssm.py` 92,
  `reconcile.py` 100, `restart.py` 97, `secrets/__init__.py` 92,
  `secrets/base.py` 100, `secrets/env.py` 100. Every module above
  the ROADMAP's >80% gate.
- v0.2 is now feature-complete per ROADMAP: TCP/exec healthz, GitOps
  reconcile (`recto apply`), Win32 Job Object resource limits,
  OpenTelemetry traces, read-only admin UI, and the coverage gate
  all shipped.

### Added — v0.2 adminui (read-only web admin UI scaffold)
- `recto.adminui` module: `EventBuffer` (thread-safe ring buffer of
  recent lifecycle events, default capacity 1000), `AdminUIServer`
  (stdlib-only `ThreadingHTTPServer` wrapper), embedded single-file
  HTML index page (`INDEX_HTML`).
- Three read-only JSON endpoints:
  - `GET /api/status` — service name, healthz/restart shape, launcher
    uptime, current event count.
  - `GET /api/events?kind=...&limit=N` — recent lifecycle events from
    the in-memory ring buffer; optional kind filter and limit (capped
    at 2000).
  - `GET /api/restart-history?limit=N` — pre-filtered events of kind
    `child.exit` / `restart.attempt` / `max_attempts_reached` /
    `run.final_exit` (capped at 1000).
- `GET /` serves a self-contained HTML page that polls those three
  endpoints every 5 seconds. Three tabs: Status, Events, Restart
  History. No external CDN dependencies for the UI itself; only the
  fonts.googleapis stylesheet (operators in air-gapped environments
  can fork the page or ignore the font fallback).
- Bind defaults to `127.0.0.1:5050`. Operators expose externally via
  Cloudflare Tunnel + Cloudflare Access (or any reverse-proxy auth
  layer). Recto trusts every connection that reaches it; auth is the
  proxy's job. Soft-fails on bind errors (port in use, permission
  denied) — logs a warning via `emit_failure` and skips the server
  rather than breaking the launcher.
- `recto.launcher.AdminUIFactory` and `BufferFactory` callable
  aliases plus `adminui_factory` / `buffer_factory` kwargs on
  `launch()` / `run()`. Production passes the real `AdminUIServer`
  and `EventBuffer`; tests inject stubs that record `start` / `stop`
  calls without spawning an HTTP server.
- Test suite grew to 376 (+24 from v0.2 telemetry): 21 new tests in
  `tests/test_adminui.py` covering EventBuffer (append, ring
  behavior, kind filter, thread-safety smoke), AdminUIServer
  lifecycle (disabled-skip, idempotent stop, soft-fail on bind
  collision), HTTP routes (`/`, `/api/status`, `/api/events`,
  `/api/restart-history`, 404 for unknown paths), and the embedded
  HTML index. 3 new tests in `tests/test_launcher.py::TestAdminUIWiring`
  covering the launcher integration: factory construction +
  start/stop bracketing, buffer receives `child.spawn` + `child.exit`
  events, stop() runs even when popen raises.

### Changed — v0.2 adminui
- `recto.launcher._emit_event` now optionally appends to a third
  sink (the EventBuffer) after the stdout JSON / dispatcher /
  telemetry sinks. All four sinks are independent and best-effort.
- `recto.launcher.launch()` and `recto._launcher_run.run()` always
  build an EventBuffer (cheap, ~1KB) and an AdminUIServer; the
  server only binds when `spec.admin_ui.enabled` is True. Stop is
  always called in the finally so the daemon thread joins cleanly
  even if the supervised child failed to spawn.

### Deferred (post-v0.2)
- `POST /api/secrets/<name>/rotate` — write op, needs careful auth.
- `GET /api/secrets` — names-only inventory; needs CredManSource
  reach-through.
- `GET /api/config` — needs a secret-redaction pass on the YAML
  render before it can ship.
- Server-Sent Events for live log tail (currently the UI polls every
  5 seconds, which is fine for human use but heavy if many tabs are
  open).

### Added — v0.2 telemetry (OpenTelemetry traces)
- `recto.telemetry` module: `TelemetryClient` wrapping the OpenTelemetry
  tracer, `coerce_attribute_value` helper for converting Python values
  into OTel-compatible attributes (None -> "<none>", lists/tuples
  preserved, dicts JSON-serialized, arbitrary objects via repr).
- One long-lived span per `run()` (or `launch()`) invocation, named
  `recto.run.<service>`, with these lifecycle events recorded as span
  events: `child.spawn`, `child.exit`, `restart.attempt`,
  `max_attempts_reached`, `run.final_exit`, `source.teardown_failed`.
  Span attributes include `service.name`, `recto.healthz.type`,
  `recto.restart.policy`, and (on end) `recto.returncode`.
- Optional dependency: `pip install recto[otel]` pulls in
  `opentelemetry-api`, `opentelemetry-sdk`, and
  `opentelemetry-exporter-otlp-proto-http`. When `telemetry.enabled:
  true` but those packages are not installed, the client warns once
  to stderr and falls back to no-op so the launcher keeps running.
- Failure isolation: every public method on `TelemetryClient` swallows
  exceptions internally so a failing tracer (network outage, bad OTLP
  endpoint) cannot break the launcher. The launcher's `_emit_event`
  treats the telemetry sink the same way it treats the dispatcher
  sink: best-effort, never propagates.
- `recto.launcher.TelemetryFactory` callable alias and
  `telemetry_factory` kwarg on `launch()` / `run()` /
  `_spawn_and_wait` / `_emit_event`. Production passes the real
  `TelemetryClient`; tests inject stubs.
- Test suite grew to 352 (+28 from v0.2 joblimit): 24 new tests in
  `tests/test_telemetry.py` covering attribute coercion, no-op when
  disabled, fallback when OTel deps missing, the active path via a
  FakeTelemetryClient subclass that overrides `_build_tracer`, and
  failure isolation when a tracer raises. 4 new tests in
  `tests/test_launcher.py::TestTelemetryWiring` covering the launcher
  integration: start_run -> events -> end_run -> shutdown sequence,
  returncode flows to end_run, ctx flows to record_event attributes,
  telemetry stub raising doesn't break the launcher.

### Changed — v0.2 telemetry
- `recto.launcher._emit_event` now optionally calls
  `telemetry.record_event(kind, ctx)` after the stdout JSON line and
  the dispatcher.dispatch call, mirroring the existing dispatcher
  contract. Both sinks are independent: a failing dispatcher doesn't
  affect telemetry, and vice versa.
- `pyproject.toml` adds `[project.optional-dependencies] otel = [...]`
  so the OpenTelemetry tree stays out of the default install
  footprint (Recto's hard rule: stdlib-only launcher path).

### Added — v0.2 joblimit (Win32 Job Object resource limits)
- `recto.joblimit` module: `JobLimit` class wrapping a Win32 Job Object,
  `plan_for(spec) -> _JobLimitPlan` (pure planning layer), `JoblimitError`
  exception. `JobLimit` enforces `spec.resource_limits` at the kernel
  level: `memory_mb` -> `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (per-process
  committed-memory cap), `cpu_percent` -> CpuRateControlInformation
  (hard cap, 1/100ths of a percent), `process_count` -> ActiveProcessLimit.
  Plus an unconditional `KILL_ON_JOB_CLOSE` so the supervised child
  dies with the launcher even on orphaned-launcher / panicked-launcher
  paths NSSM doesn't catch.
- Cross-platform import safe: when no resource_limits are set (the
  common case), `JobLimit` is an inert shell — `attach()` and `close()`
  are no-ops without touching Win32. When limits ARE requested on a
  non-Windows host, the constructor raises `JoblimitError` ("Job Object
  limits require Windows"). Same pattern as `recto.secrets.credman`.
- Two-layer design for testability: `plan_for` is pure (tests assert
  on the returned dataclass directly), and the four ctypes-touching
  methods (`_create_job_object` / `_apply_limits` / `_assign_process`
  / `_close_handle`) are split into overridable seams. Tests use a
  `FakeJobLimit` subclass that records every call without invoking
  ctypes, mirroring the `CredManSource` / `FakeCredManSource` pattern.
- `recto.launcher.JoblimitFactory` callable alias and `joblimit_factory`
  kwarg on `launch()` / `run()` / `_spawn_and_wait`. Production passes
  the real `JobLimit`; tests inject stubs.
- Test suite grew to 324 (+24 from v0.2 reconcile): 20 new tests in
  `tests/test_joblimit.py` covering plan computation across each limit
  type, KILL_ON_JOB_CLOSE always-on flag, JobLimit lifecycle (attach +
  close + double-close idempotence + context-manager exit), and the
  non-Windows guard. 4 new tests in `tests/test_launcher.py::TestJoblimitWiring`
  covering the launcher integration: no-limits path skips attach,
  limits-set path attaches + closes, finally-block runs even on attach
  failure (with re-raise so the run-loop sees the error).

### Changed — v0.2 joblimit
- `recto.launcher._spawn_and_wait` constructs a `JobLimit` after
  `popen()` returns and attaches the child PID before entering the
  wait loop. The `proc.pid` access is gated on `joblimit.handle is not
  None` so the existing test stubs that don't expose `.pid` keep
  working unchanged. The `finally` block always closes the JobLimit
  whether the wait exited naturally or via probe-driven termination.

### Added — v0.2 reconcile (`recto apply`)
- `recto.reconcile` module: `ReconcilePlan` / `FieldChange` dataclasses,
  `compute_plan(cfg, current, *, yaml_path, python_exe)`,
  `render_plan(plan)`, `apply_plan(plan, nssm)`. Pure-functional plan
  computation + rendering; only `apply_plan` has side effects (routes
  through `NssmClient`).
- `recto apply <yaml> [--python-exe PATH] [--yes|-y] [--dry-run]` CLI
  subcommand. Reads a service.yaml, reads the current NSSM state,
  computes a diff, prints it, prompts y/N (default), then applies via
  `NssmClient`. Replaces imperative `nssm set ...` PowerShell with
  declarative GitOps. Reconciles AppPath, AppParameters, AppDirectory,
  DisplayName, Description, and clears AppEnvironmentExtra if non-empty
  (so plaintext secrets stop sitting in the registry once a service
  has been migrated to CredMan).
- `recto._migrate` private module — `_migration_plan` / `_generate_service_yaml`
  / `_escape_yaml` (renamed `build_migration_plan` / `generate_service_yaml`
  / `escape_yaml`) extracted from `recto.cli` to keep cli.py under the
  Cowork sandbox's Write-tool size threshold. Same pattern as
  `recto._launcher_run`. Public CLI behavior unchanged.
- `ConfirmFn` callable alias in `recto.cli` (defaults to `builtins.input`)
  so tests can inject scripted y/N responses without monkeypatching.
- Test suite grew to 300 (+33 from v0.2 healthz): 19 new tests in
  `tests/test_reconcile.py` covering plan computation across no-op /
  single-field / full-change / AppEnvironmentExtra-clear scenarios,
  rendering markers (`~` for changed, blank for unchanged, `!` for
  the env-extra clear), apply-call ordering, and the no-leak guarantee
  (env-extra values never appear in plan output); 14 new tests in
  `tests/test_cli.py::TestApplyDispatch` covering dry-run no-mutate,
  --yes skips prompt, interactive y/n/EOF, no-changes-needed exit-0
  path, invalid YAML, missing file, NSSM-not-found, NSSM-not-installed,
  AppEnvironmentExtra clear summarized.

### Changed — v0.2 reconcile
- `recto.secrets.credman.CredManSource` raises `SecretSourceError`
  (instead of `NotImplementedError`) when instantiated on a non-Windows
  host without `platform_check=False`. The internal `_ensure_windows()`
  helper raises the same error type. Per Darwin's 2026-04-25 IM-update
  suggestion: SecretSourceError is the canonical secret-backend error
  class, so `except SecretSourceError` paths in the launcher now catch
  platform mismatches uniformly with other backend failures. Adds 1
  test covering the helper directly.

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
