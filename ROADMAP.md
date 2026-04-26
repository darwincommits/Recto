# Recto — Roadmap

Phased shipping plan. Each phase is a tagged release; the architecture seam (`SecretSource` ABC, YAML schema) is locked at v0.1 so later phases slot in without breaking earlier consumers.

## Cadence note

Original timeframes (April-May 2026 → late-2026/2027) were drafted before AI-assisted development cadence was factored in. The actual pace has compressed v0.1 to a single development sprint; the targets below reflect what we're now shipping against. Compressed milestones assume the operator stays available for review + push, not full-time AI work; if review windows lengthen, milestones slip linearly.

## v0.1 — "Don't leak secrets to the Windows registry"

**Target:** end of April 2026 (in flight; cli is the last module).

**Scope:**
- `recto.secrets.base` — `SecretSource` ABC + `SecretMaterial` sealed type (`DirectSecret` + `SigningCapability` declared even though only `DirectSecret` ships).
- `recto.secrets.env` — passthrough backend reading from `os.environ`. Useful for local dev + tests.
- `recto.secrets.credman` — Windows Credential Manager backend via `ctypes` to `advapi32.CredRead` / `CredWrite`.
- `recto.config` — YAML loader + schema validator. Catches malformed configs at startup, not at first secret fetch.
- `recto.launcher` — main process orchestrator: reads config, fetches secrets, spawns child via `subprocess.Popen` with the right env, supervises lifecycle.
- `recto.restart` — backoff + max-attempts policy. Stateless; called from launcher.
- `recto.healthz` — HTTP probe loop. Threaded; signals launcher to restart child on N consecutive failures.
- `recto.comms` — webhook dispatch with template interpolation. Posts events to the configured comms endpoint.
- `recto.cli` — argparse CLI: `recto launch`, `recto credman set/list/delete`, `recto status`, `recto migrate-from-nssm`.
- Migration script: `recto migrate-from-nssm <service>` reads existing NSSM config, generates YAML, retargets the NSSM `Application` parameter, imports AppEnvironmentExtra entries to Credential Manager, clears AppEnvironmentExtra.
- Tests: config validation, credman backend (ctypes mocked), launcher e2e against a sleep-based echo service.
- Examples: minimal `service.yaml` showing common shapes (single-process, Docker-wrapped, multi-secret).
- Docs: `install.md`, `upgrade-from-nssm.md`.

**Success criterion:** A real Python service runs under Recto. Its API key lives in Credential Manager (encrypted), not in NSSM `AppEnvironmentExtra` (plaintext). Crash detection fires within 30 seconds. Restart events post to a configurable webhook. Tracked behavior of the wrapped service is identical to a direct NSSM install.

**Estimated code:** ~1,500 lines of Python + ~500 lines of tests.

## v0.2 — "Operational maturity"

**Target:** mid-May 2026 (~2-3 weeks after v0.1).

**Scope:**
- Web admin UI at `127.0.0.1:5050`, exposed via Cloudflare Tunnel (or any reverse proxy you bring), gated by Cloudflare Access or your auth layer of choice. Tabs: Status, Logs (live tail), Secrets (names only, masked values, rotate button), Config (read-only YAML render), Restart History. **Shipped (read-only scaffold).** Three read-only JSON endpoints (`/api/status`, `/api/events`, `/api/restart-history`) plus a self-contained HTML index. EventBuffer thread-safe ring of recent lifecycle events feeds the endpoints. Soft-fails on bind error so a port collision can't break the launcher. Deferred to a follow-up: secrets-rotate POST, config-with-redaction, SSE live tail.
- GitOps reconcile. `recto apply <yaml>` reads the YAML and reconciles NSSM state to match. Replaces imperative PowerShell. Diff-and-confirm before applying. **Shipped.** Reconciles Application, AppParameters, AppDirectory, DisplayName, Description, and clears AppEnvironmentExtra. `--dry-run` for plan-only; `--yes` to skip the confirm prompt.
- Win32 Job Object resource limits. `recto.joblimit` wraps the child in a Job Object enforcing the YAML-declared `resource_limits`. **Shipped.** Enforces `memory_mb` (per-process commit cap), `cpu_percent` (CpuRate hard cap), and `process_count` (ActiveProcessLimit), plus an always-on `KILL_ON_JOB_CLOSE` so the supervised child dies with the launcher.
- OpenTelemetry traces for every lifecycle event. Sink to a configurable OTLP endpoint or no-op if undeclared. **Shipped.** One long-lived span per `run()` invocation, lifecycle events recorded as span events. Optional `pip install recto[otel]` extra so the OTel tree stays out of the default install. Failure-isolated: a misconfigured exporter cannot break the launcher.
- TCP and exec-based health checks alongside the HTTP variant. **Shipped.** `spec.healthz.type: tcp` and `type: exec` work end-to-end with type-aware schema validation; default implementations dispatched from `_default_check_for_spec`.
- `pytest-cov` >80% on the launcher critical path. **Shipped at 91% total.** `[tool.coverage.run]` + `[tool.coverage.report]` configured in `pyproject.toml`. Win32 ctypes blocks (joblimit, secrets/credman) and the OTel-SDK-installed path are `# pragma: no cover` since they only execute on the target platform; cross-platform Linux suite covers everything else. With this v0.2 is feature-complete.

**Estimated code:** ~2,000 lines.

## v0.3 — "Multi-platform secret backends"

**Target:** mid-June 2026 (~3-4 weeks after v0.2).

**Scope:**
- `recto.secrets.keychain` — macOS Keychain via `/usr/bin/security` CLI (stdlib only).
- `recto.secrets.secretsvc` — Linux Secret Service via `secretstorage` package.
- `recto.secrets.aws` — AWS Secrets Manager via `boto3` (optional dep, lazy-loaded).
- `recto.secrets.vault` — HashiCorp Vault via `hvac` (optional dep, lazy-loaded).
- Linux + macOS launcher paths (replacing NSSM with systemd / launchd integrations).
- Cross-platform CI: GitHub Actions runners on Windows, Linux, macOS.

**Estimated code:** ~1,500 lines + per-platform integration tests.

## v0.4 — "Secrets that never sit on the server"

**Target:** Substrate landed 2026-04-26 (compressed from August 2026 estimate after the same-day v0.3-deferral decision). v0.4.0 release pending: launcher integration, CLI, and the companion phone app. The marquee phase. Designed to be quantum-resistant in the wire format from day one (post-quantum signature schemes — Dilithium / Falcon / SPHINCS+ — slot in via the `algorithm` negotiation field once iOS Secure Enclave / Android StrongBox support catches up). v0.4.0 ships Ed25519 only.

**Scope:** Hardware-enclave secret backend. Private keys live in a phone's Secure Enclave (iOS) or StrongBox (Android); never touch the server's filesystem. Each cryptographic operation (sign / decrypt) is biometric-gated on the phone via `LAContext` (iOS) / `BiometricPrompt` (Android).

**Locked design decisions** (see `docs/v0.4-protocol.md` for the full RFC):

- **Distribution**: personal-use only via TestFlight (iOS) / APK sideload (Android) for v0.4.0. App-store distribution waits for v0.5+ which adds multi-user account abstractions.
- **Transport**: HTTPS + push wakeup (APNs / FCM). NOT QUIC (originally drafted but deferred -- MAUI's QUIC story is too immature for v0.4.0; revisit if mobile-network reliability becomes a real complaint).
- **Signature scheme**: Ed25519 (RFC 8032). 32-byte public keys, 64-byte signatures, deterministic. iOS 16+ + Android 11+ enclave native support.
- **Session model**: short-lived JWT (default 24h, max 1000 uses, configurable per-secret). Phone signs the JWT once during issuance; bootloader caches and replays for in-session sign operations until expiry. Proactive renewal at 80% of lifetime/uses to avoid latency spikes. Mitigates the "phone wakeup per sign operation" UX disaster.

**Architecture:**

- **Bootloader process** (`recto.bootloader`, this repo): long-lived Python process spawned by the launcher when any `spec.secrets[].source == "enclave"`. Holds public keys + cached session JWTs + pending sign requests. Runs an HTTPS server the phone polls; speaks to the launcher over a local socket. Customers self-host; we never see customer secrets.
- **Launcher integration** (`recto.launcher` extension): detects `SigningCapability` fetch results and routes them through a local-socket sign-helper instead of env-var injection. Child apps that opt in call the sign-helper for cryptographic operations; child apps that don't continue using env-var sources unchanged.
- **Sign-helper protocol** (`recto.sign_helper`): Unix socket (Linux/macOS) or Windows named pipe between launcher and supervised child. Length-prefixed JSON wire format. v0.4.0 ships Unix sockets only; Windows named pipe is v0.4.1 followup.
- **Phone app** (separate MAUI Blazor project under `/phone/`): cross-platform .NET MAUI app. Generates Ed25519 keypair in platform enclave; biometric-gated sign UI; push-notification listener; HTTPS client implementing the wire-protocol RFC.

**Shipped (2026-04-26 substrate batch 1):**

- `docs/v0.4-protocol.md` — wire-protocol RFC (430 lines, locked).
- `recto.secrets.enclave_stub` — in-memory Ed25519 backend for testing the launcher's SigningCapability code path without phone hardware.
- `recto.bootloader` package — state persistence, JWT/signature verify helpers, HTTPS endpoint handlers.
- `recto.sign_helper` — local-socket server (launcher side) + reference Python client (consumer side).
- `[v0_4]` optional dependency extra (`pip install recto[v0_4]`).
- 64 new tests (517/526 full-suite passing; 9 Windows-only skips).

**Pending (substrate batch 2 + ship):**

- Launcher integration (start `SignHelperServer` when SigningCapability is fetched; set `RECTO_SIGN_HELPER` env var on child).
- CLI: `recto v0.4 register` (issue pairing code), `recto v0.4 revoke <phone_id>`, `recto v0.4 list-phones`, `recto v0.4 serve` (run bootloader as a foreground process for testing; production deploys it under Recto itself).
- Push-notification helpers (APNs via `aioapns`, FCM via stdlib HTTP POST). Stubbed in v0.4 substrate; real backends for v0.4.0.
- End-to-end HTTP integration tests for `bootloader.server` (currently unit-tested at handler dispatch level).
- Windows named-pipe transport for `sign_helper`.
- Phone app (MAUI Blazor) -- separate project, built against the RFC.

**Open questions (post-v0.4.0):**

- Phone-availability recovery beyond "register two phones, revoke the lost one." Co-signers (m-of-n), sealed cold-storage backup keys signed by a hardware wallet (Trezor / Ledger). v0.6+.
- Cross-bootloader federation: single phone trusted by multiple bootloaders. Useful for operators with N services across N hosts.
- Audit log of every sign approval (timestamp, requesting child PID, payload hash). v0.4.1+.
- Revenue model: support / hardening / compliance audits around the OSS bootloader, possibly a hosted enterprise distro. Decided closer to ship.

**Pre-requisites for the substrate were:** v0.1 + v0.2 in production with real consumers (✓), the SigningCapability ABC seam (✓ shipped in v0.1). v0.3 multi-platform backends and v0.3 Linux/macOS launcher work were originally listed as prereqs but proved separable -- v0.4 substrate ships independently and the v0.3 work resurfaces as a separate sprint when consumer demand warrants.

## Long-term ideas (no timeline)

Things worth doing once the substrate is mature; not blocking anything.

- Native Windows-service registration (replace NSSM).
- Secret rotation orchestration: `recto rotate <service>/<name>` triggers vault rotation, restarts service with new secret, posts event.
- Multi-process services: Docker Compose + Kubernetes Pod equivalents in YAML.
- Hot-reload of secrets without service restart (named-pipe SIGHUP-equivalent on Windows).
- Audit log of every secret access (when, by which child PID, for which operation).
