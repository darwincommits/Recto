# Recto — Roadmap

Phased shipping plan. Each phase is a tagged release; the architecture seam (`SecretSource` ABC, YAML schema) is locked at v0.1 so later phases slot in without breaking earlier consumers.

## v0.1 — "Don't leak secrets to the Windows registry"

**Target:** April-May 2026.

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
- Migration script: `recto migrate-from-nssm <service>` reads existing NSSM config, generates YAML, retargets AppPath, imports AppEnvironmentExtra entries to Credential Manager, clears AppEnvironmentExtra.
- Tests: config validation, credman backend (ctypes mocked), launcher e2e against a sleep-based echo service.
- Examples: minimal `service.yaml` showing common shapes (single-process, Docker-wrapped, multi-secret).
- Docs: `install.md`, `upgrade-from-nssm.md`.

**Success criterion:** A real Python service runs under Recto. Its API key lives in Credential Manager (encrypted), not in NSSM `AppEnvironmentExtra` (plaintext). Crash detection fires within 30 seconds. Restart events post to a configurable webhook. Tracked behavior of the wrapped service is identical to a direct NSSM install.

**Estimated code:** ~1,500 lines of Python + ~500 lines of tests.

## v0.2 — "Operational maturity"

**Target:** Within a month of v0.1 ship.

**Scope:**
- Web admin UI at `127.0.0.1:5050`, exposed via Cloudflare Tunnel (or any reverse proxy you bring), gated by Cloudflare Access or your auth layer of choice. Tabs: Status, Logs (live tail), Secrets (names only, masked values, rotate button), Config (read-only YAML render), Restart History.
- GitOps reconcile. `recto apply <yaml>` reads the YAML and reconciles NSSM state to match. Replaces imperative PowerShell. Diff-and-confirm before applying.
- Win32 Job Object resource limits. `recto.joblimit` wraps the child in a Job Object enforcing the YAML-declared `resource_limits`.
- OpenTelemetry traces for every lifecycle event. Sink to a configurable OTLP endpoint or no-op if undeclared.
- TCP and exec-based health checks alongside the HTTP variant.
- `pytest-cov` >80% on the launcher critical path.

**Estimated code:** ~2,000 lines.

## v0.3 — "Multi-platform secret backends"

**Target:** Q3 2026.

**Scope:**
- `recto.secrets.keychain` — macOS Keychain via `/usr/bin/security` CLI (stdlib only).
- `recto.secrets.secretsvc` — Linux Secret Service via `secretstorage` package.
- `recto.secrets.aws` — AWS Secrets Manager via `boto3` (optional dep, lazy-loaded).
- `recto.secrets.vault` — HashiCorp Vault via `hvac` (optional dep, lazy-loaded).
- Linux + macOS launcher paths (replacing NSSM with systemd / launchd integrations).
- Cross-platform CI: GitHub Actions runners on Windows, Linux, macOS.

**Estimated code:** ~1,500 lines + per-platform integration tests.

## v0.4 — "Secrets that never sit on the server"

**Target:** Late 2026 / 2027. The marquee phase.

**Scope:** Hardware-enclave secret backend. Secrets live in a phone's Secure Enclave or StrongBox; never touch the server's filesystem. Each cryptographic operation (sign / decrypt) is biometric-gated on the phone. Designed to be quantum-resistant from the start (NIST-finalized PQ signature schemes — Dilithium / Falcon / SPHINCS+ — when hardware support catches up; classical ECDSA in-enclave as the bridge).

**Architecture:**
- A companion bootloader process per customer that bridges the consumer's main app and the employee's phone-resident vault.
- The bootloader is OSS (lives in this repo); customers self-host. We never see customer secrets.
- Recto launcher detects `SigningCapability` returns (vs `DirectSecret`) and exposes a local-socket sign-helper to the child process instead of an env var. Child apps that opt in call the sign-helper for cryptographic operations; child apps that don't continue using env-var sources unchanged.
- Network protocol between launcher and bootloader: QUIC + signed challenges. Push-notification wakeup (APNs / FCM) for foreground operations.

**Open questions (resolve closer to ship date):**
- Phone-availability recovery: co-signers, sealed cold-storage backup, grace-period fallback. Trezor / Ledger conventions probably apply.
- Latency model: short-lived session tokens issued by phone, cached on server with N-minute lifetime. Phone signs the session-token issuance, not every operation.
- Revenue model: support / hardening / compliance audits around the OSS bootloader, possibly a hosted enterprise distro. Decided closer to ship.

**Pre-requisites:** v0.1 + v0.2 + v0.3 in production with real users; consumer base of users who'd upgrade their secret backend; high-value secret stores (cloud APIs, signing keys) to sign against.

## Long-term ideas (no timeline)

Things worth doing once the substrate is mature; not blocking anything.

- Native Windows-service registration (replace NSSM).
- Secret rotation orchestration: `recto rotate <service>/<name>` triggers vault rotation, restarts service with new secret, posts event.
- Multi-process services: Docker Compose + Kubernetes Pod equivalents in YAML.
- Hot-reload of secrets without service restart (named-pipe SIGHUP-equivalent on Windows).
- Audit log of every secret access (when, by which child PID, for which operation).
