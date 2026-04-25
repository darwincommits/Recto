# Recto

Modern Windows-service wrapper. Spiritual successor to NSSM with a 2026 feature set.

## Why Recto

NSSM has been the canonical "wrap an executable as a Windows service" tool since 2003 and remains rock-solid at that primitive. But the world it was built for didn't have OpenTelemetry, didn't have GitOps, didn't have hardware-enclave secret stores, and didn't have the threat model where production secrets sitting in plaintext registry keys is a real attack surface. Recto picks up where NSSM stops:

- **Vault-backed secrets.** Service env vars never sit in plaintext on disk. Pulled from Windows Credential Manager (DPAPI-encrypted) at process start, or from any pluggable backend.
- **HTTP liveness probes** with configurable thresholds and exponential-backoff restart.
- **Restart-event webhooks** post structured JSON to any URL when the supervised process crashes, restarts, or fails health checks.
- **Declarative YAML config** that lives in the consuming repo, reviewable in PRs. Replaces imperative `nssm set ...` PowerShell.
- **Win32 Job Object resource limits** for memory, CPU, process count.
- **OpenTelemetry traces** for every lifecycle event.
- **Pluggable secret-source backends** — Credential Manager (Windows), Keychain (macOS), Secret Service (Linux), AWS Secrets Manager, HashiCorp Vault — and the architectural seam for hardware-enclave backends with biometric release.

Recto wraps NSSM today; v0.2+ may absorb the service-registration responsibility natively.

## Status

**v0.1 in active development.** Not yet released to PyPI. See [ROADMAP.md](ROADMAP.md) for phased shipping plan.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design doc — pluggable backends, YAML schema, NSSM relationship, threat model.

## Lineage

NSSM (the Non-Sucking Service Manager) by Iain Patterson, 2003-2017, public domain. Recto stands on its shoulders for the service-registration primitive and aims to keep the give-it-away spirit alive under a license that adds explicit patent grants for the modern era.
