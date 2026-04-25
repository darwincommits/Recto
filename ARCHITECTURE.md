# Recto — Architecture

## Decisions committed at v0.1

| Decision | Choice | Rationale |
|---|---|---|
| Project name | `recto` | Bookbinding term — the right-hand page of an open book. Mnemonic: Recto stands behind your service the way a printed page stands behind text. |
| License | Apache 2.0 | Permissive (honors NSSM's give-it-away spirit) plus explicit patent grant for modern OSS hygiene. |
| Language | Python 3.12+ | Stdlib-only HTTP keeps the install footprint tiny and works on any box that already has Python. Ships v0.1 fast. Door open to port hot paths to Rust at v0.4 if portable single binaries are needed. |
| Build / install | `pip install -e .` for dev; PyPI release at v0.2 | Standard modern Python. `pyproject.toml` + `setuptools`. No Poetry. |
| NSSM relationship | **Wrap, not replace** in v0.1 | NSSM stays the Windows-service registrar. Its `AppPath` points at `python -m recto launch service.yaml`. Recto handles everything inside the service. v0.2+ may absorb registration. |
| Test stack | `pytest`, `mypy`, `ruff` | Industry default. Strict typing, lint on PR. |
| Config format | YAML, `apiVersion: recto/v1` | Familiar to anyone who's read Kubernetes / systemd / docker-compose. Versioned for forward compat. |
| Secret backend interface | `SecretSource` ABC returning `SecretMaterial` (sealed type: `DirectSecret` or `SigningCapability`) | Forward-compatible with v0.4 hardware-enclave backends where the secret never leaves the enclave. v0.1 only uses `DirectSecret`. |

## The service-config YAML schema

The `apiVersion: recto/v1` shape is locked. Fields are additive after v0.1; no removals without two-minor-version deprecation.

```yaml
apiVersion: recto/v1
kind: Service
metadata:
  name: myservice
  description: "Example service"

spec:
  # Process definition
  exec: python.exe
  args: ["C:\\path\\to\\myservice\\app.py"]
  working_dir: "C:\\path\\to\\myservice"
  user: "NT AUTHORITY\\NETWORK SERVICE"     # optional

  # Secret injection (v0.1 + v0.3 backends)
  secrets:
    - name: MY_API_KEY                        # logical name (CLI / admin UI / logs)
      source: credman                         # backend selector
      target_env: MY_API_KEY                  # env var on child process
      required: true                          # fail launch if missing
    - name: WEBHOOK_TOKEN
      source: credman
      target_env: WEBHOOK_TOKEN
      required: true
    # v0.3 example:
    # - name: ANTHROPIC_KEY
    #   source: vault
    #   config: {mount: secret, path: anthropic/api-key}
    #   target_env: ANTHROPIC_API_KEY

  # Plain env vars (non-secret)
  env:
    MYSERVICE_DRY_RUN: "0"
    PYTHONUNBUFFERED: "1"

  # Liveness probe (v0.1)
  healthz:
    enabled: true
    type: http                                # also: tcp, exec (v0.2)
    url: http://localhost:5000/healthz
    interval_seconds: 30
    timeout_seconds: 5
    failure_threshold: 3                      # consecutive failures before restart
    restart_grace_seconds: 10                 # wait this long after restart before probing again

  # Restart policy (v0.1)
  restart:
    policy: always                            # also: never, on-failure
    backoff: exponential                      # also: linear, constant
    initial_delay_seconds: 1
    max_delay_seconds: 60
    max_attempts: 10                          # 0 = unlimited
    notify_on_event:
      - restart
      - health_failure
      - max_attempts_reached
      - secret_rotation

  # Event dispatch (v0.1)
  comms:
    - type: webhook
      url: https://hooks.example.com/recto
      headers:
        X-Auth-Token: "${env:WEBHOOK_TOKEN}"
        # Cloudflare Access example:
        CF-Access-Client-Id: "${env:CF_ACCESS_CLIENT_ID}"
        CF-Access-Client-Secret: "${env:CF_ACCESS_CLIENT_SECRET}"
      template:
        subject: "[recto/${service.name}] ${event.kind}"
        body: "${event.summary}"
        context: "${event.context_json}"

  # Resource limits (v0.2)
  resource_limits:
    memory_mb: 512
    cpu_percent: 50
    process_count: 32

  # Admin UI (v0.2)
  admin_ui:
    enabled: true
    bind: "127.0.0.1:5050"
    cf_access_required: true
    expose_via_tunnel:
      hostname: recto.example.com
      service_token_env: CF_TUNNEL_SERVICE_TOKEN

  # OpenTelemetry (v0.2)
  telemetry:
    enabled: false
    otlp_endpoint: http://localhost:4318
    service_name: myservice
```

## Plugin seam: `SecretSource` and `SecretMaterial`

The architectural decision that lets v0.4 hardware-enclave backends slot in without rewriting v0.1.

```python
# recto/secrets/base.py (paraphrased)

class DirectSecret:
    """Secret value materialized as a string. v0.1 + v0.3 backends return this."""
    value: str

class SigningCapability:
    """Secret never leaves its enclave; instead expose a sign-callable.
    v0.4 hardware-enclave backends return this."""
    sign: Callable[[bytes], bytes]
    public_key: bytes
    algorithm: str   # "ed25519", "ecdsa-p256", "dilithium3", ...

SecretMaterial = DirectSecret | SigningCapability

class SecretSource(ABC):
    @abstractmethod
    def fetch(self, secret_name: str, config: dict) -> SecretMaterial: ...
    def supports_lifecycle(self) -> bool: return False
    def init(self) -> None: ...
    def teardown(self) -> None: ...
    def supports_rotation(self) -> bool: return False
    def rotate(self, secret_name: str, new_value: str) -> None: raise NotImplementedError
```

In v0.1 the launcher only consumes `DirectSecret`. When a hardware-enclave backend returns `SigningCapability`, the launcher exposes a local-socket sign-helper to the child process. Child apps that consume `SigningCapability` need to call the sign-helper instead of reading an env var — an opt-in change, not a forced one.

## NSSM relationship

NSSM remains the Windows-service registrar throughout v0.1 and v0.2.

```
Windows boots
  └─ NSSM Windows service "myservice" starts
       └─ runs: python -m recto launch C:\path\to\myservice\service.yaml
            └─ Recto reads YAML, fetches secrets via SecretSource, spawns child:
                 └─ python.exe C:\path\to\myservice\app.py  (with secrets in env vars)
                      └─ healthz probe loop running in parallel
                      └─ restart on policy
                      └─ webhook dispatch on lifecycle events
```

Migration from existing NSSM-only install is one-shot:
1. `recto migrate-from-nssm <service>` reads existing NSSM config.
2. Generates equivalent `<service>.service.yaml`.
3. Imports each `AppEnvironmentExtra` entry into Credential Manager.
4. Retargets `AppPath` from `python.exe` to `python -m recto launch ...`.
5. Clears `AppEnvironmentExtra`.
6. `Restart-Service <service>` picks up the new wrapping.

After migration the child process sees identical env vars and behaves identically. The Windows registry no longer holds plaintext secrets.

## Threat model

What Recto defends against, and what it doesn't.

**Defends against:**
- Plaintext secret leakage via the Windows registry. NSSM stores `AppEnvironmentExtra` as a plaintext registry value at `HKLM:\SYSTEM\CurrentControlSet\Services\<name>\Parameters\AppEnvironmentExtra`. Anyone with local admin (or compromise of the SYSTEM account) reads it. Recto pulls from Credential Manager (DPAPI-encrypted, scoped to the service account) instead.
- Silent service failure. NSSM restarts on process exit, but a deadlocked process holds the service "Running" forever. Recto's healthz probe catches deadlocks via HTTP responsiveness checks.
- Lost incidents. NSSM logs to Windows Event Log. Recto additionally posts structured events to a configurable webhook so cross-host orchestration sees crashes.

**Does not defend against:**
- Compromise of the service account itself. If an attacker has the running service's identity (via process injection, token theft, etc.), they can read secrets via the same Credential Manager APIs Recto uses.
- Compromise of the local box. If an attacker has SYSTEM, they can read DPAPI master keys and decrypt Credential Manager entries. The mitigation here is "don't put production secrets on workstation-class boxes" — same threat model as any local secret store. v0.4 hardware-enclave backends extend the defense by moving secrets off the box entirely.
- Side-channel attacks. Memory scraping, timing attacks, etc. Out of scope; Recto is a userland tool, not a hardened HSM.

## What Recto explicitly does NOT do

- Run on Linux or macOS today. v0.3 brings cross-platform secret backends + a Linux/macOS launcher, but v0.1 + v0.2 are Windows-only.
- Manage container lifecycles natively. A Docker Compose stack is wrapped by Recto via `exec: docker.exe args: [compose, up]`, not via a Docker-aware backend. Could change in v0.5+ if there's demand.
- Provide a hosted control plane. Each customer / consumer runs their own Recto. There is no central Recto SaaS; that may emerge as a separate product layered on top of v0.4 if/when the hardware-enclave backend ships.
