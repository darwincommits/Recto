# Recto — Architecture

## Decisions committed at v0.1

| Decision | Choice | Rationale |
|---|---|---|
| Project name | `recto` | Bookbinding term — the right-hand page of an open book. Mnemonic: Recto stands behind your service the way a printed page stands behind text. |
| License | Apache 2.0 | Permissive (honors NSSM's give-it-away spirit) plus explicit patent grant for modern OSS hygiene. |
| Language | Python 3.12+ | Stdlib-only HTTP keeps the install footprint tiny and works on any box that already has Python. Ships v0.1 fast. Door open to port hot paths to Rust at v0.4 if portable single binaries are needed. |
| Build / install | `pip install -e .` for dev; PyPI release at v0.2 | Standard modern Python. `pyproject.toml` + `setuptools`. No Poetry. |
| NSSM relationship | **Wrap, not replace** in v0.1 | NSSM stays the Windows-service registrar. Its `Application` parameter points at `python -m recto launch service.yaml`. Recto handles everything inside the service. v0.2+ may absorb registration. |
| Test stack | `pytest`, `mypy`, `ruff` | Industry default. Strict typing, lint on PR. |
| Config format | YAML, `apiVersion: recto/v1` | Familiar to anyone who's read Kubernetes / systemd / docker-compose. Versioned for forward compat. |
| Secret backend interface | `SecretSource` ABC returning `SecretMaterial` (sealed type: `DirectSecret` or `SigningCapability`) | Forward-compatible with v0.4 hardware-enclave backends where the secret never leaves the enclave. v0.1 only uses `DirectSecret`. |

## Design decisions (post-v0.1 scaffold)

### 2026-04-25 — Launcher polls child + healthz probe in tandem

The launcher's `_spawn_and_wait` does NOT block on `proc.wait()`. Instead
it polls `proc.poll()` and `probe.restart_required` on a configurable
interval (default 0.5s). When the probe trips while the child is still
running, the launcher SIGTERMs the child, waits up to a grace window
(default 5s) for clean shutdown, then SIGKILLs if needed, and returns
the resulting exit code. This means a healthz-detected deadlock surfaces
to the restart policy as a non-zero exit and feeds the existing
backoff/max-attempts machinery — no second restart code path.

Trade-off: 0.5s polling adds a small fixed CPU cost per supervised
service. Acceptable for v0.1 (services are long-lived, the launcher is
one-per-service, and modern Windows boxes don't care about a 2 Hz Python
poll). If the poll cost ever shows up in profiling, the alternative is
an OS-level event-driven approach (`WaitForMultipleObjects` on Windows,
`select` / `epoll` on POSIX) — but that adds platform-specific code
where the simple poll-loop is portable.

### 2026-04-26 — v0.5+ universal vault scope; capability delegation as the agent path

Two design pivots crystallized during v0.4 phone-app round 4 development
that broaden Recto's scope substantially.

**Universal vault.** The phone-resident enclave is a generic
cryptographic-capability provider, not a service-secrets-only vault. The
same operator-gated phone-side primitive that signs a service's payload
hash can equally generate a TOTP code (RFC 6238) for legacy 2FA, sign a
WebAuthn assertion challenge for passkey login, sign a PKCS#11 digest
for SSH / code-signing, decrypt a PGP message, or expose phone-as-
authenticator over FIDO2 hybrid transport (caBLE). Each is a new value
of the wire protocol's `PendingRequest.kind` field; the phone enclave +
biometric ACL pattern stays uniform across kinds. Recto v0.5+ targets
unifying every credential a user carries — replacing YubiKey-for-SSH,
Authy-for-2FA, password-managers-for-credentials, and browser-stored-
passkeys with one phone-anchored vault. The original "service env vars"
use case becomes one kind among many.

**Capability delegation as the agent path.** AI agents and other
autonomous actors can't provide biometric approval. The resolution: the
operator (with biometric on phone) is the unconditional root of trust;
agents receive scoped, time-bounded, revocable JWT capabilities that
authorize delegated signing for some duration / use count. The agent
presents the capability with each sign request; the bootloader verifies
against the operator's public key. Two structural properties fall out:
agents cannot exceed the scope their human granted, cannot persist past
the capability's expiry, and can be revoked any time from the human's
phone; and the human stays in the loop at *capability granularity*
(granted once, valid 24h / 1000 ops) rather than *operation
granularity* (every individual signature). The latter would make any
meaningful agent workflow unusable.

The session-JWT primitive originally planned as a v0.4 phone-app round 5
bootloader-internal latency optimization is the same artifact with
bearer = bootloader. Capability JWTs for external agents subsume that
use case. Round 5 redirects to the universal-vault direction (TOTP as
the first non-`single_sign` kind); JWT work resurfaces alongside agent
identity registration in a later round. **Forward-compat hook**: when
JWTs eventually ship, an optional `recto:bearer` claim distinguishes
`"bootloader"` (cached internally) from `"agent:<agent-id>"` (held
externally). Protocol stays at version 1.

### 2026-04-27 — Production cert architecture; Web3 / blockchain credential expansion

Two design decisions on the morning of v0.4.1 v1-completion-sprint cleanup,
both shaping where Recto goes between v1 launch and v0.7+.

**Production cert architecture: CA-signed + SPKI pinning** (the
Signal / WhatsApp model, not pure self-signed-with-pin). For v1 launch
the bootloader sits behind a Cloudflare Tunnel that terminates TLS with
a Let's Encrypt cert tied to the operator's chosen subdomain (e.g.
`vault.recto.example`). The phone-side `PinningService` continues to
pin the SPKI captured at pairing time; CA compromise -> cert rotation
-> SPKI mismatch -> phone fails closed. Three reasons CA-signed beats
pure self-signed-with-pin:

- **Browser ergonomics.** The bootloader's operator UI loads cleanly
  without "Not secure" warnings. Operator-team click-through fatigue
  becomes a real signal-to-noise problem in pure self-signed mode
  (was the warning expected, or is something compromised?).
- **AI agent ergonomics.** Stock HTTP libraries (httpx, fetch,
  reqwest) connect cleanly to a CA-signed origin without per-runtime
  custom-pinning code. Capability JWT does the heavy lifting on auth;
  the cert layer just answers "is this the right host." Agents can
  ship anywhere without operator-supplied pinning bundles.
- **Renewal automation reuse.** Operators who already terminate TLS
  for other services via Cloudflare Tunnel + Let's Encrypt can adopt
  the same pattern for Recto bootloaders at near-zero marginal cost:
  same renewal pipeline, same CF zone, same admin overhead.

Self-signed `--tls` mode (with rotation-on-startup) stays in the
codebase for dev iteration, air-gapped deployments, and any deployment
shape where the bootloader genuinely doesn't have public DNS / internet
egress. SPKI pinning is layer-orthogonal: applies identically whether
the underlying cert is self-signed-stable, self-signed-rotating, or
CA-signed. Tailscale-style identity-key-only-no-cert architecture
considered and rejected: clean architecture but would require
rebuilding Recto's network protocol from scratch and lose interop
with stock HTTP tooling. Not the right trade-off for v1.

**Web3 / blockchain credential expansion (v0.6+).** Recto's universal-
vault scope (declared in the 2026-04-26 entry above) explicitly
includes Web3 credentials: ETH transaction signing, EIP-712 typed-data
signing for off-chain authorization, ENS-resolved human-readable
recipients, eventually multi-chain support (Solana, Bitcoin, etc.).
This is a substantial scope expansion but a natural one: the substrate
already supports it conceptually.

- **Phone enclave + biometric IS the right hardware-wallet primitive.**
  Per-transaction biometric approval is the sweet spot between "seed
  phrase exposed in software" (catastrophic) and "Ledger / Trezor in
  pocket" (you don't carry it everywhere). A phone is always carried;
  Recto's biometric-gated signing matches Ledger's trust model with
  better ergonomics.
- **Capability JWT framework IS the right delegation primitive for
  AI crypto agents.** Today's crypto AI agents either have full key
  access (catastrophic if compromised) or no key access (can't
  transact). Scoped capability JWTs are the missing primitive --
  per-address allowlists, per-amount caps, per-time-window caps. An
  agent delegated "can sign tx up to 0.1 ETH to addresses on this
  list, expires 24h, max 50 uses" is what hardware-wallet UX has been
  waiting for. The capability primitive shipped in v0.4 round 6 with
  bearer = bootloader; v0.7+ extends it for crypto-agent scenarios.
- **Audit log is table stakes for crypto.** Every signature is a real-
  money transaction; the per-phone audit log shipped in v0.4.1 already
  captures the right shape (timestamp + payload hash + decision +
  recorded_at_unix). For ETH the payload hash is sufficient; for
  EIP-712 the bootloader will need to also store the typed-data struct
  for human-readable history.
- **Lost-phone recovery already works for crypto.** Pair two phones
  at separate pairing events, revoke the lost one from the survivor.
  This is exactly the recovery model crypto users want and don't get
  from hardware wallets (Ledger's recovery story is famously rough).

The technical gap that makes blockchain v0.6 not v1:

- **secp256k1 isn't enclave-native on iOS or Android.** Both Secure
  Enclave and StrongBox support only P-256 / RSA / Ed25519
  (Ed25519 only on Android). secp256k1 (ETH's, Bitcoin's curve)
  needs software-backed signing via BouncyCastle. Resolution:
  envelope encryption -- secp256k1 key material in software,
  encrypted by the existing enclave-resident P-256 key, decrypted at
  sign time after biometric. Standard mobile-wallet pattern (used by
  Coinbase Wallet, MetaMask Mobile, Rainbow, etc.). Acceptable
  trade-off: slightly weaker than pure-enclave P-256 keys in that the
  decrypted secp256k1 material exists briefly in process memory, but
  still fully gated by phone-resident biometric and never leaves the
  device. Will revisit if Apple / Google add secp256k1 to enclaves
  natively (not anticipated in any 2026 announcements).
- **Transaction-aware UI is its own substantial sprint.** Doing crypto
  signing safely requires decoding EIP-1559 + legacy transactions,
  decoding EIP-712 typed-data structures (every protocol has its own
  struct), resolving ENS for human-readable recipients, optionally
  contract-call decoding (recognize "this is a USDC transfer to X" vs
  raw `approve(unlimited)` -- the latter being the #1 crypto phishing
  vector today). Doing it badly = losing real money. Doing it right =
  ~2-3 weeks of focused work plus ongoing maintenance as new EIP
  patterns emerge.

Strategic implication: **the operator's ENS (e.g. `yourname.eth`)
becomes a phone-protected identity sitting alongside Keycloak login,
TOTP codes, SSH keys, and PGP keys -- single biometric tap, scoped to
whatever's being approved, audit-logged in one place.** This unifies
Web2 and Web3 identity behind a single phone-anchored enclave, which
no existing product does well. Hardware wallets do crypto but not Web2;
password managers do Web2 but not crypto; Recto can do both with the
same primitives.

The capability-bounded-AI-crypto-agent scenario is the strategic moat:
no other product has a primitive for "let an agent sign transactions
within a scoped budget without giving up the keys." Most crypto AI
agents today are either (a) given the seed phrase (catastrophic on
compromise) or (b) restricted to read-only operations (can't actually
do anything useful). Recto's capability framework ships agent-bounded
delegation by construction.

### 2026-04-27 (later) — Native-asset substrate (operator-branded coin direction, v1.0+)

Beyond integrating existing chains as vault credentials (the v0.6-v0.9
multi-chain sprint in ROADMAP.md), Recto's primitives are positioned to
support **operator-branded native-asset launches** built on the same
substrate. This is an architectural observation about the substrate's
suitability, not a Recto-the-OSS-project commitment to launching its
own coin -- specific coin launches are commercial decisions made by
operators deploying Recto, not by the OSS project. Three primitives
make Recto unusually well-suited as the substrate beneath any
operator-branded native asset:

**1. Phone-resident enclave keys are validator keys by construction.**
Today's PoS validators are server-class machines running 24/7 with
software-resident keys. A Recto-substrate-equipped chain can be the
first where **validators are operator-attended phones**. Every
block-signing operation requires biometric approval -- a property no
existing chain has. Trade-offs vs. machine validators:

- *Liveness*: machine validators have higher uptime; phone validators
  may miss blocks during sleep / no-network. Mitigation: validator
  set sized larger so quorum tolerates phone-availability variance;
  capability JWTs let the operator delegate "auto-sign blocks for the
  next 24h up to 1000 ops" to the phone-itself-as-agent, which is the
  same primitive that lets external agents act bounded.
- *Decentralization*: phone validators are massively more decentralized
  than server validators. A network of 10,000 phone-validators
  scattered across operators worldwide is harder to attack than a
  network of 100 cloud-server validators concentrated in three AWS
  regions.
- *Sybil resistance*: each validator slot requires biometric-gated
  signing, which raises the cost of pure-machine sybil farms. Pairs
  well with stake-weighted slot allocation (PoS classic).

**2. Capability JWTs are governance + delegation primitives by
construction.** The same capability framework that lets an agent sign
ETH transactions within a scoped budget naturally extends to:

- *Validator delegation*: "I delegate my validator slot to my own
  always-on phone instance for 24h" (bearer = operator's secondary
  phone).
- *Stake delegation*: "I delegate N units of stake to validator X for
  governance purposes; they vote on my behalf, I retain withdrawal
  rights" -- standard liquid-staking, but with the delegate-
  revocation primitive baked in via JWT expiry / revocation.
- *Agent-driven on-chain transactions*: AI agents paying for vault
  operations (per-sign, per-capability-issuance) within
  operator-bounded budgets. The same agent-bounded-delegation moat
  that applies across existing chains (v0.7) applies here too.

**3. Audit log is on-chain history.** The per-phone audit log shipped
in v0.4.1 captures every signature event. For a substrate-equipped
chain, those events are chain history -- block-signing, stake
operations, capability issuance, transfers. The schema change is
minor: existing audit fields (timestamp, payload hash, decision,
recorded_at_unix) plus block height + chain-state-relevant fields.
The on-chain log and the operator's phone-side audit log are the same
data viewed two ways.

**Open architectural questions for any substrate-equipped chain:**

- *Layer architecture*: L1 sovereign vs. L2 rollup on Ethereum vs.
  Cosmos SDK zone? L2 on ETH is fastest to bootstrap (leverages ETH
  security; native asset is an ERC-20 + rollup). Cosmos SDK is medium
  effort with IBC interop into the Cosmos ecosystem (covered by the
  v0.8 multi-chain sprint). Sovereign L1 with phone-validator
  consensus is most ambitious but most architecturally novel. Default
  bet for substrate design work: **Cosmos SDK zone** -- proven
  consensus (Tendermint / CometBFT), IBC interop for free, sovereign
  control of the validator set rules (which is where the
  phone-validator innovation happens), and faster shipping than a
  from-scratch L1.
- *Consensus mechanism*: standard Tendermint with phone-validator
  participation? Custom block-production rules that account for
  phone-availability variance? Hybrid PoS + biometric attestation?
- *Tokenomics shape* (substrate-level guidance, not asset-specific):
  fixed supply, inflationary, or deflationary fee-burn. Validator
  rewards have to come from somewhere; pure fixed-supply requires
  meaningful per-operation fees.
- *Wallet integration*: every Recto-equipped phone is a wallet by
  construction. The vault key IS the wallet key -- no separate seed
  phrase, no separate biometric flow, no separate recovery model.
  Lost-phone recovery via the existing two-phone-revoke flow inherits
  to native-asset balances.
- *Compliance posture*: substrate decisions don't bind operators on
  compliance, but the substrate should not foreclose any reasonable
  compliance posture an operator might choose (utility token,
  security token, foundation-issued, etc.).

**Roadmap positioning**: substrate-level work for native-asset support
sequences AFTER the multi-chain integration sprints (v0.6-v0.9). The
`IBlockchainSigner` extensibility seam built for ETH / BTC / Solana /
Cosmos / Polkadot is the same seam any substrate-equipped chain plugs
into; building the seam against external chains first prevents
substrate-specific assumptions from constraining its general
applicability.

**Strategic framing (substrate-level)**: with multi-chain integration
(v0.6-v0.9) Recto-the-substrate becomes the user identity layer for
crypto. Adding native-asset substrate support (v1.0+) opens a path
where operators can launch chains where Web2 identity, multi-chain
Web3 identity, AND a native settlement layer for vault-operation
economics all live under one biometric-gated phone-anchored vault. The
capability-bounded-AI-agent primitive is the moat across all three
layers; the substrate stays generic about which operator launches what
asset on top.

**Metered-AI-product launch pattern (substrate-level support).** Any
product where AI consumption is metered and paid-per-use is a natural
demand-side anchor for an operator-branded native asset built on
Recto. The shape is well-understood from existing subscription-AI
products: per-user monthly allotments of AI operations gated behind
tiered pricing, settled via fiat-card subscriptions. The substrate
supports collapsing this to per-operation settlement: each upstream
LLM-API call the product makes on a user's behalf burns or transfers
a small amount of the operator's native asset from the user's
vault-resident balance. Heavy users pay proportionally; light users
save vs. tier-amortized pricing.

The capability JWT framework completes the picture: users delegate
"this AI agent can spend up to N units from my balance on AI
operations in the next 24 hours" via the same primitive that
authorizes Web2 sign operations (today) and Web3 crypto-agent
transactions (v0.7). End-to-end: a user signs in via Recto-passkey,
the product issues an AI-quota capability JWT to its own server-side
AI agent, each AI operation consumes from the user's vault validated
against the capability's per-amount and per-time-window caps. User
identity, payment, and agent delegation all live in the same
biometric-gated vault. Operators with existing AI-quota plumbing
(subscription tiers gating per-user AI allotments) are well-positioned
as early adopters; the migration shape is "replace the fiat-card-
billing layer with native-asset settlement" without changing
user-facing tier semantics.

The specific assets, brands, distribution mechanics, tokenomics, and
launch sequencing are operator-and-product decisions outside the OSS
substrate's scope. Operators planning their own native-asset launch
should track those design decisions in their own product's
documentation, not in Recto's.

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
4. Retargets the NSSM `Application` parameter from `python.exe` to `python -m recto launch ...`.
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
