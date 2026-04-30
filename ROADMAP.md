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

**Phone app progress (2026-04-26):**

Three rounds shipped; `phone/` tree gitignored at repo root until
ready for public-domain promotion. Detail in CHANGELOG.md.

- ✓ Round 1 -- Scaffold cleanup, clean MAUI build, Windows launch,
  paired empty-state UI.
- ✓ Round 2 -- Pairing wire-protocol (`GET /v0.4/registration_challenge`
  + `POST /v0.4/register`) end-to-end. BootloaderClient typed
  HttpClient, BouncyCastle Ed25519 software-enclave stand-in,
  SecureStorage pairing-state persistence, mock bootloader for
  offline iteration.
- ✓ Round 3 -- Native hardware-enclave keys + biometric ACLs.
  iOS Secure Enclave (`SecKey` + `kSecAttrTokenIDSecureEnclave` +
  `.biometryCurrentSet`, ECDSA P-256). Android StrongBox
  (`KeyPairGenerator` + `setIsStrongBoxBacked(true)` +
  `setUserAuthenticationRequired(true)`, Ed25519, falls back to TEE
  on devices without StrongBox). Multi-algorithm protocol negotiation
  via `supported_algorithms`. Mock bootloader verifies both
  algorithms. Software impl remains the Windows / the macOS host Catalyst dev
  backing.
- ✓ Round 4 -- Pending sign-request flow end-to-end. New protocol
  DTOs (PendingRequest / PendingRequestContext / RespondRequest /
  RespondResponse). IBootloaderClient extended with GetPendingAsync
  / RespondAsync. Home.razor Paired card grew a Pending Sign
  Requests section with Approve / Deny buttons; 3-second poll loop
  while paired (push wakeup is round 5). Mock bootloader queues fake
  sign requests via operator-UI button, verifies returned signatures
  against stored public keys per phone. Protocol RFC clarified the
  phone_id query param + body field on the pending / respond
  endpoints (additive; stays at version 1).
- ✓ Round 5 -- **Universal vault first kind: TOTP.** Pivoted round 5
  away from the originally-planned bootloader-internal session JWT
  (subsumed under the future capability JWT framework -- see
  ARCHITECTURE.md 2026-04-26) toward the broader goal of
  Recto-as-universal-credential-platform. Added `totp_provision` and
  `totp_generate` PendingRequest kinds, ITotpService /
  TotpCodeCalculator (RFC 6238 pure-math), MauiTotpService
  (SecureStorage-backed per-alias secrets), Home.razor kind-aware
  pending-request rendering with last-generated-TOTP display, mock
  bootloader TOTP provision + generate operator-UI buttons with
  server-side code verification (+-1 time-step window for clock skew).
- ✓ Round 6 -- **Capability JWT framework + TLS cert pinning.** The
  architectural climax. Capability JWTs (`session_issuance` pending
  kind, `CapabilityJwtClaims` + `CapabilityJwtBuilder` shared
  services, `recto:bearer` claim distinguishing `"bootloader"` from
  `"agent:<agent-id>"`) are the primitive that lets agents inherit
  capabilities from humans without bypassing operator approval &mdash;
  same artifact, different bearer. Mock bootloader verifies JWT
  signatures (manual JWS verification in pure stdlib + cryptography,
  EdDSA + ES256 dispatch, aud + exp claim checks) and tracks issued
  JWTs in an operator-UI panel. TLS cert pinning (`IPinningService`,
  `CertPinHelpers.ComputeSpkiPin`, `ConfigurePrimaryHttpMessageHandler`
  callback) closes the LAN-bootloader security gap via SPKI-pin
  trust-on-first-use; pin captured at pairing, persisted in
  PairingState, restored at app start, cleared on unpair.
- ✓ Round 7 -- **Phone management + lost-phone recovery + UX polish.**
  Three new bootloader endpoints (GET `/v0.4/manage/phones`, GET
  `/v0.4/manage/revoke_challenge`, POST `/v0.4/manage/revoke`)
  + matching IBootloaderClient methods. Phone-id dedup on re-pair
  (replace-in-place). Home.razor Paired card grew a "Registered
  phones" section with per-phone Revoke button (browser confirm
  dialog -> biometric prompt -> sign challenge -> POST -> refresh).
  TOTP clipboard copy via navigator.clipboard.writeText with visual
  "&#10003; Copied" feedback for 2 s. Mock bootloader recovery
  endpoints with proper challenge-bound signature verification per
  algorithm. Now the operator can drive the lost-phone recovery flow
  from the surviving phone's UI, no shell access required.
  **Validated on real Pixel 10 (Android 16) alongside Windows MAUI**
  -- two phones registered against one bootloader, all four pending-
  request kinds verified end-to-end on the Pixel with biometric
  prompting per crypto operation (single_sign, totp_provision,
  totp_generate code 288319 matching expected, session_issuance
  24h JWT signed + verified). Surfaced two AndroidKeyStore footguns
  fixed in the same batch: `Xamarin.AndroidX.Biometric` version pin
  (1.2.0.13 didn't exist -- correct latest is 1.1.0.32) and
  `UserNotAuthenticatedException` on `Signature.initSign` for keys
  with `setUserAuthenticationRequired(true)` -- fixed via per-use
  auth (`setUserAuthenticationParameters(0, ...)`) +
  `BiometricPrompt.authenticate(promptInfo,
  CryptoObject(signature))` driving a TaskCompletionSource. Both
  banked as CLAUDE.md gotchas. v1-grade security model proven on
  commodity Android 16 hardware.

- ✓ Round 8 -- **v1-readiness sprint.** All five v1-blocker items
  shipped same-day. (a) **HTTPS-capable mock bootloader** with
  ephemeral self-signed ECDSA P-256 cert generated at startup;
  companion fix to `PinningService.Validate` that accepts any cert
  during the pre-pairing TOFU window so the very first connection
  to a self-signed bootloader can complete and capture the pin.
  (b) **Recto branding text-mark placeholder** -- indigo `#1E1B4B`
  vault color, white path-based "R" glyph + "RECTO" wordmark,
  replacing the .NET-default scaffolding assets. (c) **Phone-side
  unit tests** in a new Recto.Shared.Tests xUnit project (~30
  tests across 5 files) pinning TotpCodeCalculator against RFC
  6238 reference vectors, PinningService against TOFU + locked-pin
  behavior, EcdsaSignatureFormat, CapabilityJwtBuilder, and
  BootloaderClient + WebAuthnAssertionBuilder. (d) **WebAuthn /
  passkey browser-login bridge** -- new `webauthn_assert`
  PendingRequest kind, `WebAuthnAssertionBuilder` produces a
  conformant clientDataJSON + authenticatorData + signature that
  any FIDO2 / RFC 8809 relying party can verify; mock bootloader
  stands in as the RP with a `demo.recto.example` fixture and
  verifies with the same math a production Keycloak adapter would
  run. Foundation for the v0.5+ Keycloak-replacement integration.
  (e) **Push notifications scaffolding** -- IPushTokenService with
  Android (FCM via Xamarin.Firebase.Messaging 125.0.1.2), iOS
  (UNUserNotificationCenter + APNs device-token), and no-op
  (Windows / the macOS host Catalyst dev) impls. RegistrationRequest carries
  push_token + push_platform; bootloader stores per-phone, exposes
  `POST /v0.4/manage/push_token` for rotation, calls a `send_push
  _wakeup` stub after every queue handler logging
  "[push] would send {platform} wakeup to {token-prefix}...". iOS
  Entitlements.plist + AndroidManifest POST_NOTIFICATIONS wired.
  Bundle ID flipped from .NET-template `com.companyname.Recto` to
  `app.recto.phone` for cert ceremony alignment. Apple Developer
  Program + Firebase Console walkthroughs in dev-tools/README.md.
  Real APNs HTTP/2 + FCM v1 HTTP senders are v0.4.1 follow-up
  behind the existing seam; phone-side code is final.

- ✓ v0.4.1 -- **v1-completion sprint** (same-day follow-on to round 8,
  2026-04-26). Eight items shipped: real APNs HTTP/2 + FCM v1 HTTP
  senders behind the existing send_push_wakeup seam (OAuth2 access
  token caching for FCM, ES256 provider JWT for APNs with raw R||S
  conversion, httpx for HTTP/2); per-phone audit log on the
  bootloader (cap 500 events) + GetAuditLogAsync on
  IBootloaderClient + AuditLogResponse / AuditEvent DTOs; phone-side
  Settings page (polling interval, audit history limit, theme,
  Unpair-all emergency wipe) backed by IUserPreferencesService;
  UX polish on Home.razor (friendly polling-error banner with retry,
  All-caught-up empty state); WebAuthn browser demo page at
  /demo/webauthn with full RP-bootloader-phone flow; composite
  enclave fallback decorator (off by default, enables graceful
  degradation when hardware enclave fails); PKCS#11 + PGP credential
  kinds (protocol seam + phone-side UI; real bootloader-side
  PKCS#11 module / gpg-agent integration is v0.5+).

## v0.5 — "First public launch"

**Target:** when the phone app clears App Store + Google Play review.
The first version with multi-user account abstractions and an
out-of-the-box pairing flow that doesn't require a sideloaded APK
or a TestFlight invite. v0.5 is also the version that pairs with the
**fresh-repo cutover** (operator decision 2026-04-27).

**Fresh-repo cutover plan:**

1. The current GitHub repo's history accumulated cruft from the
   substrate-v0.4 development sprint (initial commit churn, leak
   audits, naming churn around persona / AI-handle conventions).
   Rather than carry that history forward, the repo gets deleted and
   recreated with v0.5 as the **first commit**.
2. v0.5 first commit = the working tree at the moment App Store +
   Play Store both have approved builds in flight. Includes the full
   `recto/` Python package, the `phone/RectoMAUIBlazor/` MAUI tree,
   `docs/`, `examples/`, and the public memory files
   (CLAUDE.md / ARCHITECTURE.md / ROADMAP.md / CHANGELOG.md / README.md).
3. CHANGELOG.md gets a single rolled-up "v0.1 through v0.4.1" entry
   summarizing the substrate phases (instead of the per-sprint blow-by-
   blow that lives in current CHANGELOG.md). The detailed history is
   archived in the operator's private memo for posterity.
4. Re-mint all secrets that touched the old repo's history during
   development (any PAT used for autonomous push, any service token
   pasted into chat, any ephemeral test key). Hard rule #2 already
   keeps real production secrets out of the tree, but the cutover is
   a natural moment to rotate anything that *might* have been exposed
   via clipboard / chat-history surface area.
5. Re-register the GitHub Actions runners against the new repo URL
   (registration tokens are repo-scoped — old tokens won't work).

**Scope (post-cutover):**

- Multi-user account abstractions in the phone app: pairing without
  a manually-issued challenge code (instead, claim-by-QR-code or
  email-magic-link onboarding).
- Phone app published to App Store + Google Play (not just TestFlight
  / APK sideload). Reader-app-style review compliance: the binary is
  a credential vault that holds keys created elsewhere; no in-app
  monetization, no payment surface.
- Bootloader's CA-signed cert path (Let's Encrypt automation) becomes
  the documented production deploy. Self-signed `--tls` mode stays as
  the dev iteration path.
- Universal vault matures: TOTP / WebAuthn / PKCS#11 / PGP all
  bootloader-side reference implementations (vs. v0.4.1's protocol-seam
  + phone-side scaffolding only).
- Operator-onboarding docs: `docs/onboarding.md` walks a new operator
  through "from clean Windows host to first paired phone in 15
  minutes" without requiring Recto-internals knowledge.

**Why a fresh repo and not `git rebase --orphan`:**

- The current repo's commit graph contains experimental commits, leak
  audits, and naming churn that are not useful for downstream forkers.
- A clean v0.5-first-commit repo gives anyone forking the project an
  instantly-readable history starting from a coherent product, not
  starting from an early-substrate moment that requires context to
  interpret.
- Re-registering the runner / re-minting any per-repo tokens is a
  small one-time cost paid once at cutover.

Future rounds (v0.5+ / v1+):

- **Production cert architecture for the bootloader** (v1 launch) --
  decided 2026-04-26: **Let's Encrypt CA-signed cert + SPKI pinning**
  (the Signal / WhatsApp model), NOT pure self-signed-with-pin.
  Operators with existing Cloudflare Tunnel + Let's Encrypt automation
  for other services adopt the same pattern for Recto bootloaders at
  near-zero marginal cost. Browser access to the bootloader's operator
  UI works without "Not secure" warnings; AI agents using stock HTTP
  libraries (httpx / fetch / reqwest) connect cleanly without
  per-runtime custom-pinning code; phone-side SPKI pinning rides on top
  as defense-in-depth (CA compromise -> cert rotation -> SPKI mismatch
  -> fail closed). Self-signed `--tls` mode stays in place for dev
  iteration; production deployment uses CA-signed via a tunnel.
- **v0.6: ETH / blockchain credential kinds** -- positions Recto as
  the universal vault for Web2 AND Web3. Substrate already supports
  it conceptually (phone enclave + biometric IS the right hardware-
  wallet primitive; capability JWT framework IS the right delegation
  primitive for AI crypto agents). Scope:
  - New `eth_sign_message` PendingRequest.kind (EIP-191) -- simplest,
    do first; arbitrary-message signing for off-chain auth.
  - New `eth_sign_typed_data` (EIP-712) -- structured-data display
    so the operator sees "you're approving unlimited USDC spend to
    contract X" rather than opaque bytes. EIP-712 is the #1 phishing
    vector in crypto today; getting the display right is the most
    security-critical part.
  - New `eth_sign_transaction` (EIP-1559 + legacy) -- with recipient
    address + amount + gas estimation + ENS resolution for
    human-readable display.
  - secp256k1 software-resident key, envelope-encrypted by the
    existing enclave P-256 key. Both iOS Secure Enclave and Android
    StrongBox are P-256-only natively; secp256k1 (ETH's curve) needs
    software-backed signing via BouncyCastle. Standard mobile-wallet
    pattern; trade-off documented (slightly weaker than pure-enclave
    P-256 keys, but still gated by phone-resident biometric).
  - ENS resolution comes for free once ETH signing works -- ENS is
    just contract calls. The operator's ENS (e.g. `yourname.eth`)
    becomes a phone-protected identity alongside Keycloak login + TOTP
    + SSH + PGP -- single biometric tap, scoped to whatever's being
    signed, audit-logged.
- **v0.7: AI crypto-agent capability extensions** -- the strategic
  wedge that makes Recto+ETH unique. Today's crypto AI agents have
  full key access (catastrophic) or no key access (can't transact).
  Scoped capability JWTs are the missing primitive:
  - Per-address allowlists in capability scope (agent can sign tx
    only to addresses on this list).
  - Per-amount caps (agent can sign tx up to 0.1 ETH per call).
  - Per-time-window caps (agent's capability expires in 24h, max 50
    uses).
  - "Submit-for-review" capabilities (agent can prepare and submit a
    tx but can't sign without explicit operator approval -- useful
    for high-value-transaction proposers).
- **Multi-chain commitment (v0.6 -> v0.9 sprints).** v0.6 designs for
  chain extensibility from day one rather than baking ETH-specific
  assumptions into the wire protocol; new chains slot in as additional
  `PendingRequest.kind` values without re-shaping anything that
  shipped before. The "major 5" starting line covers the dominant
  ecosystems with five focused sprints:
  1. **Ethereum + EVM family (v0.6)** -- ETH, Polygon, Arbitrum,
     Optimism, Base, BNB Chain, Avalanche C-Chain, etc. share signing
     impl + transaction format and differ only by chain ID. One
     sprint covers the entire EVM ecosystem; per-chain config (RPC
     endpoint, chain ID, gas estimation source, ENS support y/n) is
     YAML-driven.
  2. **Bitcoin (v0.7)** -- secp256k1 like ETH but completely different
     UTXO transaction model. Standalone sprint. Critical for the
     institutional / cold-storage user segment.
  3. **Solana (v0.7)** -- Ed25519 (enclave-native on Android, software
     fallback on iOS via existing BouncyCastle path), separate
     transaction shape, separate program-call decoding.
  4. **Cosmos SDK family (v0.8)** -- Cosmos Hub, Osmosis, Juno, Akash,
     Celestia, dYdX, etc. share secp256k1 + Cosmos SDK transaction
     format with per-chain config. Like EVM, one sprint covers the
     entire IBC ecosystem.
  5. **Polkadot / Substrate family (v0.8)** -- sr25519 (Schnorr-based,
     not natively supported by either enclave platform; software-only
     via schnorrkel). Covers Polkadot, Kusama, Acala, Moonbeam, etc.

  Major 20 (v0.9+, gradual rollout): Tron, Cardano, Ripple/XRP,
  Stellar, NEAR, Aptos, Sui, Hedera, Algorand, Tezos, Filecoin,
  Litecoin, Bitcoin Cash, Dogecoin, Zcash, Monero, ICP, plus any
  emerging L1s the market validates between v0.8 and the long-tail
  rollout. Each is a focused sprint at v0.9-pace cadence (one chain
  per 1-2 weeks) once the core extensibility framework is proven on
  the major 5.

  **Architectural principle**: chains are pluggable backends behind
  a `IBlockchainSigner` interface analogous to `IEnclaveKeyService`.
  Each backend declares its sig algorithm, transaction format,
  address derivation, and operator-display formatter. New chains
  ship without touching the bootloader's pending-request dispatcher
  or the phone's enclave path -- pure extension via the seam.
- **Hardware-attested agent identity** -- TPM / YubiKey / cloud-HSM-
  backed agent keys for agents whose host integrity matters (CI
  runners, cloud-hosted agents). Operator pre-approves the agent's
  public key during a one-time onboarding ceremony.

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
