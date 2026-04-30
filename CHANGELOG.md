# Changelog

All notable changes to Recto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Recto adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Polish — Mock bootloader operator UI front-end design closed (2026-04-30)

After Wave 9 part 2 landed and the test device smoke validated all 20
coin / credential types end-to-end, the operator UI's layout was
revisited and closed out as a stable design point. Five distinct polish
commits sequenced through the day:

1. **EVM chain selector** for the three ETH queue endpoints (mainnet /
   Base / Polygon / Arbitrum / Optimism / BNB / Avalanche + 2 testnets),
   replacing the hardcoded "Base 8453" default. `localStorage`
   persistence so the operator's chain pick survives the 3s
   auto-refresh.
2. **`_rectoChainRestored` flag** to scope the localStorage restore to
   page-load only -- earlier version restored on every onchange and
   snapped the dropdown back when the operator picked a different
   chain.
3. **Operator-UI section boxes** -- two tinted panels (`Identity &
   Access` and `Crypto Tokens`) grouping the 14 queue buttons into
   findable categories. Taller buttons, gap spacing.
4. **2x2 top grid** -- `Bootloader info` / `Pairing codes` /
   `Registered phones` / `Pending requests` arranged as a fixed grid
   so the page never re-flows when content lengths change. Per-panel
   `overflow-y: auto` keeps the grid stable.
5. **Layout flip** (this commit) -- Recent responses + Recent requests
   each promoted to full-width `log-panel-wide` (22rem fixed height),
   while Provisioned TOTP aliases + Issued JWT capabilities moved into
   a 2-column `log-grid` (14rem fixed height). Smoke-test discovery:
   recents entries are multi-line (timestamp + verb + recovered address
   + full rsv hex) and want horizontal width; TOTP/JWT entries are 1-2
   lines and fit comfortably in narrow columns.

Smart-skip auto-refresh logic remains -- the 3s reload still drives
"something just landed in the queue" feedback, but skips when the
active element is a SELECT / INPUT / TEXTAREA or when any non-empty
text selection is active, so dropdown picks and copy/paste workflows
aren't kicked.

Design captured in ARCHITECTURE.md's 2026-04-30 entry. Future coin/
credential additions slot into the existing structure (button into
the matching section box, render arm into the Pending Requests panel,
response row into Recent Responses) without further layout work.

### Added — Wave 9 part 2: TRON C# phone-side (2026-04-30)

Closes the loop on Wave 9. Wave 9 part 1 (Python verifier + protocol
DTOs + mock-bootloader) shipped earlier today; this commit ships the
phone-side C# implementation that produces a TIP-191 signature the
Wave 9 part 1 verifier accepts.

**Coverage**: 20/21 target coins now have phone-side signing AND
Python-side verification. Smoke validation against the test device
pending; mock-bootloader operator-UI already shows the queued
`tron_sign` request correctly (proves Wave 9 part 1's
`PendingRequestContext` emit is right -- just had no render arm
for it before this commit).

**Architecture**: TRON shares secp256k1 + Keccak-256 with Ethereum
byte-for-byte. The C# implementation reuses
`EthSigningOps.SignWithRecovery` + `EthSigningOps.Keccak256` directly;
net-new is the TIP-191 preamble (`"TRON Signed Message:\n"` instead
of EIP-191's `"Ethereum Signed Message:\n"`) and the base58check
address encoding with version byte 0x41. Same one-mnemonic-shared-
across-services posture as ETH/BTC/ED -- the new
`MauiTronSignService` reads the same SecureStorage entry
(`recto.phone.eth.mnemonic.{alias}`) those services already
provision. One mnemonic, nine chain trees now: ETH, BTC, LTC, DOGE,
BCH, SOL, XLM, XRP, TRON.

**Wave 9 part 2 deliverables**:

- `Recto.Shared/Services/TronSigningOps.cs` -- TIP-191 hash with the
  load-bearing leading 0x19 byte, base58check encoder (Bitcoin
  alphabet + double-SHA-256 checksum), TRON address derivation
  from 64-byte uncompressed pubkey, sign + recover delegating to
  `EthSigningOps`. Pure BouncyCastle / SHA-256 math; no platform-
  specific code.
- `Recto.Shared/Services/ITronSignService.cs` -- five-method
  interface (EnsureMnemonicAsync / GetAccountAsync / ExistsAsync /
  SignMessageAsync / ClearAsync) mirroring `IEthSignService`'s
  message_signing subset. Transaction signing reserved for a
  follow-up wave.
- `Recto.Shared/Models/TronAccount.cs` -- value object with
  `DerivationPath` + `Address` (T-prefixed 34-char base58check).
- `Recto/Services/MauiTronSignService.cs` -- SecureStorage-backed
  orchestrator. Mirrors `MauiEthSignService` shape; reads the
  shared mnemonic, derives at `m/44'/195'/0'/0/N` via existing
  `Bip32`, signs via `TronSigningOps.SignWithRecovery`. Wipes seed
  + leaf private key + chain code in `finally` blocks.
- `Recto.Shared/Protocol/V04/PendingRequest.cs` --
  `PendingRequestKind.TronSign` constant, `TronMessageKind` enum
  (MessageSigning / Transaction-reserved), `TronNetwork` enum
  (Mainnet / Shasta / Nile).
- `Recto.Shared/Protocol/V04/PendingRequestContext.cs` -- six new
  optional `tron_*` fields mirroring the Python state.py shape.
- `Recto.Shared/Protocol/V04/RespondRequest.cs` -- new
  `TronSignatureRsv` field for the 65-byte r||s||v hex.
- `Recto.Shared/Pages/Home.razor` -- TRON render arm in the
  Pending Requests switch (red TRX badge, network label, derivation
  path, pre-derived address, message text), `ApproveTronSignAsync`
  dispatcher producing the dual signature (TIP-191 r||s||v + Ed25519
  envelope), `PopulateTronAddressesAsync` hooked into
  `RefreshPendingAsync`, helper labels (`_tronMessageKindLabel`,
  `_tronNetworkLabel`), `IsTokenSigningKind` extended.
- `Recto.Shared/wwwroot/app.css` + `Recto.Shared/Pages/Home.razor.css`
  -- new `--rec-coin-tron` CSS variable (Tronix-red `#ec0a1e`) and
  `.rec-coin-badge-tron` class.
- `Recto/MauiProgram.cs` -- DI registration for
  `ITronSignService` -> `MauiTronSignService` as a cross-platform
  singleton.
- `Recto.Shared.Tests/TronSigningOpsTests.cs` -- 11 tests pinning
  the canonical generator-G TRON address against the same Wave 9
  part 1 vector
  (`TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC`), confirming the 20-byte
  hash160-equivalent matches Ethereum's address bytes for the same
  pubkey, validating the TIP-191 length-byte ASCII-decimal
  encoding, distinctness vs EIP-191, sign-then-recover round-trip.

**Validated 2026-04-30**: rebuild + redeploy + smoke against the
test device landed clean. Phone displayed the TRON request with
red TRX badge, mainnet network, derivation path `m/44'/195'/0'/0/0`,
derived address `TVm1H9XYdGKGnT5goozq3moyXmZtRgwtrJ`, and the
TIP-191 message text. Approve produced a 65-byte r||s||v signature;
the mock bootloader recovered the signer address from the rsv and
matched the phone-derived address byte-for-byte. Green "verified"
pill, no amber warning. POST /v0.4/respond returned 200. Coverage
20/21 (95.2%) hardware-proven end-to-end on the test device.
Cardano (ADA) is the only remaining target coin; ships in Wave 10
when its custom SLIP-23 / CIP-1852 derivation lands.

**Hotfix shipped same-day**: first iPhone smoke surfaced an
UnboundLocalError in the mock bootloader's tron_sign envelope-
verify branch -- referenced `target_phone` (queue-handler-only
variable) instead of `phone` (respond-handler scope). Caught by my
own try/except, surfaced as "HTTP 400: envelope verify failed:
local variable 'target_phone' referenced before assignment" on the
phone. Bootloader log was silent because the broken catch
swallowed the exception before it could reach stderr. Fix aligned
the branch with the canonical eth_sign envelope-verify pattern;
the broken catch-all was removed, so future tron-branch exceptions
now bubble up to BaseHTTPRequestHandler's default exception
handler (which writes tracebacks to stderr ->
`~/recto-bootloader.log`). After the hotfix, smoke ran clean.

**Full coin family hardware-proven same-session**: post-Wave-9
smoke ran every card type end-to-end on the test device in a
single ~60-second sweep, all approvals returning verified pills:
TRON / XRP / XLM / SOL / BCH / DOGE / LTC / BTC / ETH transaction
(EIP-1559) / ETH typed_data (EIP-712). Same paired phone, same
BIP-39 mnemonic, all derived addresses matched their expected
forms. Wave 6 + 7 + 8 + 9 all hardware-proven simultaneously --
the Wave-7-retroactive BIP-137 header-byte fix (permanent fix
for BCH/DOGE legacy P2PKH recovery) survived a clean rebuild
cycle.

**Known issue (non-blocking, banked for next session)**:
immediately after the ETH typed_data (EIP-712) approval -- which
ITSELF succeeded with a verified pill and correct recovered
address -- the phone self-unpaired and reverted to the "Not paired
yet" screen. VS console showed
`System.Threading.Tasks.TaskCanceledException` on the next GET
/v0.4/pending poll, immediately followed by `.NET TP Worker`
exiting. Two leading hypotheses for next-session investigation:
(a) post-approve render path triggers a component dispose that
cancels the polling loop's CancellationToken, and some error path
in the polling-loop catch interprets cancellation as "phone has
been revoked, clear local state"; (b) `ApproveEthTypedDataAsync`
has a kind-specific cleanup branch that wrongly clears pairing
state on some condition I can't see without more logs. Either way
it's a phone-side bug (the underlying signature flow is provably
correct since the bootloader recorded the verified response before
the unpair fired). Doesn't affect any other card type; phone
re-pairs and continues working normally after restart.

### Added — Wave 9 part 1: TRON verifier + protocol DTOs (2026-04-30)

Sister implementation of Wave 6 (ETH) and Wave 7 (BTC family) for
the TRON chain. Reuses the secp256k1 + Keccak-256 primitives from
`recto.ethereum` directly; net-new is the address encoding
(base58check with version byte 0x41 producing T-prefixed 34-char
addresses) and the signed-message preamble (TIP-191's
`"TRON Signed Message:\n"` instead of EIP-191's
`"Ethereum Signed Message:\n"`).

**Coverage**: brings the supported-coin list to 20 of 21 target
coins (95.2%) at the protocol layer. Wave 9 part 2 (C# phone-side)
closes the loop end-to-end on the test device.

**Architecture**: one BIP-39 mnemonic per phone (shared with the
existing `MauiEthSignService`, `MauiBtcSignService`, and
`MauiEd25519ChainSignService`), one new BIP-32 secp256k1 tree at
the standard SLIP-0044 coin-type 195: `m/44'/195'/0'/0/N`. Same
backup ceremony continues to cover all six coin families now (ETH,
BTC, LTC, DOGE, BCH, SOL, XLM, XRP, TRON). 24 words, nine chain
trees.

**Wave 9 part 1 deliverables**:

- `recto.tron` Python module (~280 lines) -- TIP-191 hash with the
  load-bearing leading 0x19 byte, base58check encode + decode,
  address derivation from 64-byte uncompressed pubkey
  (`base58check(0x41 || keccak256(pubkey64)[-20:])`), recover-
  public-key + recover-address (delegates secp256k1 math to
  `recto.ethereum`), `verify_signature` round-trip helper,
  `address_to_hex` for cross-checking against blockchain explorers
  + dev debugging.
- `recto[tron]` extra in `pyproject.toml` (empty list -- gates the
  import path; `cryptography` is pulled transitively via
  `recto[v0_4]` if/when consumers want the verify path).
- `PendingRequest.new_tron(...)` constructor in
  `recto.bootloader.state` with construction-time validation
  matching Wave 7's `new_btc` pattern. Six new optional
  `tron_*` fields on the `PendingRequest` dataclass. Refuses
  `tron_message_kind="transaction"` for the moment -- TRON's
  protobuf-serialized `Transaction` parser isn't shipped yet;
  reserved here so a future phone impl enables it without
  protocol drift.
- `_pending_to_wire` emits `tron_*` fields when
  `kind == "tron_sign"` (omitted otherwise -- regression test
  pins this).
- `_handle_respond` structure-checks `tron_signature_rsv` (130 hex
  chars after optional 0x prefix; valid hex). `_notify_resolved`
  extends with `tron_signature_rsv: str | None = None` and a new
  TypeError-fallback tier so older `notify_fn` callbacks that
  pre-date Wave 9 keep working.
- `phone/RectoMAUIBlazor/dev-tools/mock-bootloader.py`:
  - new `/_queue_tron_message_sign` endpoint handler that mints a
    TRON login-style message and queues a `tron_sign`
    `PendingRequest` with the placeholder `T...` address (real
    phone-derived address overrides on respond);
  - "Queue TRON message_sign" operator-UI button on the index
    page (mirrors the existing per-coin button row);
  - TRON branch in `_handle_respond` validating the rsv shape and
    surfacing `tron_signature_rsv` + `tron_recovered_address` to
    the responses panel;
  - recent-responses display branch rendering the TRON row with
    network label, signature short-form, recovered address, and
    full rsv breakdown;
  - placeholder-address suppression so test queues with the
    `TPlaceholder...` sentinel don't flag amber "differs from
    expected" on a successful round-trip.
- 22 new tests in `tests/test_tron.py` -- pin TIP-191 hash against
  a known reference value, pin the secp256k1 generator point G's
  TRON address (`TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC`, mechanically
  derived from G's uncompressed pubkey via the same 20-byte ETH-
  equivalent prefixed with 0x41 and base58check'd), exercise sign-
  then-verify round-trips, distinctness vs EIP-191 and bare keccak.
  All 22 pass locally.
- ~25 new tests in `tests/test_bootloader_tron.py` -- construction
  validation, `_pending_to_wire` emit-only-when-tron, end-to-end
  live HTTP good-envelope/denied/missing-rsv/wrong-length/non-hex/
  forged-envelope/non-tron-regression coverage. (Exercise pending
  on Windows-side pytest -- the sandbox FUSE-mount-lag gotcha
  prevents reliable in-sandbox runs after edits to `state.py` /
  `server.py`.)

**Wave 9 part 2 (next)**: C# phone-side. Mirrors Wave 6 (ETH C#)
shape closely since TRON shares ETH's secp256k1 + Keccak primitive.
Net-new: `Recto.Shared/Services/TronSigningOps.cs` (TIP-191 hash,
base58check encoder, recover-id discovery), `MauiTronSignService`
SecureStorage-backed orchestrator at `m/44'/195'/0'/0/0`,
`Home.razor` render arm + ApproveTronSignAsync dispatcher, per-
coin badge color in `app.css`. Same one-mnemonic-shared-across-
services posture as the existing six chains.

### Fixed — BIP-137 header byte now dispatches on coin (Wave-7 retroactive, 2026-04-30)

Smoke test of all 16 credential kinds on the test device (running
iOS 17.x, against the mock bootloader on the macOS host) surfaced
three operator-UI warnings. All chain signatures verified green;
the warnings were verifier-side display issues that did NOT
indicate a crypto regression.

**Bug 1 (real, phone-side)**: BCH and DOGE message_sign approvals
showed `address recovery failed: <coin> does not support native
SegWit (P2WPKH); use kind='p2pkh' instead` next to a green
"chain sig verified" pill. Root cause: `BtcSigningOps.SignCompactBip137`
in `Recto.Shared` hardcoded the BIP-137 compact-sig header byte to
`27 + 12 + recId = 39..42` (P2WPKH range) regardless of coin. The
verifier (`recto.bitcoin.recover_address(coin=...)`) parses the
header byte to decide what address shape to encode the recovered
hash160 as, then tries to encode bech32 -- which fails for DOGE and
BCH because those coins' `bech32_hrp_mainnet` is `None`. BTC + LTC
worked because both have native SegWit; DOGE + BCH require P2PKH
compressed (header range 31..34). Wave-7 added LTC + DOGE + BCH on
top of BTC by sharing the secp256k1 primitive across the family
and dispatching the preamble per coin -- the sprint's audit caught
the preamble layer but missed the BIP-137 header-byte layer.

**Fix**: thread `coin` through `SignCompactBip137(msgHash,
privateKey, coin = "btc")`, look up `GetCoinConfig(coin).DefaultAddressKind`,
map address kind to header offset
(`p2pkh-uncompressed`=0, `p2pkh`=4, `p2sh-p2wpkh`=8, `p2wpkh`=12),
emit `header = 27 + offset + recId`. `MauiBtcSignService` passes
the coin discriminator through; misleading "header byte is
coin-agnostic" comment replaced with a comment documenting the
two-layer dispatch (preamble + header byte) and pointing at the
new gotcha entry in CLAUDE.md.

**Bug 2 (cosmetic, mock-bootloader-side)**: SOL message_sign
approvals showed `differs from expected 11111...1112` even though
the recovered address was correct for the operator's mnemonic at
`m/44'/501'/0'/0'`. Root cause: `mock-bootloader.py`'s placeholder-
prefix tuple (`_handle_respond` in `ed_sign` branch) had a 32-ones
literal `"11111111111111111111111111111111"` for SOL, but the queue
default uses the System Program pubkey `"11111111111111111111111111111112"`
(31 ones + a `2`). `startswith()` returned False because char 32
is `2` not `1`, so the placeholder-suppression branch never fired.

**Fix**: shorten the SOL prefix to 24 ones, matching both the
"32-ones" and "31-ones-and-a-2" forms. Any real ed25519 pubkey is
high-entropy enough to never collide with a 24-ones run.

**Tests**: new `[Theory]` `SignCompactBip137_HeaderByteDispatchesOnCoin`
in `BtcSigningOpsTests` pins per-coin header-byte ranges (BTC + LTC
expect 39/40, DOGE + BCH expect 31/32) so the next "share the
primitive across coins" sprint has a unit-test canary for this
class of bug. Companion `SignCompactBip137_UnknownCoinThrows` pins
the rejection path. Original `SignCompactBip137_ReturnsP2wpkhHeaderInRange`
keeps its original assertion (BTC default).

**Files**: `Recto.Shared/Services/BtcSigningOps.cs`,
`Recto/Services/MauiBtcSignService.cs`,
`Recto.Shared.Tests/BtcSigningOpsTests.cs`,
`dev-tools/mock-bootloader.py`. CLAUDE.md gains a new gotcha entry
("BIP-137 header byte must dispatch on coin").

**Validated 2026-04-30**: re-deploy + re-smoke on the test device
landed all three fixes clean. 16/16 cards approved end-to-end, no
regressions on the previously-passing 13.

- **BCH** now shows `recovered 1LKbeiS7Qy1ESNL8TJYeCr5GmsnidiYhAj`
  (proper legacy P2PKH form, BCH `version_byte_p2pkh = 0x00` base58s
  to a `1...` prefix). Previous "address recovery failed: Bitcoin
  Cash does not support native SegWit" error gone.
- **DOGE** now shows `recovered D6AZoodY7vmqzJnACqUmJvYKLUA9GkWrCT`
  (proper Dogecoin P2PKH form, DOGE `version_byte_p2pkh = 0x1E`
  base58s to a `D...` prefix). Previous "Dogecoin does not support
  native SegWit" error gone.
- **SOL** now shows just `(chain sig verified) -- verified` with
  no amber "differs from expected" warning. Derived address
  `Bqg5MhnrrSAgEBE4yM4sEyag6KDm8FqWbrWgtt78SboA` matches the
  operator's mnemonic at `m/44'/501'/0'/0'`.

Closes Wave-7-retroactive. Also closes the iPhone-smoke half of
Wave 8's remaining validation -- SOL/XLM/XRP rows are now hardware-
proven on the test device. Cross-wallet interop pinning
(SOL/Phantom, XLM/Stellar Lab, XRP/Xumm) remains the only thing
gating full Wave 8 closure.

### Validated — First real-iPhone deploy + Secure Enclave smoke tests (2026-04-29)

First time the v0.5+ iOS Secure-Enclave code paths ran against real
hardware. Closes the "real-iPhone deploy validation" gate that was
the last open item in the macOS-side pivot before Wave 8.

**Test device.** the test device (UDID-registered in the developer
provisioning profile) running iOS 17.x, deployed via
`dotnet publish -f net10.0-ios -c Release -r ios-arm64` +
`xcrun devicectl device install` from a the macOS host mini build host under
an Apple Developer Program account (Team ID-bound certs +
provisioning profile). The original plan was an a legacy iPhone capped
at iOS 15.x; pivoted to the test device when that turned out to be
the available unit. `Recto.csproj`'s
`SupportedOSPlatformVersion=15.0` continues to work — the iOS-17
device is well above the floor.

**Secure Enclave path active.** Pairing screen reported
`signing algorithm: ecdsa-p256`, confirming the iOS
`IosSecureEnclaveKeyService` (P-256 keypair via
`kSecAttrTokenIDSecureEnclave`, ACL =
`BiometryCurrentSet | PrivateKeyUsage`, DER-to-raw signature
conversion via `EcdsaSignatureFormat.DerToRaw`) was driving the
sign path — NOT the cross-platform software fallback.

**All five coin families approved end-to-end.** Across multiple
mock-bootloader queue/approve cycles:
- ed25519 envelope (`single_sign`, `webauthn_assert`,
  `pkcs11_sign`, `pgp_sign` — all share the IEnclaveKeyService
  signing path)
- secp256k1 + EIP-191 personal_sign (Ethereum / EVM-family)
- secp256k1 + BIP-137 compact-sig message_sign across BTC + LTC
  + DOGE + BCH (Bitcoin family with per-coin preamble dispatch)

Every approval round-tripped through the comms layer back to the
mock bootloader, which recovered the signer address from the rsv
or compact-sig and reported ✓.

**UI rendered correctly on iOS WKWebView.** Wave-7's dark vault
aesthetic — `:root` design tokens (`--rec-bg #0d1117`,
`--rec-accent #d4a554` vault gold, per-coin `--rec-coin-*`),
IDENTITY & ACCESS / CRYPTO TOKENS section split, slim 2.75rem
topbar carrying brand mark + settings gear — all held up on iOS
without platform-specific layout regressions.

**Architectural bet validated.** Phone-resident vault, agent-cap
delegation by JWT, Secure Enclave as root of trust, one BIP-39
mnemonic deriving five coin trees — the shape works on real
hardware. **Wave 8 unblocked** (TRON + XRP + SOL + XLM → 20 of
21 coins covered).

**Banked gotchas** (full text in `Recto/CLAUDE.md` Gotchas index +
`phone/RectoMAUIBlazor/CLAUDE.md` Enclave / cryptography section):
- `OSStatus -25293 errSecAuthFailed` on Secure Enclave keygen →
  device needs both a passcode AND an enrolled biometric;
  `BiometryCurrentSet` ACL can't evaluate without one. Canonical
  first-iPhone-deploy stumble; can be misdiagnosed as a transport
  / TLS / pairing-code issue because the error fires before any
  network call. Open code-side TODO: translate raw OSStatus into
  operator-readable copy in `IosSecureEnclaveKeyService.cs`.
- iCloud account on the iPhone is fully independent of the
  Apple Developer Program account on the build host — no need
  to wipe a borrowed test device "to use the developer's iCloud."
  Activation Lock makes wipes risky on shared-ownership devices.

**TLS path validation deferred.** Cleartext smoke tests proved
every signature path works end-to-end against the LAN-bound
mock bootloader (NSAllowsLocalNetworking exempts the local LAN range from
ATS). Mock-self-signed-cert TLS adds cert-trust-on-iPhone friction
without exercising any new code in the phone-side crypto, the
verifier, or the comms protocol. Real TLS validation lands when
Recto deploys behind a real Cloudflare Tunnel cert (which iOS
already trusts by default).

### Added — Wave 7: Bitcoin family (LTC + DOGE + BCH) end-to-end (2026-04-29)

Extends the `btc_sign` credential kind from "Bitcoin only" to the
full Bitcoin family of four coins via a single coin-discriminator
field. Same crypto primitives across the family (secp256k1,
double-SHA-256, BIP-137 compact signatures, HASH160); per-coin
differences (preamble, address-format version bytes, bech32 HRP,
BIP-44 coin type, default address kind) live in a single COIN_CONFIG
table that mirrors between Python's `recto.bitcoin` and C#'s
`BtcSigningOps`. Adding a fifth coin = one entry in each table
plus a test vector. No new credential kinds, no new RFC fields
beyond the optional `btc_coin` discriminator, no breaking changes
to v0.5 phones (absent / null `btc_coin` defaults to "btc").

**Coverage unlocked.** Three more of the user's top-21 target
coins activated:
- **LTC (Litecoin)** — `m/84'/2'/0'/0/N` native SegWit P2WPKH
  (`ltc1q...`) with HRP `ltc`. Litecoin Signed Message preamble.
- **DOGE (Dogecoin)** — `m/44'/3'/0'/0/N` legacy P2PKH (`D...`,
  version byte 0x1E). Dogecoin Signed Message preamble. No
  native SegWit.
- **BCH (Bitcoin Cash)** — `m/44'/145'/0'/0/N` legacy P2PKH
  (`1...`, version byte 0x00 — same as BTC's legacy form). BCH
  retained Bitcoin's signed-message preamble post-fork; only
  the BIP-44 coin type and forward CashAddr surface differ
  (CashAddr deferred — legacy P2PKH still verifies on every BCH
  wallet). Same preimage hash as BTC for the same message.

Combined with BTC + ETH-family from prior waves: 16 of 21 top
coins now sign through Recto.

**Wave 7A — Python verifier (recto.bitcoin) coin parameter.**
Already shipped in Wave 7 part 1 — `signed_message_hash`,
`address_from_public_key`, `recover_address`, `verify_signature`
all take an optional `coin="btc"` parameter, with the per-coin
preamble + version bytes + HRP looked up from a `COIN_CONFIG`
dict at module top. Backward compatible — existing BTC callers
(default coin) keep working unchanged.

**Wave 7B — Protocol DTOs.** New `BtcCoin` enum class in
`Recto.Shared.Protocol.V04` (constants: `Bitcoin` / `Litecoin` /
`Dogecoin` / `BitcoinCash`), new optional `btc_coin` field on
`PendingRequestContext`. Same `btc_sign` credential kind covers
all four; the discriminator selects which.

**Wave 7C — Python state.py + bootloader server.**
`PendingRequest.btc_coin` field added with default None.
`PendingRequest.new_btc()` accepts a `btc_coin: str = "btc"`
parameter with construction-time validation; if
`btc_derivation_path` is None, it defaults to the coin's
canonical BIP-44 path (`m/84'/0'` BTC, `m/84'/2'` LTC,
`m/44'/3'` DOGE, `m/44'/145'` BCH). `_pending_to_wire` emits
the `btc_coin` field only when non-default (preserves v0.5
wire shape for BTC-only callers). `_handle_respond` is
coin-agnostic — BIP-137 compact-sig structural validation is
the same across the family.

**Wave 7D — C# BtcSigningOps coin-aware primitives.** New
`BtcCoinConfig` record + `CoinConfigs` dict mirroring Python's
`COIN_CONFIG`. `SignedMessageHash(message, coin="btc")` dispatches
to the right preamble. `AddressFromPublicKey(pub, network, kind,
coin)` dispatches to the right version bytes / HRP. New
`Base58CheckEncode` for legacy P2PKH (DOGE / BCH default kind).
P2WPKH rejected with a clear error when called against DOGE / BCH
(no native SegWit support).

**Wave 7E — C# `IBtcSignService` + `MauiBtcSignService` coin
parameter.** All three method signatures (`EnsureMnemonicAsync`,
`GetAccountAsync`, `SignMessageAsync`) now accept a `string coin`
parameter. The service's internal `DeriveAccount` helper uses the
coin's `DefaultAddressKind` (P2WPKH for BTC/LTC, P2PKH for
DOGE/BCH) so the address surfaced to the operator UI matches
what each coin's wallet ecosystem expects.

**Wave 7F — Home.razor BtcSign render arm.** Per-coin badge
(BTC orange `#f7931a`, LTC blue `#345d9d`, DOGE gold `#c2a633`,
BCH green `#0ac18e`) painted via the `.rec-coin-badge-{coin}`
CSS classes shipped in part 1's vault redesign. Approval card
shows coin name + network + path + derived address; the
existing single-foreach RenderFragment lambda dispatches the
right helper per request automatically.

**Wave 7G — Mock bootloader operator UI.** Refactored the
existing BTC handler into `_queue_btc_family_message_sign(coin)`
helper driven by a `_BTC_FAMILY_CONFIG` dict mapping coin →
ticker / default path / placeholder address / secret label.
Three new endpoint paths:
`/_queue_ltc_message_sign` / `/_queue_doge_message_sign` /
`/_queue_bch_message_sign` plus their UI buttons. Recovery side
uses the new `coin=` parameter on `recto.bitcoin.recover_address`
+ `signed_message_hash` so each end-to-end test is self-verifying
(operator sees "recovered: ltc1q.../D.../1..." inline). Recent-
responses listing now shows the right ticker (LTC/DOGE/BCH)
instead of always "BTC".

**Tests.** Two new test classes in `tests/test_bitcoin.py`:
`TestSignedMessageHashCoinFamily` (5 tests — pins that BTC + BCH
share the Bitcoin preamble, LTC + DOGE produce distinct hashes
matching their canonical preambles, unknown coin rejected) and
`TestAddressFromPublicKeyCoinFamily` (6 tests — BTC P2WPKH
canonical reference vector, LTC bech32 starts with `ltc1q`, DOGE
P2PKH starts with `D`, BCH legacy P2PKH starts with `1`, P2WPKH
rejected for DOGE / BCH with a clear error). 11 net-new tests
covering the coin-config dispatch surface end to end.

### Added — Wave 6: EVM expansion + EIP-712 + EIP-1559 (2026-04-29)

Extends the Ethereum credential kind from "personal_sign on a
single chain" to the full EVM signing surface across 21 EVM-
compatible chains, with all three signing verbs wired end-to-end:
EIP-191 personal_sign (already shipped wave-1), EIP-712 typed-data
(new), EIP-1559 (type-2) raw-transaction signing (new). One sprint
unlocks 8 of the user's top-21 cryptocurrencies that share the
same `m/44'/60'/0'/0/N` BIP-44 tree: ETH (mainnet+L2s), BNB Smart
Chain, Avalanche C-chain, Polygon, plus every USD-pegged ERC-20
stablecoin (USDT/USDC/DAI/USD1) and every ERC-20 utility token
(LINK, HYPE, etc.) — all sign identically through the same
secp256k1 + Keccak-256 + EIP-191 / EIP-712 / EIP-1559 stack.
Adding a new EVM-compatible chain after wave-6 is a one-line
addition to the friendly-label switch in Home.razor; no protocol,
DTO, or signing-primitive changes.

**Wave 6A — Multi-chain EVM expansion (chain-id labels).**
`Home.razor`'s `_ethChainLabel` switch extended from 4 chains
(mainnet / Sepolia / Base / Polygon) to 21 chains: Ethereum
mainnet, the major L2 rollups (Optimism, Arbitrum One, Base,
zkSync Era, Linea, Scroll), the major sidechains / alt-L1s (BNB
Smart Chain, Polygon, Polygon zkEVM, Avalanche C-chain, Gnosis
Chain, Cronos, Fantom), and the canonical public testnets
(Ethereum Sepolia + Holesky, Base Sepolia, Arbitrum Sepolia,
Optimism Sepolia, Polygon Amoy, Avalanche Fuji, BNB testnet).
Friendly labels show in the operator approval card so the
operator sees "Base (8453)" instead of "chain 8453" before
approving — material when an unfamiliar chain id is passed by
a launcher. The signing math is unchanged across all 21 chains;
chainId only matters for EIP-1559's RLP payload (replay
protection lives at the chainId field, not the v byte).

**Wave 6B — EIP-712 typed-data signing.** `recto.ethereum`
gained `typed_data_hash(td)` plus the EIP-712 internals
(`_struct_hash`, `_encode_type`, `_find_type_dependencies`,
`_encode_value`) implementing the canonical
`keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))`
digest with recursive struct dependency resolution and full
type encoding (uint*, int*, bytes*, address, bool, string,
nested struct, fixed + dynamic arrays, atomic types). Mirror
implementation in C# `EthSigningOps.TypedDataHash` parsing the
same canonical EIP-712 JSON envelope via `System.Text.Json`.
`MauiEthSignService.SignTypedDataAsync` extends the phone-side
service: same BIP-39 → BIP-32/BIP-44 derivation chain as
personal_sign, signs the EIP-712 digest with secp256k1 + RFC
6979 deterministic-k + low-s + v-recovery, returns 65-byte
r||s||v with v ∈ {27, 28} (canonical OZ / viem / ethers shape).
`Home.razor`'s `ApproveEthSignAsync` dispatcher routes
typed_data through `SignTypedDataAsync`, plus an operator-
facing summary card shows the EIP-712 primary type, domain
name + version, and verifyingContract before the operator
approves — material disclosures for any token-permit or
DAO-vote signing flow.

**Wave 6C — EIP-1559 (type-2) transaction signing.**
`recto.ethereum` gained `transaction_hash_eip1559(tx)` plus
`rlp_encode` / `rlp_decode` implementing the canonical
`keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
maxFeePerGas, gasLimit, to, value, data, accessList]))`
digest. Mirror implementation in C#
`EthSigningOps.TransactionHashEip1559` + `RlpEncode` parsing
the same JSON envelope. New `EthSigningOps.SignAndEncodeTransactionEip1559`
returns the FULL signed raw-tx bytes
(`0x02 || rlp([fields..., yParity, r, s])`) ready for
`eth_sendRawTransaction`. `MauiEthSignService.SignTransactionAsync`
extends the phone-side service: same derivation chain, signs
with secp256k1 (raw recovery_id 0/1 for yParity, NOT 27+recid
like personal_sign — chainId already encodes replay protection
in the RLP payload), returns the full signed-tx hex. Per-
transaction display arm in `Home.razor` shows recipient
address (or "Contract creation"), value in ETH (with wei
fallback), gas limit, max fee per gas in gwei, and a data
preview before approval. Bootloader `_handle_respond`
structural validation extended: personal_sign + typed_data
keep the strict 130-hex-char check (65-byte r||s||v);
transaction accepts any length ≥ 200 hex chars (sane minimum
for a non-empty signed-tx body), since the encoded length
varies with payload size.

**Mock bootloader operator-UI buttons (dev tooling).**
`/_queue_eth_typed_data` queues a sample EIP-2612 USDC permit
on Base; `/_queue_eth_transaction` queues a sample EIP-1559
ETH transfer on Base. Both end-to-end testable from the mock's
operator UI on Windows MAUI. Mock's response handler extended
with typed_data + transaction recovery logic — recovers the
signer address from the rsv (typed_data: re-hashes via
`typed_data_hash`; transaction: RLP-decodes the signed-tx,
extracts `[yParity, r, s]` from the tail, re-assembles a
canonical 27/28 v rsv, recovers via `recover_address` over
the unsigned `transaction_hash_eip1559`). Operator UI shows
"recovered: 0x..." inline so each end-to-end test is self-
verifying without external tooling.

**Coverage unlocked.** 8 of the 21 top-by-market-cap coins
on the operator's target list now sign through Recto:
- ETH + L2 family (mainnet, Base, Optimism, Arbitrum, etc.)
- BNB Smart Chain (BNB)
- AVAX C-chain (AVAX)
- USDT (Tether) — ERC-20 on multiple EVM chains
- USDC (Circle) — ERC-20 on multiple EVM chains
- DAI (MakerDAO) — ERC-20 on Ethereum
- LINK (Chainlink) — ERC-20 on Ethereum + L2s
- HYPE (Hyperliquid) — ERC-20 on Hyperliquid L1
- USD1 (World Liberty Financial) — ERC-20 on Ethereum + Base

Combined with ETH + BTC already shipped, ~13 of 21 top coins
covered. Remaining sprint scope: Bitcoin family (LTC, DOGE,
BCH — wave 7), TRON + XRP (wave 8 / 9), Solana + XLM (wave 10),
Cardano (wave 11). XMR / ZCASH / CC skipped (privacy-by-
design + institutional architecture mismatch).

### Added — Bitcoin credential kind end-to-end (3 waves, 2026-04-29)

Sister implementation of the Ethereum credential kind shipped
2026-04-28. Reuses the BIP-39 mnemonic infrastructure (one mnemonic
per phone, two BIP-44 trees: <c>m/44'/60'</c> for ETH,
<c>m/84'/0'</c> for BTC native-SegWit P2WPKH default) and the
secp256k1 ECDSA primitive (same curve). Net-new code: bech32
encoding (BIP-173), HASH160 + RIPEMD-160 (pure-stdlib in Python,
BouncyCastle in C#), BIP-137 signed-message hashing, BIP-137
compact-signature parse + recover. PSBT (BIP-174 transaction
signing) is reserved for a follow-up; today the message-signing
verb is wired end-to-end.

**`recto.bitcoin` module + `recto[bitcoin]` extra (Wave 1).** Pure-
stdlib verify-side primitives mirroring `recto.ethereum`'s structure:
RIPEMD-160 from-scratch reference impl (Python's
`hashlib.new("ripemd160")` is OpenSSL-build-dependent and unreliable
on modern stacks), HASH160, double-SHA-256, bech32/bech32m encoding
+ decoding, public-key compression (64-byte uncompressed →
33-byte compressed), P2WPKH / P2PKH / P2SH-P2WPKH address
derivation, BIP-137 signed-message hash, BIP-137 compact-signature
parse + recover. secp256k1 ECDSA verify is delegated to
`recto.ethereum.recover_public_key` (same curve). 42 new tests in
`tests/test_bitcoin.py` against canonical reference vectors:
RIPEMD-160 paper test vectors, BIP-173 mainnet+testnet
P2WPKH+P2WSH addresses, HASH160 of generator G →
`bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`, BIP-137 sign-then-
recover round trip with low-s canonicalization.

**Protocol DTO additions in `Recto.Shared.Protocol.V04` (Wave 1).**
New `BtcSign = "btc_sign"` constant on `PendingRequestKind`; new
`BtcMessageKind` discriminator class with `MessageSigning` /
`Psbt` constants; new `BtcNetwork` discriminator class with
`Mainnet` / `Testnet` / `Signet` / `Regtest`; new BTC-specific
optional fields on `PendingRequestContext` (`BtcNetwork`,
`BtcMessageKind`, `BtcAddress`, `BtcDerivationPath`,
`BtcMessageText`, `BtcPsbtBase64`); new `BtcSignatureBase64` field
on `RespondRequest` carrying the 65-byte BIP-137 compact signature
base64-encoded. All additions backward-compatible (optional fields
default null). `docs/v0.4-protocol.md` "Bitcoin signing capability
(v0.5+)" section authored.

**Bootloader-side wiring + mock parity (Wave 2).**
`PendingRequest.new_btc(...)` constructor + 6 optional BTC context
fields on the dataclass with construction-time validation
(message-kind, network, per-kind body field, address minimum-
length sanity check). `recto.bootloader.server`'s
`_pending_to_wire` emits the BTC fields when `kind == "btc_sign"`
(omitted for non-BTC kinds — regression-tested); `_handle_respond`
extracts and structure-checks `btc_signature_base64` on approvals
(65-byte decode + header byte in 27..42), forwards through
`_notify_resolved` alongside the existing Ed25519 envelope and ETH
signature pass-through. Mock bootloader gains a "Queue BTC
message_sign" operator-UI button that queues a BIP-137 login-style
message on Bitcoin mainnet at `m/84'/0'/0'/0/0` and recovers the
signer's bech32 P2WPKH address when the mock is launched from a
Recto checkout. New tests in `tests/test_bootloader_btc.py`:
state-level construction validation, persistence round-trip,
end-to-end live-HTTP exercises with the actual `BootloaderHandler`
including missing/malformed-sig negative cases, plus a regression
test that the existing eth_sign path is unaffected.

**Phone-side service + Home.razor approval (Wave 3).**
`IBtcSignService` interface in `Recto.Shared/Services/`
(cross-platform contract: `EnsureMnemonicAsync` / `GetAccountAsync`
/ `ExistsAsync` / `SignMessageAsync` / `ClearAsync`). Surfaces
`BtcAccount(DerivationPath, Address, Network, AddressKind)` from
`Recto.Shared/Models/`. `BtcSigningOps` static class in
`Recto.Shared/Services/` (BouncyCastle-backed math: RIPEMD-160 via
`RipeMD160Digest`, HASH160, double-SHA-256, varint encoding,
BIP-137 signed-message hash, public-key compression, bech32
encoding, P2WPKH address derivation, BIP-137 compact-signature
sign with deterministic-k ECDSA + low-s canonicalization +
v-recovery via the Eth recover primitive). `MauiBtcSignService` in
`Recto/Services/` reads the SAME `recto.phone.eth.mnemonic.{alias}`
SecureStorage entry as `MauiEthSignService` — one mnemonic, two
BIP-44 trees, one backup ceremony covers both coins. DI
registration alongside `IEthSignService` in `MauiProgram.cs`.
Home.razor render arm with orange BTC badge, network label,
derivation path, derived address, message text. New
`ApproveBtcSignAsync` dispatcher producing the dual signature
(BIP-137 compact base64 via `IBtcSignService` + Ed25519 envelope
via `IEnclaveKeyService`). New `_btcAddressByRequestId` cache
populated alongside the ETH cache after every refresh so the
approval card displays the bech32 address inline before the user
clicks Approve.

**`Recto.Shared.Tests/BtcSigningOpsTests.cs` +
`Bip32BtcTests.cs` — ~16 new tests** covering RIPEMD-160 canonical
vectors, BIP-173 mainnet+testnet P2WPKH addresses, HASH160
composition, double-SHA-256, public-key compression, P2WPKH
end-to-end address derivation with rejection of unknown networks,
BIP-137 signed-message hash determinism, BIP-137 compact signature
header-byte range + low-s canonicalization + RFC 6979
determinism. `Bip32BtcTests` covers BIP-84 derivation against the
canonical "abandon...about" mnemonic (`m/84'/0'/0'/0/0` →
`bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`) — the cross-wallet
interop sanity check. Plus a one-mnemonic-two-coins integration
test that ETH and BTC addresses derived from the same seed are
both correct.

**Sprint exits when**: cross-wallet interop confirmed live for
Bitcoin (paste a Recto-produced BIP-137 signature into Bitcoin
Core's `verifymessage` or any BIP-137-compatible verifier; recover
the same bech32 address Recto produced). Same posture as the ETH
sprint exit. Both sprints together complete the cryptocurrency-
custody story: ~80% of by-market-cap on-chain custody surface,
all from one phone-resident 24-word mnemonic.

**Still ahead** (follow-ups, non-blocking):
- **PSBT (BIP-174) signing** — Bitcoin transaction signing.
  ~400 LOC of partial-signature combine machinery on top of the
  existing primitives.
- **P2PKH / P2SH-P2WPKH paths** — wire `m/44'/0'` and `m/49'/0'`
  purpose levels through `MauiBtcSignService`. The `BtcSigningOps`
  layer already supports P2PKH and P2SH-P2WPKH address derivation;
  just needs the dispatch in `DeriveAccount` based on the path's
  purpose level.
- **Vault-namespaced storage refactor** — both coin services
  currently read `recto.phone.eth.mnemonic.{alias}` (misleadingly
  named post-wave-5). v0.6+ migration path: copy from
  `recto.phone.eth.mnemonic.{alias}` to
  `recto.phone.vault.mnemonic.{alias}` on first read, both keys
  remain readable for one release, then the legacy key is dropped.

### Added — BIP-39 mnemonic + BIP-32/BIP-44 derivation (sprint fourth wave 2026-04-28)

Promotes the protocol's `eth_derivation_path` field from advisory
metadata to a real lookup parameter. The phone-side
`MauiEthSignService` no longer stores a single random secp256k1
private key per alias; instead it stores a 24-word BIP-39 mnemonic
and derives infinitely many addresses on demand via BIP-32. Mnemonics
are byte-for-byte interoperable with every other BIP-39 wallet
(MetaMask, Ledger, Trezor, Rabby, Coinbase Wallet, etc.) — same
words, same derivation, same addresses. Foundation for downstream
consumers binding user wallets to platform identities.

**`Bip39Wordlist` in `Recto.Shared/Services/`.** Loads the canonical
2048-word BIP-0039 English wordlist from an embedded resource at
`Recto.Shared/Resources/Bip39/english.txt` (one-time download from
the bitcoin/bips repo during sprint setup). Defensive validation at
load time catches corrupt files, BOM injection, line-ending drift,
and length mismatches loudly. Operators using Recto-generated
mnemonics can recover them in any other BIP-39 wallet.

**`Bip39` in `Recto.Shared/Services/`.** Mnemonic generation
(CSPRNG entropy → words via the canonical wordlist + SHA-256
checksum), validation (words → entropy + checksum verify), and seed
derivation (PBKDF2-HMAC-SHA512 with 2048 iterations per BIP-39
spec). Defaults to 24-word / 256-bit entropy. NFKD-normalizes
mnemonic + passphrase per BIP-39 §"From mnemonic to seed".

**`Bip32` in `Recto.Shared/Services/`.** Hierarchical-deterministic
key derivation. `MasterFromSeed` (HMAC-SHA512 with "Bitcoin seed"
key), `DeriveChild` (hardened + non-hardened branches per BIP-32
spec), `DeriveAtPath` (walks a `m/44'/60'/0'/0/N`-style path string
to the leaf), `ParsePath` (handles `'` and `h` hardened markers,
optional `m/` prefix). Out-of-range guards on master + child IL
values throw a clear error (probability ~2^-127, but visible
instead of silently-wrong if it ever fires).

**`MauiEthSignService` rewrite in `Recto/Services/`.** Storage
shape changed from `recto.phone.eth.{alias}` (single random
secp256k1 key, hex) to `recto.phone.eth.mnemonic.{alias}` (24-word
BIP-39 mnemonic, plaintext space-separated). Each
`SignPersonalSignAsync` call reads the mnemonic, runs PBKDF2 →
master → BIP-32 derivation → secp256k1 sign in-memory and wipes
all intermediate secrets via `CryptographicOperations.ZeroMemory`
before returning. **Breaking change for v0.5+ first-cut testers**:
the legacy single-key entry is no longer read by any wave-4 code
path; phones that only ever ran the first cut will generate a
fresh BIP-39 mnemonic on first wave-4 sign and derive a NEW address
tree (the old random key becomes unrecoverable via Recto, but it
was testnet-only dev iteration so no production data was on it).
`ClearAsync` cleans up both new and legacy SecureStorage entries
in one call.

**`Recto.Shared.Tests/Bip39Tests.cs` + `Bip32Tests.cs` +
`EthSigningOpsTests.cs`.** ~30 new tests pinning the implementation
against published reference vectors. Most-cited cross-wallet sanity
check: mnemonic "abandon abandon abandon abandon abandon abandon
abandon abandon abandon abandon abandon about" (12-word zero-entropy)
+ empty passphrase + path `m/44'/60'/0'/0/0` → ETH address
`0x9858EfFD232B4033E47d90003D41EC34EcaEda94` (Trezor's reference
fixture; if our impl produces this exact address for that input,
the entire BIP-39 + BIP-32 + secp256k1 + Keccak stack is verified
cross-wallet interoperable). Plus Trezor-passphrase seed
validation, RFC 6979 deterministic-k confirmation, low-s
canonicalization check, sign-then-recover round trip,
keccak256("") canonical hash, EIP-191 hash of "hello".

**Home.razor address-display polish.** When a pending `eth_sign`
request renders, the approval card now shows the actual ETH
address that will sign (derived live from the requested path) so
the operator can confirm before approving. New
`PopulateEthAddressesAsync` hook runs after every
`RefreshPendingAsync` to pre-derive addresses for all pending
eth_sign requests; render arm reads from the cached map. Operators
clicking Approve see "Address: 0x..." inline as the visible fruit
of the BIP-32 work.

**Code-organization refactor.** Crypto classes moved from
`Recto/Services/` (MAUI host project) to `Recto.Shared/Services/`
so the test project can reach them via the existing project
reference. BouncyCastle.Cryptography reference + the embedded
wordlist resource also moved to Recto.Shared. `MauiEthSignService`
stays in the MAUI host because it depends on
`Microsoft.Maui.Storage.SecureStorage`. Old files at
`Recto/Services/{EthSigningOps,Bip39,Bip32,Bip39Wordlist}.cs` are
empty placeholder comments and can be deleted from the working
tree.

**Still ahead** for the sprint (or follow-up):
- **`ImportMnemonicAsync` UI surface** — Settings page hookup so
  operators can paste an existing mnemonic (e.g. from a Ledger
  recovery phrase) and have Recto re-derive the same addresses.
  The capability is built; just needs the UI form. Behind a
  destructive-confirmation modal (overwrites any existing
  mnemonic for the alias).
- **`ExportMnemonicAsync` UI surface** — biometric-gated mnemonic
  display for backup ceremony. One-time-display semantics:
  operator confirms they wrote down the words by re-entering
  3 of them at random positions; mnemonic returns to hidden state
  after that.
- **Multi-account picker** — Settings list of every address
  derived so far + an "Add account" button that bumps the BIP-44
  account index and derives a fresh address. Today the protocol
  permits any path, but the UI only exposes the default
  `m/44'/60'/0'/0/0`.
- **EIP-712 typed-data + RLP transaction signing** — same
  derivation infrastructure, different digest computation. Today
  only `personal_sign` is wired end-to-end; `typed_data` and
  `transaction` short-circuit with a "not yet implemented"
  message in `ApproveEthSignAsync`.
- **Real-iPhone validation** — every line of wave-4 code is
  cross-platform and runs identically on iOS, but a real-device
  build pass would catch any platform-specific gotchas with
  `SecureStorage` Keychain semantics. Pending the a legacy iPhone
  charge + Xcode 26.3 DeviceSupport question.

### Added — Ethereum credential-kind phone-side signing service + Home.razor approval UI (sprint third wave 2026-04-28)

Third wave of the major-token credential-kind sprint. Closes the
ETH personal_sign loop end-to-end: queue an `eth_sign` request from
the mock bootloader's operator UI → phone-side approval handler dispatches
through `IEthSignService` → secp256k1 ECDSA sign with deterministic-k
+ v-recovery → `r||s||v` hex returned via `RespondRequest.EthSignatureRsv`
→ mock recovers signer address from rsv and surfaces it for inspection.
The reframing of "needs Apple-platform-build host" gating in the
wave-2 sprint notes was wrong — the software impl is cross-platform
via BouncyCastle and authorable from any contributor host; no
Apple-hardware dependency for the Windows MAUI dev path. Real-iPhone
deploy validates the same code path on hardware later, but is not on
the critical path for proving the protocol.

**`IEthSignService` interface in `Recto.Shared/Services/`.** Cross-platform
contract: `EnsureMnemonicAsync` / `GetAccountAsync` / `ExistsAsync` /
`SignPersonalSignAsync` / `ClearAsync`. Surfaces `EthAccount(DerivationPath,
Address)` from `Recto.Shared/Models/`. Mnemonic naming preserved on the
interface for v0.6+ when full BIP39 + BIP32/BIP44 derivation lands; v0.5+
ground floor goes straight from CSPRNG to a 32-byte secp256k1 private key
without mnemonic intermediation. The `eth_derivation_path` protocol field is
treated as advisory metadata in this cut.

**`EthSigningOps` static class in `Recto/Services/`.** Pure-math BouncyCastle-
backed primitives: `GeneratePrivateKey` (CSPRNG, value in `[1, n-1]`),
`PublicKeyFromPrivate` (uncompressed 64-byte X||Y), `Keccak256` (original
Keccak padding, not FIPS-202 SHA3 padding), `PersonalSignHash` (EIP-191
prefix + Keccak), `AddressFromPublicKey` (last 20 bytes of pub-Keccak as
0x-prefixed lowercase hex), `SignWithRecovery` (RFC 6979 deterministic-k
ECDSA + low-s canonicalization + v-recovery via try-recId-0-then-1),
`RecoverPublicKey` (SEC1 §4.1.6 recovery from `(msg_hash, r, s, v)`).
~250 LOC, no platform-specific code, works identically across Windows /
the macOS host Catalyst / iOS Simulator / iOS device / Android — anywhere
BouncyCastle.Cryptography compiles.

**`MauiEthSignService` impl in `Recto/Services/`.** `SecureStorage`-backed
orchestrator. Storage key shape: `recto.phone.eth.{alias}` holds the
hex-encoded private key. Implicit-create-on-use via `EnsureMnemonicAsync`
fires from `SignPersonalSignAsync` so the operator's first ETH approval
just works without a separate provisioning step (matches the iOS
`IosSecureEnclaveKeyService` pattern). In-memory key bytes wiped via
`Array.Clear` immediately after use; encrypted at rest in MAUI
`SecureStorage` (iOS Keychain / Android Keystore-encrypted prefs / Windows
DPAPI for unpackaged hosts). `ClearAsync` surfaces for the Settings
"Unpair all" emergency wipe path.

**DI registration in `MauiProgram.cs`.** `AddSingleton<IEthSignService,
MauiEthSignService>()` alongside `ITotpService`. Single cross-platform
impl — no `#if IOS / #if ANDROID` fan-out since SE / StrongBox don't
support secp256k1 anyway (SE is P-256 / RSA / Curve25519 only; StrongBox
is RSA / EC NIST curves only). The software impl IS the correct long-term
implementation for ETH, not a fallback.

**Home.razor approval handler.** New render arm displays chain id (with
human-readable label for mainnet / Base / Sepolia / Polygon / Optimism /
Arbitrum / Base Sepolia, "chain N" otherwise), derivation path, and the
full `eth_message_text` for `personal_sign` (or a truncated typed-data JSON
preview for `typed_data`). New `ApproveEthSignAsync` dispatcher method
produces TWO signatures: secp256k1 r||s||v over the EIP-191 hash via
`IEthSignService` (forwarded through `RespondRequest.EthSignatureRsv`),
AND the existing Ed25519 envelope over `payload_hash_b64u` via
`IEnclaveKeyService` (forwarded through `SignatureB64u`, proves "from the
paired phone"). `typed_data` and `transaction` kinds short-circuit with a
"not yet implemented" message so the operator sees a clear bound.

**Mock bootloader placeholder-address suppression.** When the queued
`eth_address` is the all-zero placeholder (the operator UI's default for
phones that haven't pre-registered an address), the mock skips the
"recovered vs expected" comparison and just displays the recovered address
inline — operators see "recovered: 0x..." without an amber "differs from
expected" warning that would otherwise fire on every test. Real production
flows that pin an expected address still get the comparison.

### Added — Ethereum credential-kind launcher-side handler + mock-bootloader operator UI (sprint continuation 2026-04-28)

Second wave of the major-token credential-kind sprint. Wires
the bootloader server's queue + respond path for the new
`eth_sign` kind, gives the mock bootloader an operator-UI button
to exercise the flow end-to-end, and pins the contract with 23
new tests. Phone-side `IEthSignService` (BIP39 mnemonic +
BIP32/BIP44 derivation + secp256k1 sign) is still the next
session's work — that side needs a real-Apple-hardware build pass
gated on the macOS-side host. The Python tier is now a stable
target the phone-side can develop against.

**`PendingRequest.new_eth(...)` constructor + 7 ETH context
fields on the dataclass.** `recto.bootloader.state.PendingRequest`
gains optional `eth_chain_id`, `eth_message_kind`, `eth_address`,
`eth_derivation_path`, `eth_message_text`, `eth_typed_data_json`,
`eth_transaction_json` fields (all default `None`) plus a
`new_eth(...)` classmethod that validates message-kind / per-kind
body-field shape and rejects malformed addresses at construction
time. Existing `new(...)` keeps its v0.4.0 signature unchanged so
non-ETH callers don't have to think about the new fields. The
seven fields mirror the C# `PendingRequestContext` ETH additions
in `Recto.Shared.Protocol.V04`.

**`recto.bootloader.server` — kind-aware `_pending_to_wire` +
respond dispatch.** The wire shape now emits the seven ETH fields
on the GET /v0.4/pending response when `kind == "eth_sign"`, and
omits them otherwise (regression-tested). The respond handler
extracts `eth_signature_rsv` from the body on `eth_sign`
approvals, validates structural shape (130 hex chars, optional
`0x` prefix, valid hex), forwards it through `_notify_resolved`
alongside the existing Ed25519 envelope. Per the protocol RFC
the bootloader does NOT validate the secp256k1 signature itself —
that's the consumer's job (smart contract on chain, off-chain
verifier, capability-JWT scope enforcer, etc.). The Ed25519
envelope still applies and proves "the response came from the
paired phone." `_notify_resolved` gained an optional
`eth_signature_rsv` keyword with backward-compat fallback for
older notify_fn signatures, so tests / launchers using the prior
4-arg shape keep working.

**`tests/test_bootloader_eth.py` — 23 new tests.** Three
sections: state-level construction validation (happy path for
all three message kinds + invalid kind / missing body / bad
address / address-lowercasing / custom derivation path), state
persistence round-trip, and end-to-end live-HTTP server tests
exercising real `BootloaderHandler` instances bound to an
OS-assigned localhost port. The HTTP suite covers GET /pending
emits ETH context fields, POST /respond with valid Ed25519 +
valid rsv resolves ok with rsv forwarded, denied resolves with
no rsv, missing rsv on eth_sign rejects 400, malformed rsv
rejects 400, forged Ed25519 rejects 400, and a non-eth
single_sign regression test confirms the existing v0.4.0 flow
still works after the ETH branch.

**Mock bootloader gains an ETH personal_sign operator-UI
button.** `phone/RectoMAUIBlazor/dev-tools/mock-bootloader.py`
gets a sixth queue button alongside the existing
single_sign/TOTP/session_issuance/WebAuthn/PKCS#11/PGP buttons.
Click queues an EIP-191 personal_sign request on Base (chain
8453) targeting the default `m/44'/60'/0'/0/0` derivation path
with a fresh login-style message text. The mock's respond
handler validates the Ed25519 envelope (same path as
single_sign), structure-checks the rsv signature, and stashes
both for display. Best-effort signer-address recovery via
`recto.ethereum.recover_address` runs when the mock is launched
from inside a Recto checkout — operators see the recovered
address inline next to the expected address with a green
"matches expected" / amber "differs from expected" marker, so
mnemonic-derivation correctness is eyeballable from the operator
UI without separate tooling. Recovery failure is non-fatal; the
protocol RFC explicitly says the bootloader doesn't validate the
secp256k1 sig substantively.

**Still ahead** for the sprint (next session):
phone-side `IEthSignService` (BIP39 mnemonic gen/import,
BIP32/BIP44 derivation, secp256k1 sign with v-recovery in C#
under `phone/RectoMAUIBlazor/Services/`); Home.razor approval UI
for `eth_sign` requests displaying the chain id + message text
+ derivation path with the per-call biometric prompt;
launcher-side bootloader handler that creates ETH pending
requests at child-spawn time when `service.yaml` has a
`spec.secrets[].source: enclave` entry with `kind: eth_sign`;
capability-JWT scope semantics for agent signing (target
contract, method selector, value cap, gas cap, expiry — enforced
server-side before the digest is produced). The protocol contract
+ Python verifier surface + mock-bootloader exerciser are stable
enough for the phone-side team (next-session-Claude on the macOS host) to
develop against in isolation.

### Added — Ethereum credential-kind groundwork (sprint in flight 2026-04-28)

First wave of the major-token credential-kind sprint. Lands the
Python launcher / verifier surface for the new `eth_sign` credential
kind plus the protocol DTOs the phone-side service will populate.
Phone-side signing implementation (BIP39 mnemonic + BIP32/BIP44
derivation + secp256k1 sign with v-recovery + Home.razor approval UI)
is the next session's work — those bits live in the MAUI Blazor
project under `phone/` and need a build-and-test pass on real Apple
hardware which is gated on a separate macOS-side host.

**`recto secrets set <service> <name>` (and `delete`).** Backend-
agnostic CLI commands for installing / removing secrets in any
registered backend. Default backend is `dpapi-machine` because that's
the production default for `LocalSystem`-running services (CredMan is
per-user and `ERROR_NOT_FOUND`s under a service-account read).
Mirrors `recto credman set/delete`'s safety guards (empty-prompt
refusal, explicit `--value ''` allowance, hidden prompt input). Drops
the operator-experience papercut where setting a dpapi-machine secret
required a Python one-liner against `DpapiMachineSource.write()` or a
PowerShell + .NET ProtectedData ceremony — captured in CLAUDE.md
during the second-consumer auth-rotation pass and identified as a
critical-path prerequisite for any future credential-kind rotation.
13 new tests in `tests/test_cli.py` covering both happy paths and
the readonly-backend / unknown-backend / empty-value edge cases.

**`recto.ethereum` module + `recto[ethereum]` extra.** Pure-stdlib
verify-side primitives for the eth_sign credential kind: Keccak-256
(hashlib doesn't ship it; SHA3-256 has different padding), secp256k1
ECDSA public-key recovery, EIP-191 personal_sign hashing, address
derivation from a 64-byte uncompressed public key, and EIP-55 mixed-
case checksum addresses. The extra is intentionally empty — pulls in
no new packages — and exists purely to gate the import path so
consumers without ETH-credential needs don't pay the import cost.
22 new tests in `tests/test_ethereum.py` against canonical Keccak
test vectors (empty string + ERC-20 function selectors), the EIP-55
test vectors from the EIP itself, a known-good go-ethereum address-
derivation vector, and an end-to-end synthetic-recovery round-trip
that exercises the secp256k1 modular-arithmetic path.

**Protocol DTO additions in `Recto.Shared.Protocol.V04`.** New
`EthSign = "eth_sign"` constant on `PendingRequestKind`; new
`EthMessageKind` discriminator class with `PersonalSign` / `TypedData`
/ `Transaction` constants; new ETH-specific optional fields on
`PendingRequestContext` (`EthChainId`, `EthMessageKind`, `EthAddress`,
`EthDerivationPath`, `EthMessageText`, `EthTypedDataJson`,
`EthTransactionJson`); new `EthSignatureRsv` field on `RespondRequest`
carrying the 65-byte r||s||v hex signature. All additions are
backward-compatible: existing kinds keep working without touching the
new fields. Documented in `docs/v0.4-protocol.md` under a new
"Ethereum signing capability (v0.5+)" section.

**Threat-model alignment.** Per Hard Rule #9 the phone is the
unconditional root of trust for any new credential kind. ETH is no
exception: private keys live on the phone, derived per-signing from
a BIP39 mnemonic in platform SecureStorage; the Python launcher tier
holds neither mnemonic nor derived key — it only produces digests for
the phone to sign and verifies the resulting r||s||v signatures
against expected addresses. Agent-driven signing (e.g. an automation
script that needs to call ETH actions on behalf of the operator)
flows through capability JWTs whose `scope` claims encode a
per-operation cap (target contract, method selector, value cap, gas
cap, expiry); operator approves the capability once on the phone, the
agent draws against it within bounds, the capability auto-expires.
The corresponding scope semantics will land alongside the phone-side
implementation in the next session.

### Added — v0.4.1 phone app (v1-completion sprint)

Same-day follow-on to round 8 (2026-04-26). Closes every remaining v1
gap so the phone app can ship as v1.0 after a real-device test pass.
Eight items shipped: real APNs/FCM senders, audit log, settings page,
UX polish, WebAuthn browser demo, composite enclave fallback, PKCS#11
credential kind, PGP credential kind.

**Real APNs HTTP/2 + FCM v1 HTTP senders.** Replaced the "would send"
log stubs with actual push delivery. FCM path: service-account JWT
(RS256) exchanged for OAuth2 access token, then POST to
`fcm.googleapis.com/v1/projects/{p}/messages:send` with high-priority
data-only message. APNs path: provider JWT (ES256, raw R||S
conversion from DER) over HTTP/2 to `api.sandbox.push.apple.com` /
`api.push.apple.com` via `httpx`. OAuth2 access tokens and provider
JWTs cached under module-level locks (1hr lifetime, 5-min refresh
margin). Both senders keyed off the credentials in
`phone/RectoMAUIBlazor/dev-tools/.fcm-service-account.json` +
`.apns-auth-key.p8`. CLI flags `--fcm-service-account`,
`--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-bundle-id`,
`--apns-environment` consume them. When credentials aren't
configured, the senders fall back gracefully to the existing
"would send" log stubs (no behavior change for credential-less dev
loops).

**Audit log.** Every approve/deny/sign/TOTP/JWT/WebAuthn/push-rotation
event is now recorded in a per-phone audit log (cap 500 events on
the bootloader, deque, newest-first). New endpoint
`GET /v0.4/manage/audit?phone_id=X&limit=N` returns the most-recent
N events for a phone. New protocol DTOs (`AuditLogResponse`,
`AuditEvent`, `AuditEventKind` constants). New IBootloaderClient
method `GetAuditLogAsync`. Captured fields: kind, decision, verified,
service, secret, payload_hash_b64u, totp_alias, webauthn_rp_id,
recorded_at_unix, detail. Re-pair, push-token rotation, and revoke
events also recorded via a separate `record_audit_event` helper.

**Phone Settings page.** New `/settings` route on the phone app with
polling-interval picker (2s / 3s / 5s / 10s / disabled),
audit-history-limit picker (20 / 50 / 200), theme preference
(system / light / dark), Danger-zone "Unpair all" emergency wipe
(clears every TOTP secret + the pairing record + the enclave key in
one transaction), and an About section showing version + algorithm
+ license. Backed by new `IUserPreferencesService` (MAUI
Preferences-backed, JSON blob under one key). Settings link surfaced
on the Home page via a gear icon in the top-right corner.

**UX polish on Home.razor.** Polling errors now render as a friendlier
"Couldn't reach the bootloader" alert with a Retry button (re-runs
RefreshPendingAsync inline, no need to leave the page) instead of a
raw error string. Empty-state for the pending-requests section now
shows a centered "All caught up" with a checkmark glyph + "Nothing
waiting for your approval" subline instead of an unstyled
"No requests waiting" line. Settings access added to the page chrome.

**WebAuthn browser demo page.** New `/demo/webauthn` HTML page on the
mock bootloader: a styled "Sign in with Recto" button that POSTs to
`/v0.4/webauthn/begin` (queues a webauthn_assert request for the
most-recently-paired phone), polls `/v0.4/webauthn/result/{request_id}`
every 1.5s until the phone responds, displays the verified assertion
on success. Mock bootloader caches successful assertions in a
`webauthn_results` dict for the demo page to retrieve. Demonstrates
the full RP-bootloader-phone WebAuthn flow visually; foundation for
the v0.5+ Keycloak adapter integration.

**Composite enclave fallback decorator.**
`CompositeEnclaveKeyService` wraps two `IEnclaveKeyService` impls
(primary + fallback). Tries primary first; on specific failure
modes (StrongBox unavailable, Secure Enclave errors,
NoSuchAlgorithm, biometric not enrolled) falls back to secondary.
Blocking phrases (cancelled / user denied / negative button) prevent
fallback when the user explicitly cancelled. Reports the primary's
algorithm; mismatch with fallback algorithm is by-design fail-loud
(re-pair required). Off by default; enable when real-device testing
surfaces enclave reliability issues. Documents the security
trade-off (fallback's software-resident keys are weaker than
enclave-protected) clearly in XML doc comments.

**PKCS#11 credential kind.** New `PendingRequestKind.Pkcs11Sign`.
Phone-side: reuses the single_sign signing path (same wire format,
same enclave call) but renders with a "PKCS#11" badge and a
`purpose` tag that surfaces "Sign SSH login" / "Sign code artifact" /
"Sign certificate request" instead of generic "Sign data". New
context fields: `Pkcs11ConsumerLabel`, `Purpose`. Mock bootloader has
operator-UI "Queue PKCS#11 sign" button + verification reuses the
single_sign path. `Pkcs11Purpose` constants for the standard purposes.
Foundation for the v0.5+ PKCS#11 module on the bootloader that
exposes phone-resident keys to OpenSSL / OpenSSH consumers.

**PGP credential kind.** New `PendingRequestKind.PgpSign`. Same shape
as PKCS#11 but renders with a "PGP" badge + `pgp_operation` tag
("PGP sign" / "PGP decrypt"). New context fields: `PgpKeyLabel`,
`PgpOperation`. Mock bootloader has operator-UI "Queue PGP sign"
button. `PgpOperation` constants for sign / decrypt. Foundation for
v0.5+ gpg-agent-socket integration on the bootloader that exposes
phone-resident PGP keys to git commit signing, encrypted-mail
decryption, etc.

NOT in this round (v0.5+):

- Real PKCS#11 module on the bootloader (today: protocol seam +
  phone-side UI; the bootloader-side native module that bridges
  OpenSSL/SSH to phone-resident keys is v0.5+).
- Real gpg-agent socket integration on the bootloader (same shape
  as PKCS#11).
- Recto-equipped Keycloak adapter (uses the WebAuthn assertion
  primitive shipped here; the adapter itself is a separate
  product).
- Hardware-attested agent identity (TPM/YubiKey/cloud-HSM-backed
  agent keys).
- Cross-bootloader federation (single phone trusted by multiple
  bootloaders).
- Real visual branding (text-mark placeholder is fine for v1; design
  commission is a separate work item).

### Added — v0.4 phone app (round 8: v1-readiness sprint)

Round 8 (2026-04-26) closes out the v0.4 phone app's pre-launch punch
list: HTTPS-capable mock for end-to-end cert-pinning testing, real
Recto branding (text-mark placeholder, replacing the .NET-default
scaffolding assets), 30+ phone-side unit tests pinning the pure-math
+ state-machine pieces, WebAuthn passkey browser-login bridge, and
push-notification scaffolding (APNs + FCM) with cert-ceremony
walkthroughs in the dev-tools README.

**HTTPS-capable mock bootloader.** `--tls` flag generates an ephemeral
self-signed ECDSA P-256 cert at startup, prints the SPKI pin (sha256
base64url, no padding) on stdout and in the operator UI for cross-
checking against what the phone captures during pairing. Cert SAN
includes localhost + 127.0.0.1 + ::1 + 10.0.2.2 (Android emulator
host loopback). Companion fix: `PinningService.Validate` now accepts
any cert during the pre-pairing TOFU window so the very first
connection to a self-signed bootloader can complete and capture the
pin; after `SetPin` is called, subsequent connections lock to the
captured pin and any cert change fails validation regardless of
system trust. Mirrors SSH known-hosts; without this the cert-pinning
code path was unreachable against any non-CA-signed bootloader.

**Recto branding text-mark placeholder.** Replaced the .NET-default
`appicon.svg` / `appiconfg.svg` / `splash.svg` with Recto-branded
assets: indigo `#1E1B4B` vault color, white path-based "R" glyph for
the icon foreground, white path-based "RECTO" wordmark for the splash.
Path-based to avoid font dependencies at MAUI's per-platform resize-
pipeline build time. csproj `MauiIcon` + `MauiSplashScreen` Color
attributes flipped from `#512BD4` to `#1E1B4B`.

**Phone-side unit tests** (Recto.Shared.Tests xUnit project, ~30
tests across 5 files). Pins TotpCodeCalculator against RFC 6238's
Appendix B reference vectors (so any silent regression breaks the
test instead of silently breaking every phone's TOTP), PinningService
against the TOFU + locked-pin behavior, EcdsaSignatureFormat against
the .NET runtime's own ECDSA signer + handcrafted DER edge cases
(short components, leading-0x00 positive-integer marker stripping),
CapabilityJwtBuilder against fingerprint format + JWS structural
shape + EdDSA/ES256 algorithm dispatch + signing-input determinism,
BootloaderClient against URL-shape + JSON-body-non-empty (pins the
round-2 JsonContent.Create vs StringContent fix) + error-to-Result
swallowing, WebAuthnAssertionBuilder against clientDataJSON property
order + authenticatorData layout + signing input shape. Native
enclave services stay platform-test-only since they require real
hardware; the algorithm-agnostic surface that runs on all targets
gets meaningful coverage.

**WebAuthn / passkey browser-login bridge.** New `webauthn_assert`
PendingRequest kind. Phone produces a WebAuthn-compatible assertion
(clientDataJSON + authenticatorData + signature) that any FIDO2 /
RFC 8809 relying party can verify against the phone's enclave public
key. Mock bootloader stands in as the relying party for a fictional
`demo.recto.example` and verifies with the same math a production
Recto-equipped Keycloak adapter would run.

- **Protocol DTOs**: `PendingRequestKind.WebAuthnAssert`,
  `PendingRequestContext` extended with WebAuthn fields,
  `RespondRequest` extended with `WebAuthnClientDataB64u` /
  `WebAuthnAuthenticatorDataB64u` (the assertion signature reuses
  the existing `SignatureB64u` field).
- **`WebAuthnAssertionBuilder`** in Recto.Shared.Services builds a
  canonical clientDataJSON byte string with the WebAuthn-specified
  property order, builds the 37-byte authenticatorData blob with the
  RP-ID-hash + UP+UV flag byte + big-endian counter layout, signs
  the `authenticatorData || sha256(clientDataJSON)` concatenation
  via IEnclaveKeyService.SignAsync, returns the three b64url-encoded
  pieces ready for `RespondRequest`.
- **Home.razor**: webauthn_assert renders with a "passkey" badge +
  Site / Origin labels in the pending-requests UI;
  `ApproveWebAuthnAssertAsync` triggers biometric prompt and POSTs
  the assertion back via RespondAsync.
- **Mock bootloader**: `_queue_webauthn_assert` operator-UI button
  generates a 32-byte random challenge for a fictional
  `https://demo.recto.example` RP, queues the request with the
  expected fields stashed for later verification.
  `verify_webauthn_assertion` helper parses clientDataJSON (asserts
  type=webauthn.get + challenge match + origin match), decodes
  authenticatorData (asserts rpIdHash matches sha256(rp_id) + UP
  flag set), recomputes the signing input and verifies the signature
  against the phone's stored public key.

This is the architectural foundation for Recto-as-Keycloak-replacement:
a Recto-equipped Keycloak adapter speaks the same WebAuthn assertion
protocol that any browser passkey would, with no special-casing.
v0.5+ adds the actual Keycloak adapter; v0.4 lands the primitive.

**Push notifications scaffolding (APNs + FCM).** Phone-side push-
token registration is final; bootloader-side delivery is scaffolded
with a "would send" stub pending the credential ceremony.

- **`IPushTokenService`** in Recto.Shared.Services with three impls:
  `AndroidFcmPushTokenService` (Xamarin.Firebase.Messaging 125.0.1.2);
  `IosApnsPushTokenService` (UNUserNotificationCenter authorization
  prompt + UIApplication.RegisterForRemoteNotifications with the
  device-token bytes hex-encoded; AppDelegate forwards the
  RegisteredForRemoteNotifications callback to a static helper that
  resolves any pending fetch); `NoOpPushTokenService` (Windows / the macOS host
  Catalyst dev hosts return null cleanly).
- **`RegistrationRequest`** extended with optional `PushToken` +
  `PushPlatform` fields. Pairing flow fetches the token before
  registering; failure to fetch is non-fatal.
- **`PushTokenUpdateRequest`** + `IBootloaderClient.UpdatePushTokenAsync`
  for post-pairing token rotation (FCM tokens rotate per Google
  guidance; APNs tokens can change after restoration from backup).
- **Mock bootloader**: stores `push_token` + `push_platform` per
  registered phone; new `POST /v0.4/manage/push_token` endpoint
  handles in-place rotation. `send_push_wakeup` helper called after
  every queue handler logs "[push] would send {platform} wakeup to
  {token-prefix}..." for every queued request. Operator UI
  registered-phones panel shows push-token presence per phone.
- **iOS Entitlements.plist** wires `aps-environment=development`;
  csproj has `<CodesignEntitlements>` set under the iOS-target
  conditional. AndroidManifest.xml gains `POST_NOTIFICATIONS`
  permission for Android API 33+.
- **Bundle ID** updated from the .NET template default
  `com.companyname.Recto` to `app.recto.phone` to match the cert
  ceremony's APNs + FCM registration. Existing test installs are
  invalidated (uninstall + reinstall required), but this only
  happens once.
- **Credential ceremony walkthroughs** for Firebase Console (FCM)
  and Apple Developer Program (APNs .p8 + Team ID + Key ID + bundle
  ID registration) live in `dev-tools/README.md`. Walks the operator
  through every console click; ends with the credential files
  dropped at gitignored paths inside `dev-tools/` and CLI flags
  reserved on the mock bootloader for v0.4.1 real-send wiring.

The actual APNs HTTP/2 + FCM v1 HTTP send code (~300 LOC of
cryptography + HTTP) is v0.4.1 follow-up work behind the existing
`send_push_wakeup` seam; phone-side code is final &mdash; once the
bootloader-side credentials flow is wired, push works end-to-end
without touching the phone.

### Added — v0.4 phone app (round 7: phone management + lost-phone recovery + UX polish)

Round 7 (2026-04-26) closes the operational-maturity gap between the
v0.4 architectural primitives and a v1-shippable phone app: lost-phone
recovery driven from the surviving phone's UI (no shell access to the
bootloader required), phone-id deduplication on re-pair, and small UX
polish (TOTP clipboard copy). See `docs/v0.4-protocol.md` "Phone
management (v0.5+)" section for the wire shapes.

**Phone-id deduplication on re-pair**

The mock bootloader's `register()` method now replaces an existing
phone_id entry in-place rather than appending a duplicate. The operator
just authorized the re-pair via biometric on the phone's enclave so the
new public key supersedes the old. Phones are keyed by `phone_id`;
uniqueness is the bootloader's invariant. Caught and noted as a quirk
in round 5 testing; addressed here.

**Lost-phone recovery + multi-phone management**

- **Protocol DTOs**: `RegisteredPhoneInfo` (phone_id, device_label,
  algorithm, paired_at), `RegisteredPhonesResponse`,
  `RevokeChallengeResponse` (challenge_b64u, expires_at_unix),
  `RevokeRequest` (revoking_phone_id, target_phone_id, challenge,
  signature_b64u), `RevokeResponse` (revoked, target_phone_id).
- **`IBootloaderClient`** extended with three management methods:
  `ListRegisteredPhonesAsync` (GET `/v0.4/manage/phones`),
  `GetRevokeChallengeAsync` (GET `/v0.4/manage/revoke_challenge`),
  `RevokePhoneAsync` (POST `/v0.4/manage/revoke`).
- **Mock bootloader endpoints**: routes for the three new endpoints.
  `mint_revoke_challenge` / `consume_revoke_challenge` use a separate
  `revoke_challenges` dict (per-phone single-use, 60s TTL) so a
  pairing challenge can't be replayed to authorize a revocation.
  `remove_phone` drops the registered-phones entry, any pending
  requests targeting it, and any active revoke challenge for it. The
  revoke handler verifies the signature against the revoking phone's
  stored public key using the right algorithm dispatch (ed25519 /
  ecdsa-p256).
- **`Home.razor`** Paired card grew a "Registered phones (N)" section
  that lists OTHER phones for the same bootloader with a per-phone
  "Revoke" button. Tap Revoke -> browser-native `confirm()` dialog
  (so an accidental tap doesn't nuke a backup) -> biometric prompt
  (the signing of the revoke challenge) -> POST -> list refresh.
  Refresh button on the section header drives an explicit re-fetch.
  List is auto-refreshed at OnInitializedAsync (after restoring
  paired state) and after any revocation.

**TOTP clipboard copy**

The "Last generated TOTP" alert grew a "Copy" button that uses
`navigator.clipboard.writeText` via `IJSRuntime`. Click confirmation
flips the button to "&#10003; Copied" for 2 seconds before resetting,
so the operator gets visual feedback. Avoids needing to long-press +
select the code on phone or triple-click on desktop.

**Protocol RFC** gains a new "Phone management (v0.5+)" section
documenting all three endpoints, dedup behavior, and the v0.4.0
single-operator authorization model (any registered phone can revoke
any other; v0.6+ multi-user tightens this).

**Multi-phone validation on real Android 16 hardware (Pixel 10)**

After the Windows MAUI walkthrough closed, the same flow ran end-to-end
on a real Pixel 10 alongside the Windows desktop install -- both
registered against the same mock bootloader, both exercising the v0.4
protocol independently. Verified flows on the Pixel:

- **single_sign** &times;2 with biometric prompt firing per signature
  (ECDSA P-256 / SHA256withECDSA, signatures verified by mock).
- **totp_provision** &times;2 (demo1 + demo2; biometric-gated SecureStorage
  write of the base32 secret per alias).
- **totp_generate** for demo1 -- code 288319 generated phone-side and
  matched the mock's expected value within the &plusmn;1 time-step
  window (RFC 6238 math survives real-clock skew).
- **session_issuance** -- 24h capability JWT signed by the phone, scope
  `[sign]`, max_uses 1000, bearer `bootloader`, JWS verified by the
  mock's stdlib JWT verifier (`ES256` dispatch since the Pixel is
  ECDSA-P256).

Two AndroidKeyStore footguns surfaced and were fixed during this batch:

- **`Xamarin.AndroidX.Biometric` versioning**. Initial pin of `1.2.0.13`
  doesn't exist on nuget.org; `Xamarin.AndroidX.*` package versions
  trail upstream AndroidX by one or more major-version generations
  (latest .NET binding is `1.1.0.32` of AndroidX Biometric `1.1.0`).
  Pinned to `1.1.0.32`. Banked as a CLAUDE.md gotcha so future
  `Xamarin.AndroidX.*` adds always check nuget.org instead of guessing
  from the upstream AndroidX line.
- **`UserNotAuthenticatedException` on `Signature.initSign(privateKey)`**
  for keys with `setUserAuthenticationRequired(true)`. Root cause: the
  Android keystore enforces user-presence proof at the signing API
  level when the key was generated with `setUserAuthenticationRequired`,
  and `Signature.initSign` is part of that auth boundary -- it can't
  proceed without a recent biometric/device-credential auth. Two
  flavors of fix:
  - **Per-use auth** (chosen): `setUserAuthenticationParameters(0,
    BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`. `InitSign` succeeds
    (signature object is "armed"); the actual `.sign()` call is
    authorized via `BiometricPrompt.authenticate(promptInfo,
    CryptoObject(signature))`. The success callback runs
    `signature.update(message); signature.sign()`. Each operation
    requires a fresh biometric prompt -- matches the v0.4 "operator
    approves every cryptographic operation" model exactly.
  - **Time-bound auth** (rejected): `setUserAuthenticationParameters(N,
    ...)` allows N seconds of subsequent crypto operations after a
    BiometricPrompt without CryptoObject. Weaker security model
    (operations within the timeout window can fire without explicit
    operator approval), so v0.4.0 ships per-use exclusively.
  The `AndroidStrongBoxKeyService.SignAsync` rewrite uses
  `BiometricPrompt.authenticate(promptInfo, CryptoObject(signer))`
  driving a `TaskCompletionSource<Result<byte[]>>` from the
  AuthenticationCallback's success / error / failure callbacks.
  `MauiAppCompatActivity` qualifies as the required `FragmentActivity`
  via `Microsoft.Maui.ApplicationModel.Platform.CurrentActivity` cast.
  Banked as a CLAUDE.md gotcha covering both flavors so the next
  Android-keystore-with-auth implementer doesn't re-derive the
  CryptoObject pattern from scratch.

After the fix landed: pairing on the Pixel prompted for fingerprint at
key-generation time (the keystore's first-use prompt), and every
subsequent sign request -- single_sign, totp_provision (under the
TOTP-secret-write key), totp_generate, session_issuance -- prompted
for biometric independently. Each prompt was distinct and operator-
acknowledged. v1-grade security model proven end-to-end on commodity
Android 16 hardware.

NOT in this round (round 8+):

- Push notification integration (still polling on a 3 s interval).
  Real APNs / FCM requires Apple Developer Program + Firebase Console
  credential ceremony, not just code.
- WebAuthn / passkey browser-login bridge.
- Phone-side unit tests for `TotpCodeCalculator`, `BootloaderClient`,
  `CapabilityJwtBuilder`, `PinningService`.
- Real Recto branding (icon, splash, wordmark).
- HTTPS-capable mock bootloader (would let us functionally test cert
  pinning end-to-end; small ~30 LOC addition with a self-signed
  cert generated at startup).

### Added — v0.4 phone app (round 6: capability JWT framework + TLS cert pinning)

Round 6 (2026-04-26) ships the architectural climax of the v0.4 phone
app: capability JWTs (the primitive that lets agents inherit from
humans without bypassing operator approval) plus HTTPS cert pinning
(closes the LAN-bootloader security gap). See ARCHITECTURE.md
2026-04-26 entry for the design rationale and `docs/v0.4-protocol.md`
"Capability JWTs (v0.5+)" + "TLS pinning (v0.5+)" sections for the
wire shapes.

**Capability JWT framework**

- **Protocol DTOs**: new `CapabilityJwtClaims` record (iss, sub, aud,
  exp, iat, jti, recto:scope, recto:max_uses, recto:bearer) with
  `[JsonPropertyName]` matching JWS conventions; new
  `CapabilityBearer` constants (`Bootloader = "bootloader"`,
  `AgentPrefix = "agent:"`). `PendingRequestContext` extended with
  optional `SessionBearer` / `SessionScope` /
  `SessionLifetimeSeconds` / `SessionMaxUses` /
  `SessionBootloaderId` fields. `RespondRequest` extended with
  optional `SessionJwt` field.
- **`Recto.Shared.Services.CapabilityJwtBuilder`** &mdash; manual JWT
  builder. Avoids `System.IdentityModel.Tokens.Jwt`'s
  `SignatureProvider` seam (which would require a custom
  `SecurityKey` impl to delegate to our async enclave). Instead
  builds the JWT directly: `base64url(header) + "."  +
  base64url(claims) + "." + base64url(signature)`, where the
  signature comes straight from
  `IEnclaveKeyService.SignAsync(signingInput)` &mdash; the same call
  that produces wire-format Ed25519 / ECDSA P-256 raw R||S
  signatures, which is exactly what JWS expects for EdDSA / ES256.
  ~70 LOC. Also exposes `Fingerprint(publicKey)` &mdash; SHA-256 of
  the raw public key, base64url-encoded &mdash; for the JWT `iss`
  claim.
- **`Home.razor`** pending-request rendering switch gains
  `session_issuance` branch (green "capability" badge, shows bearer +
  service/secret + scope + lifetime + max-uses).
  `ApproveSessionIssuanceAsync` builds and signs the JWT via
  `CapabilityJwtBuilder.BuildAsync` &mdash; biometric prompts as
  before since the JWT signing IS the enclave sign. POSTs the JWT
  back via the existing `/v0.4/respond/{id}` flow.
- **Mock bootloader** (`phone/dev-tools/mock-bootloader.py`):
  - `verify_capability_jwt` &mdash; manual JWS verification (no
    pyjwt dependency, just stdlib + cryptography). Splits the JWT,
    decodes header/claims/sig, dispatches on algorithm: EdDSA
    verifies directly via `Ed25519PublicKey.verify`; ES256
    reconstructs DER from the wire's raw R||S, then verifies via
    `ec.ECDSA(SHA256())`. Also checks `aud` matches the bootloader's
    own id, and `exp > now`.
  - State adds `issued_jwts` deque (newest first, max 20) tracking
    every JWT the phone signed back. Each entry shows the bearer,
    sub, scope, max_uses, exp, and verify status.
  - `/_queue_session_issuance` operator-UI button mints a
    `session_issuance` request with bearer = `bootloader`, scope =
    `["sign"]`, lifetime = 24h, max_uses = 1000.
  - `/v0.4/respond/{id}` handler dispatches to a per-kind branch for
    `session_issuance`: extracts the `session_jwt` field, verifies,
    stores in `issued_jwts` regardless of pass/fail (with verify
    error captured) so the operator UI can inspect failures.
  - New "Issued JWT capabilities" section in the operator UI lists
    bearer / sub / scope / max_uses / exp / verified status.
  - "Recent responses" section now distinguishes `session_issuance`
    decisions with bearer + exp summary.

**TLS cert pinning**

- **`Recto.Shared.Services.IPinningService` + `PinningService`** &mdash;
  thread-safe in-memory map from host to pin. Tracks both
  "observed" SPKIs (whatever the validation handler saw last) and
  "verified" pins (ones that were promoted to verification mode).
  Validation logic: if a pin is registered for the host, it's the
  only thing that matters &mdash; system trust outcome is irrelevant
  (which is what makes self-signed LAN bootloaders viable
  post-pairing); otherwise fall back to system trust.
- **`CertPinHelpers.ComputeSpkiPin`** &mdash; canonical SPKI pin form:
  SHA-256 of the cert's `ExportSubjectPublicKeyInfo()` bytes,
  base64url-encoded. Same form HPKP and Chrome's pinset use; matches
  what `openssl x509 -pubkey -noout | openssl asn1parse | sha256sum`
  produces for inspection.
- **`PairingState.BootloaderSpkiPin`** &mdash; new optional field
  carrying the pin captured at pairing time. Persisted in
  SecureStorage alongside the rest of the pairing record.
- **`AddSharedServices`** wires
  `HttpClientHandler.ServerCertificateCustomValidationCallback` via
  `ConfigurePrimaryHttpMessageHandler` to consult the pinning
  service for every connection. The validation callback always
  records the observed SPKI; verification dispatches via
  `IPinningService.Validate` (host, actual_spki, system_trust_ok).
- **`Home.razor`** captures the pin from `IPinningService.GetObservedPin`
  after successful pairing and stores it in PairingState. On app
  start (`OnInitializedAsync`), restores the pin into
  `IPinningService.SetPin` so the polling loop's first request
  enforces it. On unpair, calls `IPinningService.ClearPin` so a
  subsequent re-pair to a different bootloader doesn't carry the
  previous host's pin forward. Paired card now displays the pin
  (truncated) or "none (system trust only)" if pairing happened
  over plain HTTP (mock loopback for dev).

**Protocol RFC** (`docs/v0.4-protocol.md`):
- New "Capability JWTs (v0.5+)" section documenting the
  `session_issuance` kind, JWT format (header + claims + signature
  shape), bearer convention, and approval response. Notes that the
  earlier-sketched separate `/v0.4/issue_session` endpoint is
  subsumed by `/v0.4/respond/{id}` &mdash; same flow, fewer paths.
- New "TLS pinning (v0.5+)" section documenting the trust-on-first-use
  model, SPKI pin format, pin-mismatch failure mode, and pin
  invalidation / recovery.

NOT in this round (round 7+):

- Push notification integration (still polling on a 3 s interval).
- Lost-phone recovery (two-phone registration ceremony per RFC).
- WebAuthn / passkey browser-login bridge (the Keycloak-replacement
  integration on the web app side).
- Phone-side unit tests for `TotpCodeCalculator`, `BootloaderClient`,
  `CapabilityJwtBuilder`.
- Real Recto branding (icon, splash, wordmark).
- Composite/fallback enclave decorator.

### Added — v0.4 phone app (round 5: universal vault first kind — TOTP)

Round 5 (2026-04-26) ships the architectural pivot from "phone-resident
service-secret vault" to "universal credential platform" &mdash; the
same phone enclave + biometric ACL primitive serving any cryptographic
capability the operator carries. TOTP (RFC 6238) is the first non-
`single_sign` kind. See ARCHITECTURE.md 2026-04-26 entry for the design
rationale (universal vault scope expansion + capability-delegation as
the agent path), and `docs/v0.4-protocol.md` "TOTP capability" section
for the wire shapes.

- **Protocol DTOs**: `PendingRequestKind` constants gain
  `TotpProvision` and `TotpGenerate` (also `SessionIssuance` added as a
  forward-compat placeholder for the future capability-JWT framework).
  `PendingRequestContext` extended with optional `TotpAlias`,
  `TotpSecretB32`, `TotpPeriodSeconds`, `TotpDigits`, `TotpAlgorithm`
  fields &mdash; null for `single_sign`; `PayloadHashB64u` is now also
  nullable (only set for `single_sign`). `RespondRequest` gains
  optional `TotpCode` field for `totp_generate` approvals.
- **`Recto.Shared.Services`**: new `ITotpService` (Provision / Exists /
  Generate / Delete) and `TotpCodeCalculator` (pure-math RFC 6238
  implementation, HMAC-SHA1/256/512, RFC 4648 base32 decoder). Pure-
  managed; runs identically on iOS / Android / Windows / the macOS host targets.
- **`Recto.Services.MauiTotpService`**: SecureStorage-backed impl &mdash;
  TOTP secrets stored as JSON (secret_b32 + period + digits + algorithm)
  under `recto.phone.totp.{alias}`. Same OS keychain that holds
  pairing state and signing-key bytes.
- **`Home.razor`** pending-request rendering becomes kind-aware via a
  switch on `req.Kind`. `single_sign` cards keep the existing payload-
  hash / PID display; `totp_provision` cards show alias + period +
  digits + algorithm; `totp_generate` cards show the alias being
  asked. Approve dispatches to per-kind handlers
  (`ApproveSingleSignAsync` / `ApproveTotpProvisionAsync` /
  `ApproveTotpGenerateAsync`). The Paired card grew a "Last generated
  TOTP" alert that surfaces the code in large tabular-numeric type for
  ~30 seconds after generation, so the operator can read or copy it.
- **Mock bootloader** (`phone/dev-tools/mock-bootloader.py`):
  `compute_totp` + `verify_totp_code` Python implementation of RFC 6238
  (mirrors `TotpCodeCalculator` phone-side; verification accepts &plusmn;1
  time-step window). `b32_random_secret(20)` mints fresh 160-bit
  base32 secrets. State adds `totp_secrets` dict (server-side mirror
  keyed by alias) + `_totp_counter` (auto-generated alias suffix).
  Two new operator-UI buttons &mdash; "Queue TOTP provision" mints a
  fresh secret + alias and queues a `totp_provision` request, also
  storing the secret server-side for later verification; "Queue TOTP
  generate" queues a `totp_generate` for the most-recently-provisioned
  alias for the most-recently-paired phone. `/v0.4/respond/<id>` now
  dispatches per-kind, verifies `totp_code` against the server's
  stored secret (matches / expected-now both shown in operator UI).
  Two new operator-UI sections: "Provisioned TOTP aliases" lists
  server-known aliases with algorithm parameters (never the raw
  secret, small privacy gesture); "Recent responses" distinguishes
  single_sign / totp_provision / totp_generate response shapes with
  TOTP responses showing submitted code + expected code + green/yellow
  match marker.
- **Protocol RFC** (`docs/v0.4-protocol.md`) gains a new "TOTP
  capability (v0.5)" section documenting both new kinds, the extended
  `PendingRequestContext` shape, and the rationale for TOTP in a
  phone-resident vault. Protocol stays at version 1; additions are
  optional fields and new `kind` values.

Skipped from the earlier round-5 plan: the bootloader-internal session
JWT is subsumed under the future capability-JWT framework (see
ARCHITECTURE.md 2026-04-26). Issuing JWT capabilities to external
agents is the same primitive with bearer = agent rather than
bearer = bootloader.

NOT in this round (round 6+):

- WebAuthn-hybrid / PKCS#11 / PGP &mdash; additional credential kinds
  pending more design work.
- Capability JWT framework + agent identity registration.
- Push notification integration (still polling on a 3 s interval).
- HTTPS cert pinning.

### Added — v0.4 phone app (round 4: pending sign-request flow live)

The MAUI Blazor phone app's fourth round (2026-04-26) ships the core
end-to-end feature: the operator can approve or deny incoming sign
requests with biometric, and the signature flies back to the
bootloader for verification. Single-sign mode only; session JWT
issuance + caching is round 5.

- **`Recto.Shared/Protocol/V04/`** &mdash; new DTOs: `PendingRequest`
  (kind, service, secret, context), `PendingRequestContext`
  (`child_pid`, `child_argv0`, `requested_at_unix`,
  `operation_description`, `payload_hash_b64u`),
  `PendingRequestsResponse`, `RespondRequest` (phone_id, decision,
  signature_b64u, reason), `RespondResponse`. `PendingRequestKind` and
  `RespondDecision` constants. Every property carries
  `[property: JsonPropertyName]` matching the RFC's snake_case wire
  format byte-for-byte.
- **`IBootloaderClient`** extended with `GetPendingAsync(url,
  phoneId, ct)` &mdash;
  `GET /v0.4/pending?phone_id=...` &mdash; and `RespondAsync(url,
  requestId, body, ct)` &mdash;
  `POST /v0.4/respond/{requestId}`. Same Result&lt;T&gt; error-mapping
  as existing methods; never throws.
- **`Home.razor`** Paired card now embeds a Pending Sign Requests
  section with one card per pending request (operation description,
  service/secret, truncated payload-hash, child PID + argv0). Approve
  triggers `IEnclaveKeyService.SignAsync(payload_hash)` &mdash; iOS
  Secure Enclave / Android StrongBox prompt for biometric &mdash;
  then POSTs the signed response. Deny POSTs an "operator declined"
  response with no signature. Live count badge in the section header.
- **3-second polling loop** while paired (`PollLoopAsync` driven by a
  `CancellationTokenSource`, started after pair / re-pair, stopped on
  unpair). Push notifications are round 5+ work; for now the phone
  pulls. Component implements `IAsyncDisposable` to cancel the loop on
  teardown.
- **Mock bootloader** (`phone/dev-tools/mock-bootloader.py`) extended
  with: `GET /v0.4/pending` (filtered by phone_id), `POST
  /v0.4/respond/{id}` (verifies signature against the registered
  public key using the phone's stored algorithm, records verified /
  unverified status), `POST /_queue` (operator-UI button mints a fake
  single-sign request targeting the most-recently-registered phone
  with a random managed secret + random 32-byte payload hash). New
  operator-UI sections: "Pending sign requests" (live list of queued
  requests waiting on phone approval), "Recent responses" (decision
  + truncated signature + verified marker). Existing per-request
  stdout logging covers the new endpoints automatically.
- **Protocol RFC** clarification: <c>/v0.4/pending</c> now documents
  the <c>?phone_id=...</c> query parameter; <c>/v0.4/respond/&lt;id&gt;</c>
  now documents the <c>phone_id</c> field in the body. Additive only;
  protocol stays at version 1.

NOT in this round (round 5+):

- Composite/decorator fallback impl (still deferred until real-device
  failure rates surface).
- Session JWT issuance + caching (`POST /v0.4/issue_session`) &mdash;
  the latency optimization that turns first-sign-of-the-session into
  a cached-JWT replay for subsequent signs.
- Push notification helpers (APNs / FCM) &mdash; today the phone polls
  every 3 s; production deployments need wake-from-background.
- HTTPS cert pinning for bootloader connections.

### Added — v0.4 phone app (round 3: native enclave + multi-algorithm)

The MAUI Blazor phone app's third round shipped 2026-04-26: real
hardware-enclave-backed keys on iOS and Android, with biometric ACLs
gating every signature operation. The `phone/` tree remains gitignored
at the repo root.

- **`IEnclaveKeyService` refactored for multi-algorithm.** Added
  `string Algorithm { get; }` so each platform impl advertises its
  signature scheme. Replaced `Ed25519KeyPair` (which exposed raw
  PrivateKey, useless for enclave-resident keys) with
  `EnclavePublicKey(byte[] PublicKey, string Algorithm)`. Algorithm
  constants live on `V04Protocol.AlgorithmEd25519` /
  `V04Protocol.AlgorithmEcdsaP256`.
- **`Platforms/iOS/IosSecureEnclaveKeyService.cs`** — iOS Secure
  Enclave-backed via `SecKeyCreateRandomKey` with
  `kSecAttrTokenIDSecureEnclave` + `SecAccessControl` flags
  `BiometryCurrentSet | PrivateKeyUsage`. Key is non-exportable;
  every sign triggers Face ID / Touch ID. Algorithm: `ecdsa-p256`
  (Secure Enclave does not natively support Ed25519 &mdash; see
  CLAUDE.md gotcha). Signatures come out of `SecKeyCreateSignature`
  in DER form (SEQUENCE { r INTEGER, s INTEGER }); converted to the
  protocol's 64-byte raw R||S form via `System.Formats.Asn1.AsnReader`
  before sending. Public keys stripped from the platform's 65-byte
  uncompressed form (0x04 || X || Y) to the protocol's 64-byte raw
  X || Y. `.biometryCurrentSet` ACL deliberately invalidates the key
  if the user enrolls a new biometric; that's a re-pair event in the
  current model.
- **`Platforms/Android/AndroidStrongBoxKeyService.cs`** — Android
  StrongBox-backed via `KeyPairGenerator.GetInstance("Ed25519",
  "AndroidKeyStore")` + `KeyGenParameterSpec.Builder` with
  `SetIsStrongBoxBacked(true)`, `SetUserAuthenticationRequired(true)`,
  `SetUserAuthenticationParameters(30, BiometricStrong |
  DeviceCredential)`. 30-second grace window after biometric prompt to
  avoid re-prompting on chained operations. Falls back gracefully to
  TEE-backed (still hardware-isolated, just not the dedicated HSM) on
  devices without StrongBox via `StrongBoxUnavailableException` retry.
  Algorithm: `ed25519`. Public-key extraction strips the X.509
  SubjectPublicKeyInfo wrapper (44 bytes total, raw key at offset 12)
  to the protocol's 32-byte raw form.
- **DI plumbing.** `MauiProgram.cs` uses `#if IOS / #elif ANDROID /
  #else` to pick the right impl per target framework; iOS gets the
  Secure Enclave service, Android gets StrongBox, Windows / the macOS host
  Catalyst dev hosts keep the `SoftwareEnclaveKeyService`
  (BouncyCastle Ed25519) as the dev-loop backing.
- **Platform manifests.** iOS `Info.plist` adds
  `NSFaceIDUsageDescription`. Android `AndroidManifest.xml` adds
  `android.permission.USE_BIOMETRIC` plus `uses-feature` declarations
  for `fingerprint` and `strongbox_keystore` (both `required="false"`
  so the app is installable on devices that lack the hardware).
- **`Home.razor`** displays the active signing algorithm (in both the
  unpaired form and the Paired card), and the busy text during sign
  becomes "Awaiting biometric approval&hellip;" so the user knows the
  prompt is coming.
- **Mock bootloader extended for ECDSA P-256 verification.**
  `phone/dev-tools/mock-bootloader.py` now verifies both algorithms
  (when `cryptography` is installed): Ed25519 directly,
  ECDSA P-256 by reconstructing the public key from the 64-byte raw
  X || Y, decoding the 64-byte raw R || S signature into integers,
  re-encoding via `encode_dss_signature` for `cryptography`'s verify,
  hashing the message with SHA-256. Rejects unknown algorithms with
  400. Operator UI displays the algorithm per registered phone.
  Managed-secrets canned response now mirrors the phone's algorithm
  per registration (iOS-paired phones see `ecdsa-p256` secrets;
  Android/Windows-paired phones see `ed25519`).
- **Protocol RFC** (`docs/v0.4-protocol.md`) Cryptographic primitives
  section rewritten as a per-algorithm enumeration; Implementation
  guidance section updated to reflect the iOS-uses-P-256 reality and
  the Android StrongBox specifics. Protocol stays at version 1
  &mdash; the `supported_algorithms` negotiation seam was already
  designed for exactly this.

NOT in this round (round 4+):

- Composite/decorator impl that falls back to software when the
  primary platform impl errors (deferred until real-device testing
  surfaces actual failure rates).
- Session JWT issuance + caching (`POST /v0.4/issue_session`).
- Pending-poll loop + push notification handling.
- Sign-request UI + signature response (`POST /v0.4/respond/<id>`).
- HTTPS cert pinning for bootloader connections.

### Added — v0.4 phone app (rounds 1+2: scaffold cleanup + pairing wire-protocol live)

The MAUI Blazor phone app under `phone/` shipped its first two rounds,
complementing the server-side substrate batch 1 below. The tree is
gitignored at the repo root until the phone-side work is ready for
public-domain promotion alongside the rest of v0.4.

- **Round 1 (scaffold sanitize, 2026-04-26).** Pruned the original
  template scaffold to a minimal phone+shared shape (Recto +
  Recto.Shared). Wiped four non-phone projects (Web, Web.Client,
  AppHost, ServiceDefaults) plus the data layer. Kept the generic
  helpers in Recto.Shared (Result<T>, Error, Unit, HttpStatus,
  ICommandHandler/IQueryHandler, Logging/Validation decorators,
  IFormFactor seam). Stripped CascadingAuthenticationState +
  AuthorizeRouteView from Routes.razor (v0.4 pairing isn't auth in
  the Identity sense). Replaced Home.razor with the v0.4 pairing
  empty-state UI (Recto wordmark, "Not paired yet" card, 6-digit
  pairing-code input, IFormFactor footer). Solution builds clean on
  .NET 10 + MAUI workload; Windows MAUI launches at 1400x900 on the
  primary monitor.
- **Round 2 (pairing wire-protocol, 2026-04-26).** Implemented the
  `GET /v0.4/registration_challenge` + `POST /v0.4/register`
  handshake end-to-end. New surfaces in Recto.Shared:
  - `Protocol/V04/`: RegistrationChallengeResponse,
    RegistrationRequest (+ RegistrationProof), RegistrationResponse
    (+ ManagedSecretInfo). Every property carries
    `[property: JsonPropertyName]` matching the RFC's snake_case
    wire format byte-for-byte.
  - `Models/`: Ed25519KeyPair, PairingState (+ ManagedSecretRef).
  - `Services/`: IBootloaderClient (per-call URL, Result<T>-based
    error mapping, never throws); IEnclaveKeyService (generate /
    exists / pubkey / sign / delete); IPairingStateService (get /
    save / clear / GetOrCreatePhoneId).
  - `BootloaderClient` impl: typed HttpClient with 15s timeout, no
    Polly retry on the user-initiated pairing path (retry just
    delays actionable error messages). Pre-serializes via
    `JsonSerializer.Serialize` + `StringContent` to dodge the
    `JsonContent.Create` empty-body MAUI-pipeline gotcha (see
    CLAUDE.md Gotchas index). Logs the serialized JSON at
    LogInformation so VS Output mirrors the wire.

  New surfaces in the MAUI host (`Recto/Recto/`):
  - `Services/SoftwareEnclaveKeyService.cs` &mdash; BouncyCastle
    Ed25519PrivateKeyParameters + Ed25519Signer; persists
    base64-encoded keypair via `SecureStorage` under
    `recto.phone.identity.{privkey,pubkey}`. Round-3 swap target
    for native iOS SecKey + Android StrongBox.
  - `Services/MauiPairingStateService.cs` &mdash; PairingState as
    JSON in SecureStorage; persistent phone_id minted as uuid4 on
    first call.
  - DI registrations in `MauiProgram.cs`; window dimensions
    (1400x900 on primary monitor) in `App.xaml.cs`.

  Home.razor rewritten as a 6-step pairing state machine: get/create
  phone id &rarr; request challenge &rarr; ensure keypair &rarr;
  sign &rarr; register &rarr; persist state. Loading spinner with
  per-step text; error alerts surface BootloaderClient failures
  verbatim. Paired-state view shows bootloader id, phone id,
  paired-at, managed secrets list, and an Unpair button. Pairing
  state survives app restart (verified 2026-04-26).

  BouncyCastle.Cryptography pinned at 2.4.0 (pure-managed Ed25519,
  no native libsodium dep &mdash; works across every MAUI target
  without per-platform packaging).

- **Dev tooling.** `phone/dev-tools/mock-bootloader.py` ships a
  stdlib-only Python harness implementing both pairing endpoints
  plus a small operator-side index page (mint pairing code, watch
  recent requests, see registered phones). Optional `cryptography`
  dependency enables real Ed25519 signature verification; without
  it, signatures are accept-any. Verbose stdout logging shows
  Content-Type / Content-Length / body for incoming POSTs and
  status / error-body for outgoing responses &mdash; designed for
  fast wire-shape iteration during phone-app dev.

End-to-end paired against the mock bootloader 2026-04-26: 32-byte
public key (43 chars b64u), 64-byte signature (86 chars b64u), wire
format matches the RFC byte-for-byte. Subsequent `cryptography`
install enabled real signature verification on the mock side; the
BouncyCastle-generated keypair signs RFC 8032 conformant.

NOT in this round (round 3+ work tracked in ROADMAP.md):

- Native enclave key generation (iOS Secure Enclave / Android
  StrongBox) via DI override.
- Biometric prompt on sign (LAContext / BiometricPrompt).
- Session JWT issuance + caching (`POST /v0.4/issue_session`).
- Pending-poll + push notification handling.
- Sign-request UI + signature response (`POST /v0.4/respond/<id>`).
- HTTPS cert pinning for bootloader connections (today the system
  trust store accepts only valid certs; Cloudflare Tunnel works,
  self-signed LAN does not).

### Added — v0.4 substrate (phone-resident vault, server-side)

The launcher-side substrate for the v0.4 marquee feature: secrets that
never sit on the server. Private keys live in a phone's Secure Enclave
(iOS) or StrongBox (Android); each cryptographic operation is biometric-
gated on the phone. This commit ships everything that lives on the
server; the phone app is a separate MAUI Blazor project under `/phone/`
(in development).

- **`docs/v0.4-protocol.md`** — wire-protocol RFC for phone <-> bootloader.
  Covers: components, HTTPS endpoints (`/v0.4/register`,
  `/v0.4/registration_challenge`, `/v0.4/issue_session`, `/v0.4/pending`,
  `/v0.4/respond/<id>`), key onboarding flow, sign-request flow,
  session-token model (short-lived JWT for ergonomics), failure modes,
  security model. Locked decisions: personal-use distribution (no app
  store), HTTPS + push wakeup (no QUIC), Ed25519 signatures, short-lived
  JWT sessions. Comprehensive enough that the MAUI Blazor app can be
  built independently against the same contract.
- **`recto.secrets.enclave_stub.EnclaveStubSource`** — in-memory
  Ed25519 backend for end-to-end testing of the launcher's
  SigningCapability code path WITHOUT phone hardware. Generates a key
  in process memory; signs locally. Selector: `enclave-stub` (NOT
  `enclave`) so a misconfigured production service.yaml fails loudly
  rather than silently using the wrong backend. Optional deterministic
  seed for reproducible test fixtures. Requires `cryptography`
  (`pip install recto[v0_4]`); import raises a clear remediation error
  if the extra isn't installed.
- **`recto.bootloader`** package — server-side bridge between the
  launcher and the phone-resident vault.
  - `state.StateStore` — thread-safe persistence of phones, session
    JWTs, and pending sign requests under
    `~/.recto/bootloader/{phones,sessions,pending}.json`. ACL-tightened
    to operator-only on Linux/macOS; Windows inherits per-user APPDATA
    permissions. Pending requests intentionally NOT persisted across
    restart (in-flight requests fail rather than carrying over dirty
    state).
  - `sessions` module — JWT EdDSA verify + raw Ed25519 signature verify
    wrappers over `pyjwt` + `cryptography`. Lazy imports surface clear
    errors when [v0_4] extra isn't installed.
  - `server.BootloaderHandler` + `create_server` — stdlib-only
    `ThreadingHTTPServer` implementing the v0.4 endpoint set. TLS via
    `ssl.SSLContext` (caller-provided cert chain). Single-process, one
    bootloader per service.
- **`recto.sign_helper`** — local-socket sign-helper between launcher
  and supervised child process. The launcher exposes a Unix socket per
  service (Linux/macOS only in v0.4.0; Windows named pipe is followup).
  Wire format: 4-byte BE length-prefixed UTF-8 JSON. Requests are
  `{kind: "sign", secret, payload_b64u}`; responses are
  `{ok: true, signature_b64u, algorithm, public_key_b64u}` or
  `{ok: false, error, detail}`. `SignHelperClient.from_env()` reads
  `RECTO_SIGN_HELPER` env var that the launcher sets on the child.
  Reference Python client; other-language clients implement the same
  wire format.
- **`pyproject.toml`** — new `[v0_4]` optional-deps extra
  (`cryptography>=42`, `pyjwt[crypto]>=2.8`). Install with
  `pip install recto[v0_4]` to enable the bootloader and stub backend.
- **`.gitignore`** — `phone/**/{bin,obj,.vs,packages,...}/` for MAUI
  Blazor build artifacts. Source under `phone/` is tracked; only
  compile outputs are ignored.
- **64 new tests** across `tests/test_secrets_enclave_stub.py`,
  `tests/test_bootloader_state.py`, `tests/test_bootloader_sessions.py`,
  `tests/test_sign_helper.py`. Round-trip Ed25519 signing,
  JWT verify with valid / expired / wrong-audience / wrong-key cases,
  state-store concurrency + persistence + revocation cascade, sign-
  helper end-to-end via real Unix sockets, frame-protocol edge cases.

NOT in this commit (followup work tracked):

- Launcher integration (`recto.launcher` extension to detect
  SigningCapability returns and start `SignHelperServer`).
- CLI `recto v0.4 register / revoke / list-phones / serve` subcommands.
- Bootloader server end-to-end HTTP integration tests.
- Push-notification helpers (APNs / FCM) -- placeholder TODO in
  `bootloader/server.py`.
- Windows named-pipe transport for `sign_helper` (Linux/macOS sockets
  only in v0.4.0).
- The phone app itself (MAUI Blazor; in `/phone/`, separate build).

### Added — `recto secrets list <service>` (backend-agnostic secret enumeration)

- New `secrets` subcommand group with one subcommand initially:
  `list <service>`. Walks every registered SecretSource backend
  (credman, dpapi-machine, plus any third-party backends registered
  via `register_source`) and prints one line per installed secret
  prefixed with `[<backend-name>]`. Output is grep-friendly:
  `recto secrets list svc | grep '\[dpapi-machine\]'` filters by
  backend; `awk '{print $2}'` strips the prefix.
- Backends without a `list_names` method (e.g. `EnvSource` whose
  inventory is the entire process env-var space, with no
  enumeration primitive) are silently skipped. Per-backend errors
  (SecretSourceError, OSError) are reported on stderr but don't
  abort the iteration through the remaining backends.
- Papercut #2 fix from second-consumer migration 2026-04-26.
  `recto credman list` is preserved (no breakage); operators with
  existing scripts targeting it keep working.

### Added — `metadata.display_name` YAML field (additive, v0.1 backward-compat)

- New optional field `metadata.display_name` lets operators set NSSM
  `DisplayName` independently of `Description`. When present,
  `recto apply` writes it to NSSM `DisplayName` while
  `metadata.description` continues to drive NSSM `Description`. When
  absent, the v0.2.0 fallback applies (`description` -> DisplayName,
  or service name if both are empty) so existing service.yaml files
  keep working unchanged.
- `recto migrate-from-nssm` now emits NSSM DisplayName ->
  `metadata.display_name` and NSSM Description ->
  `metadata.description` as distinct YAML fields. Pre-Papercut-#3
  behavior collapsed NSSM DisplayName into the YAML's `description`
  field, which on round-trip through `recto apply` then wrote the
  same string back into BOTH NSSM registry parameters -- lossy. New
  migrations preserve the distinction.
- Hard Rule #1 compliance: additive only. apiVersion stays at
  `recto/v1`. No removed or renamed fields.

### Fixed — `recto apply` no longer overwrites Application with bare `python.exe`

- Pre-fix: `recto apply` defaulted `--python-exe` to the literal
  string `"python.exe"`, so an apply against a service whose NSSM
  `Application` was a fully-qualified path (e.g.
  `C:\Python314\python.exe`) silently proposed overwriting it with
  the bare name. Service then failed to start under any
  service-account context whose PATH didn't resolve `python` to the
  right interpreter.
- Post-fix: `--python-exe` defaults to `None`. When omitted,
  `_cmd_apply` reads NSSM's current `Application` and uses that as
  the desired value -- the apply proposes no change to that field
  unless the operator explicitly passes `--python-exe`. Backward-
  compat fallback when NSSM `Application` is empty (a freshly
  `nssm install`ed service that's never been Recto-wrapped):
  defaults to `"python.exe"` so the apply can still wire a usable
  Application. `recto.reconcile.compute_plan`'s `python_exe` keyword
  argument is unchanged (still defaults to `"python.exe"`); the
  resolution lives at the CLI layer.
- Papercut #1 fix from second-consumer migration 2026-04-26.

### Fixed — `migrate-from-nssm --keep-as-env` warns on missing entries

- Pre-fix: `--keep-as-env=NAME1,NAME2,NAME3` silently skipped any
  name not present in the source NSSM `AppEnvironmentExtra`. An
  operator passing `--keep-as-env=KEY1,KEY2,TYPO_KEY3` would get
  KEY1 and KEY2 routed to the YAML's env block as expected, while
  TYPO_KEY3 vanished without trace -- and the operator chasing
  "expected 15 lines, got 14" downstream had no clue which name
  was the offender.
- Post-fix: each missing name emits a separate `WARNING:` line on
  stderr like `recto migrate-from-nssm: warning: --keep-as-env
  entry 'TYPO_KEY3' not found in source AppEnvironmentExtra
  (skipping)`. Migration still proceeds with the names that DO
  match (no behavior change for the non-typo case).
- Papercut #4 fix from second-consumer migration 2026-04-26.

### Added — `dpapi-machine` secret backend (machine-bound DPAPI file storage)

- New `recto.secrets.dpapi_machine.DpapiMachineSource` implements
  `SecretSource` using `CryptProtectData` with the
  `CRYPTPROTECT_LOCAL_MACHINE` flag. Storage at
  `C:\ProgramData\recto\<service>\<name>.dpapi` — encrypted at rest,
  bound to the machine's keying material rather than the per-user
  master key. Any process on the same machine can decrypt regardless
  of which user wrote the secret; processes on other machines cannot.
- Solves the per-user limitation of the `credman` backend: when a
  service runs as `LocalSystem` and the migrator runs as an admin
  user, CredMan returns `ERROR_NOT_FOUND` because credentials are
  scoped to the writing user. DPAPI's machine-key flavor sidesteps
  the problem — the security boundary is the machine, not the user.
- Registered under selector `dpapi-machine`. Use in service.yaml as
  `source: dpapi-machine`. `recto migrate-from-nssm` accepts
  `--secret-backend=dpapi-machine` to emit the new selector + write
  through the new backend.
- Threat model: anyone with code-exec on the machine can decrypt;
  anyone with file-read but not code-exec cannot. Same boundary as
  Windows DPAPI itself. ACLs on the storage directory default to
  ProgramData's standard (Administrators+SYSTEM read+write, Users
  read); tightening to SYSTEM-only is a follow-up but isn't required
  for the documented threat model.
- 27 new tests in `tests/test_secrets_dpapi_machine.py`. Cross-platform
  tests use `FakeDpapiMachineSource` with in-memory storage (mirrors
  the FakeCredManSource pattern). Windows-only `TestWindowsLiveDpapi`
  class exercises the actual ctypes path against live `crypt32.dll`,
  using a tempdir-isolated `PROGRAMDATA` so it can't touch operator-
  installed secrets. Three live tests cover round-trip, Unicode
  values, and "ciphertext is not plaintext on disk" smoke.

### Added — `migrate-from-nssm --secret-backend=...` flag + per-user/service-account mismatch detection

- `recto migrate-from-nssm` now accepts `--secret-backend=credman` (default,
  v0.2 behavior preserved) or `--secret-backend=dpapi-machine`. The
  generated YAML's `secrets[].source` is templated from the chosen
  backend; the apply path resolves the corresponding `SecretSource`
  via the existing `register_source` plugin layer.
- Pre-flight check for the credman path: when the migrator's current
  user (via `getpass.getuser()`) doesn't match the NSSM service's
  `ObjectName` (typically `LocalSystem` for a Windows service), apply
  refuses with a clear error message pointing at
  `--secret-backend=dpapi-machine` as the recommended fix. Catches
  the would-be-bombed-at-start-time case at apply time, before any
  destructive operation. Dry-run skips the check (no destructive
  operation to protect against).
- Plan JSON output now includes a `secret_backend` field so operators
  reviewing the dry-run see which backend will receive the migration.

### Fixed — `_decode_nssm` plumbing: `ctypes.windll.advapi32` doesn't track GetLastError

- All four `_win_*` helpers in `recto/secrets/credman.py` previously
  used `ctypes.windll.advapi32`, which returns a WinDLL handle WITHOUT
  the `use_last_error` flag enabled. As a result `ctypes.get_last_error()`
  always returned 0 even when the underlying Win32 call had set a real
  GetLastError code. Every CredMan failure surfaced as `Win32 error 0`
  (= ERROR_SUCCESS), masking the real cause.
- This was bug 5a, surfaced 2026-04-26 round 6 of the first-consumer migration.
  The masked underlying error was `ERROR_NOT_FOUND` from CredReadW
  when running as LocalSystem against an admin-user-written CredMan entry —
  the per-user bug that motivated the new `dpapi-machine` backend.
- Fix: `ctypes.WinDLL("advapi32", use_last_error=True)` everywhere.
  Same pattern applied to crypt32 / kernel32 calls in the new
  `dpapi-machine` backend so future failures there will also surface
  the real Win32 error code.

### Fixed — `CredManSource` was missing four `_*_blob` wrapper methods

- `CredManSource.fetch` / `write` / `delete` / `list_names` all called
  `self._read_blob` / `self._write_blob` / `self._delete_blob` /
  `self._list_targets` — none of which existed on the class. Module-
  level `_win_read_blob` / `_win_write_blob` / `_win_delete_blob` /
  `_win_list_targets` (the ctypes -> advapi32 implementations) were
  there, but the platform-dispatch wrapper layer that should have
  delegated `self._*_blob -> _win_*_blob` on Windows was never written.
- Result on Windows: every `CredManSource` operation that touched real
  CredMan storage failed with `AttributeError: 'CredManSource' object
  has no attribute '_write_blob'` (or the equivalent for the three
  other methods). `recto migrate-from-nssm` apply path bombed at
  `cli.py:342 → credman.py:347` on the first `cred.write(...)` call.
- Test suite missed it: `tests/test_secrets_credman.py::FakeCredManSource`
  subclasses `CredManSource` and overrides the four `_*_blob` methods
  per-instance, so Python's method resolution finds the overrides on
  the instance and never hits the missing class-level wrappers. 238
  tests passed against the masked-by-fake implementation.
- Fix: added four wrapper methods on `CredManSource` that delegate to
  the corresponding `_win_*` module-level functions. Comment block
  documents the platform-dispatch seam (where `_mac_*` / `_lin_*`
  backends will plug in for v0.3 macOS Keychain / Linux Secret
  Service support).
- Added `tests/test_secrets_credman.py::TestWindowsLiveCredMan`: a
  `pytest.mark.skipif(sys.platform != "win32")` class that exercises
  the actual `_win_*` ctypes path against live Credential Manager,
  using UUID-scoped service names + try/finally cleanup so it can't
  collide with operator-installed credentials. Five tests cover the
  round-trip, Unicode values, comments, missing-key error, and per-
  service `list_names` filtering. This regression class would have
  caught the original missing-wrapper bug on a single CI run if a
  Windows runner had been in place.
- Also completed the previously-truncated `TestEndToEnd::test_full_lifecycle`
  body (the file ended mid-method on disk; pytest treated the
  docstring-only body as a passing no-op). Now exercises the canonical
  write -> list -> fetch -> rotate -> delete flow against
  `FakeCredManSource`.

### Fixed — `_decode_nssm` mojibaked UTF-8 NSSM output as UTF-16-LE

- The encoding-autodetect in `_decode_nssm` tried `bytes.decode("utf-16-le")`
  first on any even-length buffer and only fell through to UTF-8 if the
  decode raised. UTF-16-LE NEVER raises on ASCII byte pairs — every pair
  maps to a valid (mojibake) codepoint in the U+3000–U+7FFF range. So
  ASCII-only fields whose byte length happened to be even came back as
  CJK gibberish (e.g. `b"C:"` → `U+3A43` = `"㩃"`).
- Surfaced when round-3 of a real `migrate-from-nssm` dry-run rendered
  `current_app_parameters` and `current_app_directory` as
  `"㩃啜敳獲..."` — both fields are 60 / 26 bytes (even);
  `current_app_path` is 23 bytes (odd) so it sneaked through the UTF-16-LE
  attempt and decoded correctly via the UTF-8 fallback. The asymmetry
  between fields was the diagnostic — the operator's diagnostic msg
  `20260426022526-9378` reported it cleanly.
- Underlying NSSM behavior: NSSM uses wide-char Win32 APIs for multi-string
  registry values (`REG_MULTI_SZ` — `AppEnvironmentExtra`) and emits them
  as UTF-16-LE; for single-string values (`REG_SZ` / `REG_EXPAND_SZ` —
  `Application`, `AppParameters`, `AppDirectory`, `AppExit`, `DisplayName`,
  `Description`) it emits UTF-8 / system codepage. The decoder must
  handle both without false positives.
- Fix: replaced length-only heuristic with positive-evidence detection.
  UTF-16 if BOM present (`\xff\xfe` or `\xfe\xff`); UTF-16-LE if every
  odd-indexed byte is NUL (the ASCII-in-UTF-16-LE signature); else
  UTF-8 default; else cp1252 with `errors="replace"`. Module docstring
  + `SubprocessRunner` typedef + `_decode_nssm` docstring all updated to
  document the mixed-encoding NSSM emit.
- 9 new tests in `tests/test_nssm.py::TestDecodeNssm` covering: UTF-8
  ASCII (the regression), UTF-8 odd-length (Application path), UTF-8
  with high bytes (em-dashes etc.), UTF-16-LE with BOM, UTF-16-LE
  without BOM via heuristic, UTF-16-BE with BOM, str passthrough, empty
  bytes, and invalid-bytes fallback.

### Fixed — `AppExit` is a compound NSSM parameter; flat-iterator bombed

- `recto migrate-from-nssm`'s second-attempt dry-run (after the
  `Application` rename in the prior commit) bombed at the next field in
  `NSSM_FIELDS`: `nssm get <service> AppExit` returns `Parameter "AppExit"
  requires a subparameter!`. NSSM has a small family of *compound*
  parameters that require either an exit code or `Default` as a
  subparam — `AppExit` and `AppEvents` are the two seen in the wild. The
  flat iterator in `NssmClient.get_all` was treating every field as a
  3-arg `nssm get <svc> <field>`, which bombs for compound params.
- Fix: `NssmClient.get` now accepts variadic `*subparams: str` after the
  field name; `get_all` calls `self.get(service, "AppExit", "Default")`
  for the AppExit row and stays flat for everything else. The
  `AppExit` value preserved in `NssmConfig.app_exit` is now the
  Default-action string (e.g. `"Restart"`) instead of bombing the read.
  Added comment in `NSSM_FIELDS` flagging which entries are compound,
  so future additions don't regress. `AppEvents` is documented in
  `NssmClient.get`'s docstring as the next compound-param candidate
  (not currently in `NSSM_FIELDS`; if/when added, the same special-
  casing applies).
- Two new tests in `tests/test_nssm.py`: variadic-get with subparam,
  and compound-get error-message formatting.

### Fixed — wrong NSSM parameter name on migrate + apply paths

- `recto migrate-from-nssm` and `recto apply` were calling NSSM with the
  parameter name `AppPath` for the executable-path field, which NSSM
  rejects with `Invalid parameter "AppPath"`. The correct NSSM parameter
  name is `Application`. The bug was masked by the test suite — fixtures
  used the same incorrect literal as the production code, so tests
  asserted on a fiction NSSM never agreed with. Surfaced when the first
  real `migrate-from-nssm <service> --dry-run` against a live NSSM service
  bombed at the read step. Fix: literal-string rename in `recto/nssm.py`,
  `recto/cli.py`, `recto/reconcile.py`, and matching test fixtures in
  `tests/test_nssm.py`, `tests/test_cli.py`, `tests/test_reconcile.py`.
  Python attribute `app_path` and migration-plan key `new_app_path` keep
  their existing names — they're our abstraction, not NSSM's. No
  destructive changes were made on the box where the bug was found
  (Recto's call to `nssm get` failed before any mutation step ran);
  the consumer's NSSM config is unchanged from before the migration attempt.

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
  subclass overrides, and the operator's full-Windows smoke run
  exercises the real ctypes / OTel paths.

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
  declarative GitOps. Reconciles Application, AppParameters, AppDirectory,
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
  helper raises the same error type. Per the 2026-04-25 IM-update
  decision: SecretSourceError is the canonical secret-backend error
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
    Application at `python.exe`, set AppParameters to
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
