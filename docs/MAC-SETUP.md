# MAC-side setup for Recto

Recto's Mac mini host plays two roles for this repo:

1. **macOS pytest CI** — runs the suite via a GitHub Actions
   self-hosted runner. Unlocks ~17 platform-gated tests that
   currently skip on Windows (`test_sign_helper` Unix-socket flow,
   `test_joblimit` Linux/macOS Win32-Job-Object-not-supported
   guards, `test_secrets_credman`/`test_secrets_dpapi_machine`
   "Windows only" reverse-gates, `test_adminui` SO_REUSEADDR
   semantics).

2. **iOS deploy host** — builds and deploys the MAUI Blazor app to
   real iPhone hardware via Xcode + the Apple Developer Program
   certificate / provisioning profile. The phone's Secure Enclave
   path (`Platforms/iOS/IosSecureEnclaveKeyService.cs`) and APNs
   integration (`IosApnsPushTokenService.cs`) have been written
   but never validated on real hardware — this host enables that.

This document is the runbook for both. It uses the convention
`<RECTO_CLONE>` as a placeholder for wherever you cloned the Recto
repo on this machine. **GitHub Desktop's default landing dir is
`~/Documents/GitHub/Recto`** — that's the most likely value. CLI
clones default to `~/Recto`. Substitute whichever applies.

The actions-runner install dir (`~/actions-runner-recto/` below)
is INDEPENDENT of `<RECTO_CLONE>` — the runner manages its own
ephemeral checkouts in `_work/Recto/Recto/` regardless of where
your human-facing clone lives.

---

## Part A — GitHub Actions self-hosted runner for Recto

The runner runs `python3 -m pytest tests/` on every push to main
and on PRs. Mirrors the AllThruit / Verso runners already on MAC.

### Coexistence

If MAC already hosts an `actions.runner.erikcheatham-AllThruit.MAC`
runner for the AllThruit Reader-App MAUI build, **do not register
a Recto runner in the same install dir.** Each runner needs its
own checkout / config / credentials. Use a separate dir:

```
~/actions-runner-recto/
```

### Register

1. Go to https://github.com/erikcheatham/Recto/settings/actions/runners
2. Click "New self-hosted runner" → choose macOS → ARM64
3. Copy the `--token <29-char>` value from the displayed config block
4. On MAC, in a fresh terminal:

```bash
mkdir -p ~/actions-runner-recto
cd ~/actions-runner-recto
# Download the runner package (URL from the GitHub UI's instructions)
curl -o actions-runner-osx-arm64.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.334.0/actions-runner-osx-arm64-2.334.0.tar.gz
tar xzf actions-runner-osx-arm64.tar.gz

# Register. The --labels MUST include 'recto' (matches runs-on in
# .github/workflows/test-mac.yml). The default 'self-hosted, macOS,
# ARM64' implicit labels come for free.
./config.sh \
  --url https://github.com/erikcheatham/Recto \
  --token "<paste-token-here>" \
  --name MAC-recto \
  --labels recto \
  --unattended \
  --replace
```

5. Install as a launchd service so it survives reboots:

```bash
./svc.sh install
./svc.sh start
./svc.sh status
```

Confirm the runner shows `Idle` at
`https://github.com/erikcheatham/Recto/settings/actions/runners`.

### Smoke-test the workflow

Push any trivial change to `main` (or trigger via the
workflow_dispatch button in the GitHub UI). The Test-on-macOS
workflow should pick up within ~5 seconds. Look for:

```
runs-on: [self-hosted, macOS, ARM64, recto]
```

…and a passing pytest output that's larger than the Windows run
(more tests, fewer skips).

### Recovery patterns

The runner self-update can corrupt the install non-deterministically
(documented in `Verso/CLAUDE.md` "Self-hosted runner gotchas" — same
behavior across all three of Erik's repos). If the runner shows
`Offline` and the listener crash-loops:

```bash
cd ~/actions-runner-recto
./svc.sh stop
rm -f .runner .runner_migrated .credentials .credentials_rsaparams .path .env
# Mint a fresh registration token from the GitHub UI, then:
./config.sh --url https://github.com/erikcheatham/Recto \
  --token "<new-token>" --name MAC-recto --labels recto \
  --unattended --replace
./svc.sh start
```

Re-register: ALWAYS pass `--labels recto` explicitly. Implicit
labels are `self-hosted, macOS, ARM64` only — drop the `recto`
label and the `runs-on` selector in `test-mac.yml` won't match.

---

## Part B — iOS deploy to a real iPhone

Validates the iOS build path that has the `IosSecureEnclaveKeyService`
+ APNs integration written but never run on real hardware.

### One-time prerequisites (operator-driven, NOT MAC-Claude)

These touch the Apple Developer Program account and produce
secrets that must NEVER be committed:

1. **Apple Developer Program enrollment** ($99/yr, per-Apple-ID).
   Apple ID = the one on MAC's iCloud sign-in.

2. **Apple Development certificate** for code signing.
   - Open Xcode → Settings → Accounts → add your Apple ID
   - Select the team → "Manage Certificates" → "+" →
     "Apple Development"
   - Cert lands in MAC's Keychain Access under "login".

3. **App identifier** registered at
   https://developer.apple.com/account/resources/identifiers
   - Bundle ID: `app.recto.phone` (must match
     `<ApplicationId>` in `Recto.csproj`)
   - Capabilities: enable **Push Notifications** (matches the
     APNs entitlement in `Platforms/iOS/Entitlements.plist`)

4. **Provisioning profile** (development) at
   https://developer.apple.com/account/resources/profiles
   - Type: iOS App Development
   - App ID: `app.recto.phone`
   - Certificates: select the cert from step 2
   - Devices: select iPhone 7 (UDID required — see step 5)
   - Download the `.mobileprovision` file
   - Double-click it; Xcode imports into the system store

5. **iPhone 7 UDID** — connect the phone via USB to MAC, open
   Xcode → Window → Devices and Simulators → identify the
   "Identifier" field. That's the UDID. Paste it back into the
   developer-portal device list (step 4).

6. **APNs auth key** (`.p8` file) at
   https://developer.apple.com/account/resources/authkeys/list
   - Already created and present at
     `phone/RectoMAUIBlazor/dev-tools/.apns-auth-key.p8`
   - File is gitignored; do NOT check in.
   - Drop into MAC's keychain only if you'll exercise the APNs
     wakeup path during this session — push notifications work
     without this if the phone is foregrounded.

### Build + deploy

After step 1-6 are done once (cached in Keychain + Xcode), each
build cycle is:

```bash
# Substitute <RECTO_CLONE> with your actual Recto checkout path.
# GitHub Desktop default: ~/Documents/GitHub/Recto
# CLI default: ~/Recto
cd <RECTO_CLONE>/phone/RectoMAUIBlazor/Recto/Recto

# Build the iOS device variant. -r ios-arm64 selects real-device
# (vs simulator's iossimulator-arm64). The csproj's conditional
# PropertyGroup for ios-arm64 wires the entitlements file.
dotnet publish \
  -f net10.0-ios \
  -c Release \
  -r ios-arm64 \
  -p:ArchiveOnBuild=true

# The signed .ipa lands at:
# bin/Release/net10.0-ios/ios-arm64/publish/Recto.ipa
```

Deploy to the connected iPhone:

```bash
# Confirm device is connected
xcrun devicectl list devices

# Install
xcrun devicectl device install app \
  --device <iPhone-UDID> \
  bin/Release/net10.0-ios/ios-arm64/publish/Recto.ipa

# Launch (optional — the app appears on the home screen after install)
xcrun devicectl device process launch \
  --device <iPhone-UDID> \
  app.recto.phone
```

### Smoke-test on device

Once installed:

1. **Pair the phone with the bootloader.** The mock bootloader at
   `127.0.0.1:8000` won't be reachable from the iPhone — point
   `IosSecureEnclaveKeyService`'s pairing target at MAC's LAN IP
   instead (`http://10.0.0.162:8000` if the mock is running on
   MAC). The TLS pinning service will warn-on-first-trust per
   the existing TOFU flow.

2. **Test single_sign approval** — should produce an Ed25519
   signature using the iOS Secure Enclave (NOT the software
   fallback). Diagnostic breadcrumb in the Debug output should
   read `[Recto.IosSecureEnclaveKeyService] using SecureEnclave
   key` not `using software fallback key`.

3. **Test btc_sign + eth_sign approvals** — the Bitcoin-family
   and Ethereum-family signing flows live in `Recto.Shared`
   (cross-platform), so any path-derivation issue or
   `BouncyCastle`-on-iOS issue will surface here. Expected:
   identical signatures to the Windows MAUI host given the same
   mnemonic.

4. **Test the new dark vault UI** — verify the vault aesthetic
   renders correctly on iOS WKWebView. Font fallback chain
   includes JetBrains Mono → Cascadia → SF Mono → Menlo →
   Consolas; iOS should land on SF Mono, which is fine. If the
   topbar / cards / per-coin badges look broken, screenshot
   and report so we can ship CSS fixes.

### Known iPhone 7 quirks

- iOS 15.8.x is the ceiling. `Recto.csproj` sets
  `SupportedOSPlatformVersion=15.0`, so the build deploys
  without a minimum-OS workaround.
- A6/A7-era Secure Enclave may have different timing
  characteristics than newer devices; per-sign biometric prompts
  (Touch ID on iPhone 7) take ~300-500ms, longer than Face ID's
  ~150ms on newer devices. UI should not assume sub-200ms biometric
  resolution.
- iPhone 7 doesn't support iOS 16+ features (Lock Screen widgets,
  Live Activities, etc.) — irrelevant for Recto today, but worth
  noting if v0.6+ adds widgets.

---

## Operator handoff checklist

When MAC-side Cowork has finished the setup, send this status back
to Erik (or to HECATE-side Claude via the `/api/comms/send`
mechanism):

- [ ] Recto runner registered, status: Idle
- [ ] `test-mac.yml` workflow run #1 result: passed / failed (link)
- [ ] Apple Development cert in Keychain: yes / no
- [ ] Provisioning profile installed: yes / no
- [ ] iPhone 7 UDID added to provisioning profile: yes / no
- [ ] First device deploy: succeeded / failed (paste error)
- [ ] Single_sign smoke test on device: passed / failed
- [ ] BTC + ETH sign smoke tests: passed / failed
- [ ] Dark vault UI rendering on iOS: looks good / needs CSS fix

Anything that fails, paste the exact error or screenshot so
HECATE-side Claude can write the fix in the next sprint.
