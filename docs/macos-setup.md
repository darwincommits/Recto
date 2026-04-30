# macOS-side setup for Recto

Recto's the macOS host mini host plays one substantive role for this repo:

**iOS deploy host** — builds and deploys the MAUI Blazor app to
real iPhone hardware via Xcode + the Apple Developer Program
certificate / provisioning profile. The phone's Secure Enclave
path (`Platforms/iOS/IosSecureEnclaveKeyService.cs`) and APNs
integration (`IosApnsPushTokenService.cs`) have been written
but never validated on real hardware — this host enables that.

(Earlier revisions of this runbook included Part A on registering
a self-hosted GitHub Actions runner for the macOS pytest CI. That
was reverted on 2026-04-29 because Recto is a public OSS repo
and self-hosted runners on public repos are an attack vector —
any fork can submit a PR with a malicious workflow that executes
on your runner. Recto's macOS CI now uses GitHub-hosted
`macos-latest` runners, which are free for public repos,
ephemeral, and require zero machine-side setup. See
`.github/workflows/test-the macOS host.yml`. iOS deploy stays macOS-host-local
because it needs your physical iPhone connected via USB —
GitHub-hosted runners can't do that.)

This document uses `<RECTO_CLONE>` as a placeholder for wherever
you cloned the Recto repo on this machine. **GitHub Desktop's
default landing dir is `~/Documents/GitHub/Recto`** — that's the
most likely value. CLI clones default to `~/Recto`. Substitute
whichever applies.

---

## Part A — pytest CI (no macOS-side setup needed)

`.github/workflows/test-the macOS host.yml` runs the test suite on every push
to main and every PR via GitHub-hosted `macos-latest` runners.
You don't need to register anything on the macOS host for this to work — it's
fully managed by GitHub Actions.

To trigger a run manually: GitHub UI → Actions tab → "Test on
macOS" → "Run workflow" → choose `main` branch → green button.

To see the unlocked test count: look at the run's pytest summary
output. Should show ~17 fewer skips than the Windows runs, because
macOS exercises the Unix-socket sign-helper flow + Linux/macOS
Job-Object stub + the "Windows only" reverse-gates on CredMan +
DPAPI + SO_REUSEADDR semantics on adminui.


## Part B — iOS deploy to a real iPhone

Validates the iOS build path that has the `IosSecureEnclaveKeyService`
+ APNs integration written but never run on real hardware.

### One-time prerequisites (operator-driven, NOT the macOS-side AI assistant)

These touch the Apple Developer Program account and produce
secrets that must NEVER be committed:

1. **Apple Developer Program enrollment** ($99/yr, per-Apple-ID).
   Apple ID = the one on the macOS host's iCloud sign-in.

2. **Apple Development certificate** for code signing.
   - Open Xcode → Settings → Accounts → add your Apple ID
   - Select the team → "Manage Certificates" → "+" →
     "Apple Development"
   - Cert lands in the macOS host's Keychain Access under "login".

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
   - Devices: select a legacy iPhone (UDID required — see step 5)
   - Download the `.mobileprovision` file
   - Double-click it; Xcode imports into the system store

5. **a legacy iPhone UDID** — connect the phone via USB to the macOS host, open
   Xcode → Window → Devices and Simulators → identify the
   "Identifier" field. That's the UDID. Paste it back into the
   developer-portal device list (step 4).

6. **APNs auth key** (`.p8` file) at
   https://developer.apple.com/account/resources/authkeys/list
   - Already created and present at
     `phone/RectoMAUIBlazor/dev-tools/.apns-auth-key.p8`
   - File is gitignored; do NOT check in.
   - Drop into the macOS host's keychain only if you'll exercise the APNs
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
   `IosSecureEnclaveKeyService`'s pairing target at the macOS host's LAN IP
   instead (`http://<lan-ip>:8000` if the mock is running on
   the macOS host). The TLS pinning service will warn-on-first-trust per
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

### Known a legacy iPhone quirks

- iOS 15.x is the ceiling. `Recto.csproj` sets
  `SupportedOSPlatformVersion=15.0`, so the build deploys
  without a minimum-OS workaround.
- A6/A7-era Secure Enclave may have different timing
  characteristics than newer devices; per-sign biometric prompts
  (Touch ID on a legacy iPhone) take ~300-500ms, longer than Face ID's
  ~150ms on newer devices. UI should not assume sub-200ms biometric
  resolution.
- a legacy iPhone doesn't support iOS 16+ features (Lock Screen widgets,
  Live Activities, etc.) — irrelevant for Recto today, but worth
  noting if v0.6+ adds widgets.

---

## Operator handoff checklist

When macOS-side Cowork has finished the setup, send this status back
to the operator (or to the developer host-side Claude via the `/api/comms/send`
mechanism):

- [ ] Recto runner registered, status: Idle
- [ ] `test-the macOS host.yml` workflow run #1 result: passed / failed (link)
- [ ] Apple Development cert in Keychain: yes / no
- [ ] Provisioning profile installed: yes / no
- [ ] a legacy iPhone UDID added to provisioning profile: yes / no
- [ ] First device deploy: succeeded / failed (paste error)
- [ ] Single_sign smoke test on device: passed / failed
- [ ] BTC + ETH sign smoke tests: passed / failed
- [ ] Dark vault UI rendering on iOS: looks good / needs CSS fix

Anything that fails, paste the exact error or screenshot so
the developer host-side Claude can write the fix in the next sprint.
