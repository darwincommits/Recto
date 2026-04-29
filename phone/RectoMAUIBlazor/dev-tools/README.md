# Recto phone-app dev tools

Single-file Python harness for iterating the v0.4 pairing flow without
needing the real `recto.bootloader` HTTPS server (still substrate batch 2
work in `../../ROADMAP.md`).

## Mock bootloader

`mock-bootloader.py` &mdash; stdlib-only HTTP server. Implements the two
endpoints the phone needs at pairing time, plus a tiny operator UI for
minting pairing codes and watching incoming requests in real time.

### Run it

```sh
# Optional: enables real Ed25519 signature verification.
pip install cryptography

python mock-bootloader.py
```

Output:

```
Pairing code: 314159  (valid for 5 minutes)

Mock Recto bootloader running on http://127.0.0.1:8443
Operator UI    : http://127.0.0.1:8443/
Phone app field: bootloader URL = http://127.0.0.1:8443
```

Open the operator UI in a browser (it auto-refreshes every 3 s) so you
can watch the wire while you drive the phone app.

### Smoke-test sequence

1. Run the mock; note the printed pairing code.
2. Launch the phone app on Windows.
3. In the app, fill the form:
   - **Bootloader URL**: `http://127.0.0.1:8443`
   - **Pairing code**: the 6 digits from the mock's stdout
4. Click **Pair**. The button steps through the busy-text states
   (Identifying phone... &rarr; Contacting bootloader... &rarr;
   Preparing identity key... &rarr; Signing challenge... &rarr;
   Registering with bootloader...).
5. The mock's operator UI shows the two requests landing
   (`GET /v0.4/registration_challenge` then `POST /v0.4/register`)
   and the phone is added to "Registered phones".
6. The phone app flips to the **Paired** card showing the mock's
   `bootloader_id`, the phone's `phone_id`, the paired-at timestamp,
   and the canned managed-secrets list.

### Re-pairing loop

7. Click **Unpair** on the phone &mdash; pairing record is wiped.
8. In the mock UI, click **Mint pairing code** &mdash; new 6-digit code shows.
9. Repeat from step 3.

The phone's enclave keypair is preserved across unpair/repair cycles
(deliberately &mdash; the enclave alias is `recto.phone.identity` and lives in
SecureStorage). The mock will see the same public key on every pair-back.

### Flags

| Flag | Default | Effect |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` to listen on all interfaces. |
| `--port` | `8443` | Listen port. |
| `--no-verify` | off | Skip Ed25519 signature verification on `/v0.4/register`. Useful when iterating the wire shape with `cryptography` not installed. |
| `--tls` | off | Serve over HTTPS with an ephemeral self-signed ECDSA P-256 cert. Prints the SPKI pin (sha256 base64url, no padding) at startup so the phone can capture it during pairing. Requires the `cryptography` package. Cert is regenerated every startup, by design &mdash; the phone re-captures the pin on next pair if it changes. |

### TLS / cert-pinning end-to-end test

With round 6's cert-pinning shipped on the phone side, the mock can now
serve HTTPS so the full pinning code path is exercised:

```sh
python mock-bootloader.py --tls
```

Output:

```
Pairing code: 314159  (valid for 5 minutes)

Mock Recto bootloader running on https://127.0.0.1:8443
Operator UI    : https://127.0.0.1:8443/
Phone app field: bootloader URL = https://127.0.0.1:8443

TLS SPKI pin   : 7p4eVjQz2JxR-aBcDe...
                 (sha256 base64url no padding; phone captures this at pairing)
                 Cert is ephemeral -- regenerated every startup, by design.
```

Browse to the operator UI in a browser &mdash; you'll need to accept the
"your connection is not private" warning once (the cert is self-signed).
Subsequent visits are fine. The operator UI displays the SPKI pin near
the top so you can copy it for cross-checking against what the phone
captured (see the **TLS pin** field on the phone's Paired card after
re-pairing).

The phone-side `PinningService.Validate` accepts any cert during the
pre-pairing TOFU window (no pin set yet); after pairing succeeds, the
captured pin is locked in via `SetPin` and any future cert change for
that host will fail validation.

### Push notifications (round 8)

Phone-side push registration is complete. When the phone pairs, it fetches
its FCM (Android) or APNs (iOS) token via the platform's native registration
APIs and includes it in the `RegistrationRequest` body. The bootloader
stores it per phone (visible in the operator-UI registered-phones panel
as `push fcm:eHs8...` / `push apns:7d3a...`) and calls a `send_push_wakeup`
helper whenever it queues a pending request.

**The phone-side code is fully wired**; what remains is the **credential
ceremony** to get the bootloader actually delivering pushes (instead of
just logging "would send"). Two parallel tracks: Firebase Console for FCM
(Android), Apple Developer Program for APNs (iOS).

#### Track A: Firebase Console &rarr; FCM (Android)

1. Go to <https://console.firebase.google.com/> and sign in with the
   account that will own the Recto Firebase project. Click **Add project**
   (or select an existing one).
2. **Project name**: `recto-phone` (or whatever you prefer; the project ID
   will be auto-generated like `recto-phone-abc12`). Click Continue, skip
   Google Analytics for now (optional, can be added later), Create project.
3. Once the project is created, click the Android icon on the project
   overview page to register an Android app:
   - **Android package name**: `app.recto.phone` (must exactly match the
     `<ApplicationId>` in `Recto/Recto/Recto.csproj`).
   - **App nickname** (optional): `Recto Phone`.
   - **Debug signing certificate SHA-1**: optional for FCM; only required
     for Google Sign-In / Dynamic Links. Skip.
4. Click **Register app**. Firebase generates `google-services.json` and
   prompts you to download it.
5. **Drop the file at**: `phone/RectoMAUIBlazor/Recto/Recto/Platforms/Android/google-services.json`.
   The file is gitignored by virtue of the `phone/` tree being gitignored
   at the repo root, so you don't need to redact anything; it's a per-app
   resource, not a secret.
6. **Build action wiring**: the file needs `Build Action = GoogleServicesJson`
   in the csproj. Add to `Recto/Recto.csproj` inside the Android-conditional
   ItemGroup:
   ```xml
   <GoogleServicesJson Include="Platforms\Android\google-services.json" />
   ```
7. Re-build the Android target. The first run will register with FCM and
   the operator UI will show `push fcm:<token-prefix>...` for the Pixel.
8. **Server-side credential**: For the bootloader to actually deliver pushes
   (vs just logging "would send"), it needs a service-account JSON to
   authenticate with FCM v1 HTTP API. In the Firebase Console, go to
   **Project settings &rarr; Service accounts &rarr; Generate new private key**.
   Download the JSON, drop at `phone/RectoMAUIBlazor/dev-tools/.fcm-service-account.json`
   (also gitignored), and pass `--fcm-service-account .fcm-service-account.json`
   to the mock bootloader on startup. (The flag is reserved for the v0.4.1
   real-send wiring; today the mock just stubs the call.)

#### Track B: Apple Developer Program &rarr; APNs (iOS)

**Pre-requisite**: active Apple Developer Program enrollment. Check at
<https://developer.apple.com/account/>; if you see a "Join the Apple
Developer Program" CTA you're not yet enrolled. Individual enrollment
is instant after CC payment ($99/yr); organization enrollment needs a
D-U-N-S number with 24-48hrs verification.

If not enrolled, FCM (Track A) lands tonight and APNs ceremony resumes
once your seat is active.

If enrolled:

1. Sign in to <https://developer.apple.com/account/> on the Mac mini
   (signing later requires the Mac mini's Keychain). Note your **Team ID**
   from the membership detail card (10-character alphanumeric like
   `ABCDE12345`).
2. **Register the bundle ID**: <https://developer.apple.com/account/resources/identifiers/list>
   &rarr; the `+` button &rarr; **App IDs** &rarr; **App** &rarr; Continue.
   Description: `Recto Phone`. Bundle ID: **Explicit** =
   `app.recto.phone` (must match `<ApplicationId>` in csproj).
   **Capabilities**: scroll down and check **Push Notifications**. Continue,
   Register.
3. **Generate APNs auth key (.p8)**: <https://developer.apple.com/account/resources/authkeys/list>
   &rarr; the `+` button &rarr; **Apple Push Notifications service (APNs)**.
   Key Name: `Recto APNs` (any descriptive name). Continue, Register.
4. **Download the .p8 file** &mdash; Apple only lets you do this ONCE,
   right after creation. If you lose it you have to revoke + regenerate.
   Save with a clear filename: `AuthKey_<KEY_ID>.p8` (the file Apple gives
   you is named exactly that). Note the **Key ID** (10-character alphanumeric
   shown on the page).
5. **Drop the .p8 at**: `phone/RectoMAUIBlazor/dev-tools/.apns-auth-key.p8`
   (gitignored; the entire `phone/` tree is gitignored).
6. Pass the credentials to the mock bootloader on startup:
   ```sh
   python mock-bootloader.py --tls \
     --apns-key dev-tools/.apns-auth-key.p8 \
     --apns-key-id <KEY_ID> \
     --apns-team-id <TEAM_ID> \
     --apns-bundle-id app.recto.phone \
     --apns-environment development
   ```
   (Reserved CLI flags &mdash; the v0.4.1 real-send code wires them in;
   v0.4.0 today just stubs the call.)
7. **Provisioning profile**: in Xcode (or via Apple Developer site
   automatic-management), generate a development provisioning profile that
   includes the `Recto Phone` App ID with Push Notifications capability.
   The MAUI iOS build picks this up via `Entitlements.plist` (already
   committed; flips the `aps-environment` key between `development` and
   `production`).
8. Re-build the iOS target. The first run prompts the user for notification
   permission, then iOS hands the AppDelegate the device token, which
   `IosApnsPushTokenService` returns to the pairing flow. The operator UI
   will show `push apns:<token-prefix>...` for the iOS device.

#### Verifying push works

After both tracks land:

1. Restart the mock bootloader with the credential flags.
2. Re-pair both phones (uninstall + reinstall on each so the bundle-ID
   change to `app.recto.phone` takes effect &mdash; the old
   `com.companyname.Recto` install can't migrate).
3. Lock the phone screen. Click **Queue sign request** on the operator UI.
4. Within ~1 second the phone screen wakes with the pending-request
   notification. Tap to unlock + approve via biometric.
5. Compare to the pre-push baseline: the 3-second poll cycle meant up to
   3s of perceived latency between operator-click and phone-prompt; with
   push it should be sub-second.

### What the mock does NOT cover

- Persistence &mdash; mock state is in-memory; restart wipes everything.
  The phone app's persisted pairing record will then refer to a
  bootloader id the mock no longer recognizes; click Unpair to recover.
  Note that this also invalidates the captured TLS pin if you restart
  the mock with `--tls` (the cert is regenerated each startup).
- v0.4.0 ships push as a "would send" stub on the bootloader. v0.4.1
  wires the real APNs HTTP/2 + FCM v1 senders behind the existing
  `send_push_wakeup` seam. The phone-side code is final.
