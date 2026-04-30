# Recto phone app — AI memory

Per-tree memory for AI assistants working on the .NET MAUI Blazor
phone app under `phone/RectoMAUIBlazor/`. The top-level
`Recto/CLAUDE.md` covers substrate concerns (launcher, NSSM, secrets
backends, YAML schema). This file covers MAUI/iOS/Android-specific
gotchas the phone app accumulated during the v0.4 → v0.4.1 sprint.

Read this file in addition to the top-level memory whenever a task
touches anything under `phone/`.

## Project shape

- `Recto/Recto/` — MAUI host project (Android, iOS, Mac Catalyst, Windows).
- `Recto/Recto.Shared/` — Razor pages, services, DI seam (cross-platform).
- `Recto/Recto.Shared.Tests/` — xUnit unit tests (~30 tests).
- `dev-tools/mock-bootloader.py` — Python reference bootloader for
  offline phone iteration. HTTPS-capable, audit log, all
  PendingRequest kinds, WebAuthn demo at `/demo/webauthn`.
- `dev-tools/README.md` — operator credential ceremony walkthrough
  (Apple Developer Program + Firebase Console).

Bundle ID: `app.recto.phone` (flipped from .NET-template default
during the Tier-1 v1-readiness sprint).

## Dev-loop facts

- The mock bootloader at `dev-tools/mock-bootloader.py` is the
  fastest iteration target. `python mock-bootloader.py --tls` for
  the HTTPS path; the SPKI-pinning service accepts any cert during
  the pre-pairing TOFU window.
- `dotnet build` works on Windows for Android + Windows targets;
  iOS / Mac Catalyst builds compile only on macOS hosts with Xcode +
  matching MAUI workload version. `dotnet workload restore <slnx>`
  is the surgical fix when workload-pack versions drift (see gotcha
  below).
- Real-device deploy (Pixel for Android, physical iPhone for iOS)
  requires `adb reverse tcp:N tcp:N` (Android) or `host.docker
  .internal` / LAN IP (iOS) so the phone can reach the dev-host's
  bootloader. Cleartext-HTTP gotcha applies — see below.

## Phone-app gotchas (MAUI / iOS / Android)

### Razor specifics

- **`error RZ1010: Unexpected "{" after "@" character` — never wrap C#
  statements in `@{ }` when you're already inside a Razor C# block.**
  The Razor parser treats `else { ... }`, `@if (...) { ... }`,
  `@switch (x) { case Y: ... }`, `@foreach (var x in xs) { ... }` as
  C# context already; inside those bodies you write C# directly. The
  `@{ }` form is for switching INTO C# context FROM a markup-context
  region (e.g. inline scratch declarations between two `<div>`
  blocks). Doubling them up errors with RZ1010 at the inner `@{`.

  Concretely, this is wrong:
  ```razor
  case PendingRequestKind.BtcSign:
      @{ var coin = ResolveCoin(req); }   // RZ1010 — already in C#
      <span class="@coin">...</span>
  ```
  This is right:
  ```razor
  case PendingRequestKind.BtcSign:
      var coin = ResolveCoin(req);        // direct C# — already in C#
      <span class="@coin">...</span>
  ```
  Markup tags inside the case body work because Razor flips back to
  markup context on `<` and back to C# on the next statement
  terminator. `@(...)` and `@expr` inside attribute / text positions
  are fine — those are C#-expression-IN-markup, NOT C#-block-IN-C#.

  Caught wave-7 (twice) — first inside an `else { }` branch when
  splitting pending requests into IDENTITY & ACCESS / CRYPTO TOKENS
  sections, then inside a `@switch case` branch when adding the
  per-request `var btcCoin = ...;` for the LTC/DOGE/BCH render
  arm. Both fixes were "delete the `@{` and `}` wrappers". Don't
  reach for `@{ }` reflexively when adding C# helpers next to
  markup — first ask "am I already in C# context?".

### C# / .NET specifics

- **`Org.BouncyCastle.Math.BigInteger` is a CLASS, not a struct —
  `BigInteger?` is nullable reference, not `Nullable<BigInteger>`,
  so there's NO `.Value` property.** When NRT is enabled (which it
  is in `Recto.Shared.csproj`), the `?` annotation on a reference
  type just means "may be null." The `!.Value` pattern that works
  for `int?` / `long?` / `System.Numerics.BigInteger?` does NOT
  compile against BC's BigInteger — error is
  `CS1061 'BigInteger' does not contain a definition for 'Value'`.
  Use `!` alone to assert non-null:
  `var x = SomeBcMethod()!;` not `var x = SomeBcMethod()!.Value;`.
  Caught wave-6 (2026-04-29) when the EIP-1559 transaction-hash
  helper (originally written as if `BigInteger?` were a value
  type) failed to compile on first build — 11 cascade errors
  across `TransactionHashEip1559` + `SignAndEncodeTransactionEip1559`.
  When importing patterns from System.Numerics-using code
  (`https://github.com/.../System.Numerics.BigInteger`) into a
  BC-using file, audit every `.Value` access; they need to drop.

- **C# forbids method-local variable shadowing across non-overlapping
  child scopes — even when the outer declaration appears AFTER the
  child block in source order.** Means: if you have `if (x) { var s = "..."; }`
  early in a method and later in the same method declare
  `var s = new byte[32]`, the compiler errors at the `if` block:
  `CS0136 A local or parameter named 's' cannot be declared in this
  scope because that name is used in an enclosing local scope`.
  The fix is to rename one of the two — typically the outer
  method-local, since the inner-block name is the local idiom.
  Caught wave-6 when EIP-1559 sign-and-encode added
  `var r = new byte[32]; var s = new byte[32];` for signature
  components in a method whose JSON-parsing if-blocks were already
  using `var s = elem.GetString()`. Renamed signature components
  to `sigR` / `sigS` to keep the JSON-parsing idiom local-scope-clean.

### Build and deploy

- **VS Hot Reload / incremental builds silently fail to redeploy
  code changes to the running unpackaged Windows MAUI host —
  symptom is "I rebuilt and the new behavior doesn't appear."**
  Caught wave-4 (2026-04-28) in a multi-hour debugging session
  where the wave-4 BIP-39+BIP-32 phone-side service appeared not
  to deploy: the running app kept producing signatures from the
  v0.5+ first-cut random-key code path even after multiple F5
  cycles. Diagnostic that proves which path is running: drop a
  `System.Diagnostics.Debug.WriteLine("[Recto.<unique tag>] ...")`
  line into the new code path's hot loop, F5, exercise the
  feature, watch the VS Output window (Debug pane). If the
  breadcrumb doesn't appear, the running binary is stale.
  **Recovery:** (a) Stop Debugging fully (Shift+F5, NOT just
  pause); (b) Build → Clean Solution; (c) Build → Rebuild
  Solution; (d) F5. The Clean + Rebuild combo forces VS to
  invalidate cached binaries; bare Rebuild without Clean
  occasionally retains stale assemblies in the bin/obj cache for
  unpackaged Windows MAUI hosts. (e) If the breadcrumb still
  doesn't appear after that, manually delete `Recto\Recto\bin`
  and `Recto\Recto\obj` folders and retry — that's the
  scorched-earth fix that always works. Worth keeping the
  breadcrumb behind `#if DEBUG` as a permanent sanity-check
  tripwire on hot-loop code paths so future regressions where
  someone accidentally adds a fast-path that bypasses the
  expected logic surface immediately. **Companion observation
  banked the same day**: MAUI `SecureStorage` entries persist
  across stop-and-redeploy cycles AND across Clean+Rebuild
  cycles AND across `dotnet ef` clean reinstalls. Only
  `SecureStorage.Default.RemoveAll()` (called from the Settings
  page "Unpair all" emergency wipe) actually clears the data
  layer. So when testing storage-key migrations during a sprint
  like wave-4's mnemonic rewrite, the test sequence is: deploy
  new code → "Unpair all" to wipe the data layer → exercise the
  new code path against a fresh blank slate. Without the
  Unpair-all step, the new code path may read pre-existing
  entries and produce results that LOOK like the old code is
  still running.

- **`dotnet build -f X` at the solution level fails for projects
  whose <c>TargetFramework(s)</c> doesn't include X, even if other
  projects in the solution do.** Symptom from the solution dir
  (containing <c>Recto.slnx</c> + sibling project folders): running
  <c>dotnet build -f net10.0-windows10.0.19041.0</c> produces
  <c>NETSDK1005: Assets file ... doesn't have a target for
  'net10.0-windows10.0.19041.0'</c> for <c>Recto.Shared</c> and
  <c>Recto.Shared.Tests</c> (which only target <c>net10.0</c>),
  while the MAUI host project <c>Recto</c> (which targets all
  four MAUI TFMs) builds fine. The <c>-f</c> flag at solution
  level applies the filter to every project in the solution.
  Workarounds: (a) target the specific csproj instead —
  <c>dotnet build Recto\Recto\Recto.csproj -f net10.0-windows10.0.19041.0</c>;
  (b) drop the <c>-f</c> flag and let each project build at its
  own TFM(s) — <c>dotnet build</c> from the solution dir works
  fine, just slower since the MAUI host then builds for all four
  targets. For dev iteration on Windows specifically, F5 in
  Visual Studio with the Windows target picked is the cleanest
  path. Caught wave-4 2026-04-28.

- **`dotnet workload install maui` doesn't always pull a matching
  iOS-pack version; `dotnet workload restore <solution>` is the
  surgical fix.** Symptom on first build of a fresh MAUI Blazor
  scaffold: `MSB4019 The imported project
  "...\Microsoft.iOS.Sdk.net10.0_<v>\<v>.10217\Sdk\AutoImport.props"
  was not found.` The manifest version the solution declares (e.g.
  `26.2.10217`) doesn't match what the `maui` meta-workload's
  transitive `maui-ios` dependency installed. Running
  `dotnet workload restore <slnx>` reads the actual targets the
  solution needs and grabs exactly those packs;
  `dotnet workload list` afterwards shows `ios 26.2.10233/10.0.100`
  (or whichever specific build matches the solution). Generic
  `dotnet workload update` + `dotnet workload install maui-ios` is a
  less-surgical fallback.

- **iOS Simulator builds need ad-hoc signing, not no-signing —
  setting `EnableCodeSigning=false` produces an unsigned binary that
  the simulator refuses to launch.** Two failure modes ride on the
  same csproj-config knob: (a) leave default codesigning on without
  a provisioning profile → MSBuild fails at compile-time with "Could
  not find any available provisioning profiles for Recto on iOS"
  from `Xamarin.Shared.targets:2041` (the `_DetectSigningIdentity`
  task); (b) over-correct by setting `EnableCodeSigning=false` →
  binary compiles but the simulator's dyld rejects it on launch
  with `Namespace CODESIGNING, Code 2, Invalid Page` and SpringBoard
  denylists the bundle. **Correct fix uses ad-hoc signing**: keep
  signing on, set CodesignKey to `-` (the macOS codesign
  self-attested ad-hoc identity), and explicitly suppress the
  provisioning-profile requirement. Pair with a separate device-only
  PropertyGroup that applies the real entitlements + relies on the
  auto-detected dev cert. Canonical pattern:

  ```xml
  <PropertyGroup Condition="$(TargetFramework.Contains('-ios')) AND '$(RuntimeIdentifier)' == 'ios-arm64'">
      <CodesignEntitlements>Platforms/iOS/Entitlements.plist</CodesignEntitlements>
  </PropertyGroup>
  <PropertyGroup Condition="$(TargetFramework.Contains('-ios')) AND ('$(RuntimeIdentifier)' == 'iossimulator-arm64' OR '$(RuntimeIdentifier)' == 'iossimulator-x64' OR '$(RuntimeIdentifier)' == '')">
      <CodesignKey>-</CodesignKey>
      <CodesignRequireProvisioningProfile>false</CodesignRequireProvisioningProfile>
  </PropertyGroup>
  ```

  The `RuntimeIdentifier == ''` case catches plain `Build Solution`
  invocations (no specific deploy target selected). **Recovery when
  SpringBoard has already denylisted the bundle:** `xcrun simctl
  uninstall booted app.recto.phone` (or long-press + delete the app
  icon on the simulator), then redeploy. The denylist is
  per-bundle-id-per-simulator-instance and clears on uninstall.

- **Apple WWDR intermediate cert (G6) is required in the Keychain
  for `find-identity` to report any cert as "valid".** Symptom: 2
  certs in the login keychain but `security find-identity -v -p
  codesigning` reports "0 valid identities found." Fix: download
  `https://www.apple.com/certificateauthority/AppleWWDRCAG6.cer` and
  open it (double-click adds to Login Keychain). Without the
  intermediate, the chain can't be validated locally even though the
  signing cert itself is well-formed.

- **`Xamarin.AndroidX.*` NuGet versions don't track upstream AndroidX
  release numbers — always check nuget.org before pinning a
  speculative version.** The `Xamarin.AndroidX.*` package family uses
  a versioning scheme of `{androidx-version}.{binding-revision}`,
  but the .NET binding cadence trails the AndroidX upstream by one
  or more major-version generations. Concrete example:
  `Xamarin.AndroidX.Biometric` — AndroidX Biometric upstream is at
  1.2.0-alpha05 / 1.4.0-alpha, but the latest .NET binding on
  nuget.org is `1.1.0.32`. Pinning `1.2.0.13` fails NuGet restore
  with `NU1102: Unable to find package — nearest version: 1.1.0.32`.
  Workaround: when adding ANY `Xamarin.AndroidX.*` package, either
  (a) WebFetch nuget.org/packages/Xamarin.AndroidX.{Name} to read
  the latest version label, or (b) hand the operator a
  `dotnet add package Xamarin.AndroidX.{Name}` command for a fresh
  restore against the feed. Don't pin from intuition.

### Compile-time C# / Razor traps

- **`using Android.Gms.Tasks` alongside `using System.Threading`
  produces a `CancellationToken` ambiguity (CS0104) that propagates
  as a CS0535 "interface member not implemented" cascade.** Symptom:
  a service file that imports the Google Play Services Tasks API
  AND tries to satisfy a .NET interface that takes
  `System.Threading.CancellationToken`. The compiler binds to the
  wrong type, then the method doesn't match the interface signature.
  **Fix:** drop `using System.Threading;` from the file and add a
  type alias: `using DotNetCancellationToken =
  System.Threading.CancellationToken;`, then reference
  `DotNetCancellationToken` explicitly in the public method
  signature.

- **`UIApplicationDelegate` push-registration callbacks aren't
  `override`-able virtual methods on `MauiUIApplicationDelegate` in
  modern .NET MAUI iOS bindings — they MUST be wired via
  `[Export("...")]` Objective-C selectors instead.** Symptom: CS0115
  "no suitable method found to override" on
  `RegisteredForRemoteNotifications` /
  `FailedToRegisterForRemoteNotifications`. The .NET-side base class
  doesn't surface them as virtual; the Obj-C runtime dispatches by
  selector regardless of CLR inheritance. Canonical wire-up:

  ```csharp
  [Register("AppDelegate")]
  public class AppDelegate : MauiUIApplicationDelegate
  {
      protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

      [Export("application:didRegisterForRemoteNotificationsWithDeviceToken:")]
      public void RegisteredForRemoteNotifications(UIApplication app, NSData deviceToken)
      { /* ... */ }

      [Export("application:didFailToRegisterForRemoteNotificationsWithError:")]
      public void FailedToRegisterForRemoteNotifications(UIApplication app, NSError error)
      { /* ... */ }
  }
  ```

  Selector strings are verbatim from Apple's UIApplicationDelegate
  protocol documentation; do NOT abbreviate or reorder the
  colon-separated parts. `CreateMauiApp` is the only override —
  everything else is selector-based.

- **Razor `@bind` two-way binding requires settable properties;
  records' positional-ctor properties are init-only by default and
  don't satisfy it.** Symptom: `CS8852: Init-only property or
  indexer 'X.Y' can only be assigned in an object initializer` from
  the Razor source generator's output (`obj/.../*_razor.g.cs`).
  Root cause: a model defined as a positional record like `public
  sealed record Foo(int A, string B);` has init-only properties;
  Razor's generated binding code emits `_model.A = value;` which
  the compiler rejects. **Canonical fix:** convert to a plain class
  with `public int A { get; set; }`. Alternative: keep as record but
  declare with curly-brace body and explicit settable properties
  (`public sealed record Foo { public int A { get; set; } = 1; }`).
  The trap is that positional records FEEL like the right idiom for
  "config object"; the binding-time failure mode shows up via the
  source-generator output, not the model file itself.

- **XML 1.0 forbids the `--` substring inside `<!-- ... -->`
  comments — csproj / plist / xaml / svg / AndroidManifest.xml are
  all XML and all trip over this.** Symptom: project file fails to
  load with a parse error pointing at "line N position M" where the
  position lands on the second hyphen of a `--` pair. Using `--`
  as a poor-man's em-dash in prose-style comments is natural English
  habit ("AT BUILD TIME -- the conditional guard avoids ..."), but
  XML 1.0 section 2.5 explicitly forbids it. **Workarounds for
  prose-style emphasis inside XML comments:** (a) replace with a
  single em-dash glyph &mdash; XML files are UTF-8 by default and
  the &mdash; character (U+2014) is fine inside comments; (b)
  replace with a semicolon or a period + sentence break; (c) use a
  single `-`. **Defensive habit:** every multi-line `<!-- ... -->`
  in csproj / AndroidManifest.xml / *.plist / *.svg / *.xaml gets a
  final scan for `--` in the comment body before saving. (Hit twice
  in one day during the v0.4.1 sprint — costly and easy to forget.)

### Runtime traps

- **`JsonContent.Create` + MAUI HttpClient pipeline can emit
  `Content-Length: 0` bodies, swallowing the actual JSON.** Symptom:
  the request goes out with `Content-Type: application/json;
  charset=utf-8` but the body is empty bytes. Server-side parsers
  see `{}` and surface "missing required fields" 400s. Root cause is
  the lazy-serialization path inside `JsonContent`: under some MAUI
  `IHttpClientFactory` configurations the content stream gets read
  before the JSON body is fully composed. **Workaround:** pre-
  serialize via `JsonSerializer.Serialize(body, body.GetType(),
  options)` then wrap the resulting string in `new
  StringContent(json, Encoding.UTF8, "application/json")`. The
  string content is fully buffered, so Content-Length reflects
  reality and no lazy-stream timing window exists. Also useful: log
  the serialized JSON in the typed-client's SendAsync wrapper at
  `LogInformation` so future wire-shape issues show up in Visual
  Studio's Output window.

- **Android API 28+ blocks cleartext HTTP by default for ALL domains
  including loopback; iOS App Transport Security similarly blocks
  cleartext on iOS 9+.** Symptom on Android Pixel deploying a MAUI
  app that talks to a localhost mock via `adb reverse tcp:N tcp:N`:
  the phone-side request fails immediately with "cannot reach" /
  network error before any wire traffic hits the host. The `adb
  reverse` tunnel is fine; Android's NetworkSecurityPolicy is the
  gate. **Workaround (Android):** add a
  `Resources/xml/network_security_config.xml` that whitelist-allows
  cleartext for `127.0.0.1` / `localhost` / `10.0.2.2` only, and
  reference it via `<application
  android:networkSecurityConfig="@xml/network_security_config">` in
  the AndroidManifest. More secure than blanket
  `android:usesCleartextTraffic="true"`. **Workaround (iOS):** add
  `<key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>`
  to Info.plist.

### Enclave / cryptography

- **iOS Secure Enclave AND Android KeyStore both natively support
  only ECDSA P-256, NOT Ed25519, as of iOS 18 / Android 16.** iOS:
  `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`
  accepts only `kSecAttrKeyTypeECSECPrimeRandom` (P-256); Apple's
  CryptoKit has `Curve25519.Signing.PrivateKey` but those are
  software-backed (no `SecureEnclave.Curve25519` type exists).
  Android: `AndroidKeyStore`'s public `KeyProperties.KEY_ALGORITHM_*`
  list EC / RSA / AES / HMAC / XDH but NOT Ed25519. Calling
  `KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")` does
  NOT throw `NoSuchAlgorithmException` on Pixel-class devices but
  silently produces an EC P-256 key (91-byte SubjectPublicKeyInfo)
  rather than an Ed25519 one (44-byte SPKI). **Implication:** phone-
  side code that wants enclave-resident keys MUST use ECDSA P-256
  on both iOS and Android. The v0.4 protocol's `supported_algorithms`
  field is the negotiation seam; each platform's phone impl
  advertises whatever its enclave can do, and the bootloader stores
  the algorithm alongside the public key at pairing time and
  verifies subsequent signatures with it. Public-key extraction
  differs: 44-byte SPKI / offset 12 for Ed25519 (software path) vs
  91-byte SPKI / offset 27 (after the 0x04 uncompressed-point
  prefix) for EC P-256.

- **Apple `SecKey.CreateSignature` returns DER-encoded ECDSA
  signatures; protocols that ship raw R||S signatures need a DER
  parser.** `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` (and
  related digest variants) all return ASN.1 DER — SEQUENCE { r
  INTEGER, s INTEGER } — typically 70-72 bytes. The v0.4 protocol's
  wire format is 64-byte raw R||S (32+32, big-endian, no DER) for
  parity with Ed25519. Conversion is <25 lines of
  `System.Formats.Asn1.AsnReader` parsing — read sequence, read two
  INTEGER bytes, strip optional leading 0x00 (DER's positive-integer
  marker), right-align each into a 32-byte slot. Reverse direction
  (raw → DER) for verification on the Python side via
  `cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(r, s)`.
  The DER form has variable length depending on whether the high
  bit of R or S happens to be set; the parser must handle 32-byte
  AND 33-byte components.

- **.NET MAUI iOS binding marks `SecAttributeKey` /
  `SecKeyGenerationAttributeKeys` / `SecClass` as internal — use
  `SecRecord` for queries and `Dlfcn` for raw `kSec*` constants.**
  Symptom: `CS0122 'SecAttributeKey' is inaccessible due to its
  protection level`. The binding's intent is for keychain queries
  to flow through the typed `SecRecord` class. For SecKey
  generation, `SecKey.CreateRandomKey(NSDictionary, out NSError)`
  needs a raw dictionary, and the kSec* NSString constants needed
  as keys are not exposed publicly. **Workaround:** load them at
  runtime directly from the Security framework binary via
  `Dlfcn.dlsym` + `Marshal.ReadIntPtr` +
  `Runtime.GetNSObject<NSString>` (the constants are NSString*
  pointers, so dlsym yields a pointer-to-pointer that needs one
  dereference). One-time load, ~30 lines of nested-class
  boilerplate; works across binding versions. Companion lessons:
  `SecAccessControl` constructs via `new SecAccessControl(SecAccessible,
  SecAccessControlCreateFlags)` (no static `Create` factory).
  `SecKeyChain.QueryAsConcreteType(SecRecord, out SecStatusCode)`
  returns `object` and the status is the OUT param.
  `SecKey.GetExternalRepresentation()` is an instance method with
  no args. `SecAccessControl` derives from
  `ObjCRuntime.NativeObject` (CFType-bridged), NOT `NSObject` —
  bridge via `Runtime.GetNSObject<NSObject>(accessControl.Handle)`
  to wrap the same underlying handle for NSMutableDictionary.

- **Android `KeyGenParameterSpec.Builder.SetUserAuthenticationParameters`
  takes raw `int` for the type bit-mask, not the
  `KeyPropertiesAuthType` flags enum.** Symptom: `CS1503 cannot
  convert from 'Android.Security.Keystore.KeyPropertiesAuthType' to
  'int'`. The underlying Java method is
  `setUserAuthenticationParameters(int timeoutSeconds, int type)`.
  Cast: `(int)(KeyPropertiesAuthType.BiometricStrong |
  KeyPropertiesAuthType.DeviceCredential)`.

- **Android keystore keys with `setUserAuthenticationRequired(true)`
  cannot be used by `Signature.initSign(...)` directly — require
  `BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))`.**
  Symptom: calling `Signature.initSign(privateKey)` against an
  AndroidKeyStore key with `setUserAuthenticationRequired(true)`
  throws `UserNotAuthenticatedException: User not authenticated`
  even when the device is unlocked. **Per-use auth flow:**
  `setUserAuthenticationParameters(0, BIOMETRIC_STRONG |
  DEVICE_CREDENTIAL)`. `InitSign(...)` succeeds (signature is
  "armed"); the actual `.sign()` call requires
  `BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))`
  to authorize the wrapped CryptoObject. The success callback then
  runs `signature.update(...)` + `signature.sign()`. Each operation
  requires a fresh prompt — matches a "operator approves every
  cryptographic operation" model. NuGet package:
  `Xamarin.AndroidX.Biometric` (gives `AndroidX.Biometric.BiometricPrompt`
  + `CryptoObject`). Activity must be a `FragmentActivity`
  (`MauiAppCompatActivity` qualifies); cast
  `Microsoft.Maui.ApplicationModel.Platform.CurrentActivity`.

- **iPhone needs BOTH a passcode AND an enrolled biometric before
  Secure Enclave will mint a key under
  `BiometryCurrentSet | PrivateKeyUsage` ACL.** Symptom on first
  pairing attempt against a fresh test device: red error box
  `Secure Enclave keygen failed: The operation couldn't be
  completed. (OSStatus error -25293 - Key generation failed,
  error -25293)`. The error fires **before any network call**
  (keygen is purely local), so it can be misdiagnosed as a
  transport / TLS / pairing-code problem. `OSStatus -25293` =
  `errSecAuthFailed`, which at keygen time means the policy
  evaluator can't satisfy the ACL. Two prerequisites:
  (a) Device passcode set — Secure Enclave refuses to mint ANY
      key on a passcode-less device; the passcode is the root
      credential it uses to wrap key material.
  (b) At least one Face ID enrollment (or Touch ID on older
      devices) — `BiometryCurrentSet` binds the key to the
      currently-enrolled biometric set; with none enrolled, the
      policy can't be evaluated.
  **Operator fix:** Settings → Face ID & Passcode → set passcode +
  enroll Face ID, then retry pair. **Open code-side TODO** in
  `Platforms/iOS/IosSecureEnclaveKeyService.cs` catch path:
  translate `OSStatus -25293` into "Set up a device passcode and
  Face ID in iOS Settings before pairing" rather than dumping the
  raw OSStatus to the operator. The current message reads like a
  bug to the operator; a friendlier translation makes it clear
  it's a one-time iOS-Settings step. Caught wave-7 (2026-04-29)
  during first real-iPhone deploy ceremony — canonical
  first-deploy stumble worth banking explicitly. (Cross-ref:
  the same gotcha is also banked in the substrate
  `Recto/CLAUDE.md` Gotchas index alongside the iCloud-account-vs-
  Apple-Developer-Program independence note.)
