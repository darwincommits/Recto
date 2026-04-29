using Recto.Services;
using Recto.Shared.Extensions;
using Recto.Shared.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Recto;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });

        // Reserved for v0.4 settings (BootloaderUrl override, pinned cert, etc.).
        // Today only env-var binding is wired so future settings flow without code change.
        builder.Configuration.AddEnvironmentVariables();

        // Platform / device info abstraction consumed by Recto.Shared.
        builder.Services.AddSingleton<IFormFactor, FormFactor>();

        // v0.4 phone services: Ed25519 / ECDSA P-256 keypair management +
        // pairing-state persistence. The IEnclaveKeyService impl is platform-
        // specific so the right hardware-backed path runs on each target.
#if IOS
        // iOS Secure Enclave (P-256 + biometric ACL).
        builder.Services.AddSingleton<IEnclaveKeyService, Recto.Platforms.iOSImpl.IosSecureEnclaveKeyService>();
        // iOS APNs push-token registration.
        builder.Services.AddSingleton<IPushTokenService, Recto.Platforms.iOSImpl.IosApnsPushTokenService>();
#elif ANDROID
        // Android StrongBox (Ed25519 + biometric, falls back to TEE if no StrongBox).
        builder.Services.AddSingleton<IEnclaveKeyService, Recto.Platforms.AndroidImpl.AndroidStrongBoxKeyService>();
        // Android FCM push-token registration.
        builder.Services.AddSingleton<IPushTokenService, Recto.Platforms.AndroidImpl.AndroidFcmPushTokenService>();
#else
        // Windows / Mac Catalyst dev-loop backing (BouncyCastle Ed25519, no enclave).
        builder.Services.AddSingleton<IEnclaveKeyService, SoftwareEnclaveKeyService>();
        // No push transport on dev hosts; pairing still works, bootloader
        // falls back to the 3s poll cycle.
        builder.Services.AddSingleton<IPushTokenService, NoOpPushTokenService>();
#endif
        builder.Services.AddSingleton<IPairingStateService, MauiPairingStateService>();
        // v0.5 universal-vault first kind: TOTP. SecureStorage-backed; secrets
        // never leave the phone. See ARCHITECTURE.md 2026-04-26 entry.
        builder.Services.AddSingleton<ITotpService, MauiTotpService>();
        // v0.5+ Ethereum signing capability. SecureStorage-backed BIP-39
        // mnemonic + BIP-32/BIP-44 derivation; one mnemonic per alias,
        // infinitely many addresses on demand at any path. Cross-platform
        // BouncyCastle math, no per-platform fan-out (Secure Enclave /
        // StrongBox don't support secp256k1, so the software impl IS the
        // correct long-term implementation).
        builder.Services.AddSingleton<IEthSignService, MauiEthSignService>();
        // v0.4.1 user preferences (polling interval, history limit, theme).
        // MAUI Preferences-backed (not SecureStorage; not secret).
        builder.Services.AddSingleton<IUserPreferencesService, MauiUserPreferencesService>();

        // Recto.Shared scaffold: validators, handler scan, IBootloaderClient typed HttpClient.
        builder.Services.AddSharedServices(builder.Configuration, isClient: true);

        builder.Services.AddMauiBlazorWebView();

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
