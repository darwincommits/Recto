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
        // v0.5+ Bitcoin signing capability. Reads the SAME BIP-39
        // mnemonic the ETH service reads (one mnemonic per phone, two
        // BIP-44 trees: m/44'/60' for ETH, m/84'/0' for BTC native
        // SegWit). BIP-137 message_signing verb is wired today; PSBT
        // (BIP-174 transaction signing) is reserved for a follow-up.
        builder.Services.AddSingleton<IBtcSignService, MauiBtcSignService>();
        // Wave-8 ed25519-chain signing capability (SOL / XLM / XRP).
        // Reads the SAME BIP-39 mnemonic the ETH and BTC services read
        // (one mnemonic per phone, three new SLIP-0010 ed25519 trees:
        // m/44'/501'/N'/0' for SOL, m/44'/148'/N' for XLM,
        // m/44'/144'/0'/0'/N' for XRP-ed25519). Single cross-platform
        // singleton — BouncyCastle ed25519 + Slip10 derivation are the
        // canonical signing primitives on all targets (no per-platform
        // fan-out; iOS Secure Enclave + Android StrongBox don't natively
        // support SLIP-0010 ed25519 derivation paths, so the software
        // BouncyCastle path IS the implementation, not a fallback).
        builder.Services.AddSingleton<IEd25519ChainSignService, MauiEd25519ChainSignService>();
        // Wave 9: TRON signing service. Same one-mnemonic-shared-across-
        // services posture as ETH/BTC/ED -- reads the same SecureStorage
        // entry (recto.phone.eth.mnemonic.{alias}). Cross-platform
        // singleton; secp256k1 + Keccak-256 reuse EthSigningOps directly.
        builder.Services.AddSingleton<ITronSignService, MauiTronSignService>();
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
