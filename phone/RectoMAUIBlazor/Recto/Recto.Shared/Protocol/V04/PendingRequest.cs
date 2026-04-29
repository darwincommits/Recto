using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// One pending request the bootloader is waiting on the operator to
/// approve. The <see cref="Kind"/> field discriminates what the
/// request is for; different kinds populate different optional fields
/// on <see cref="PendingRequestContext"/>.
/// </summary>
public sealed record PendingRequest(
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("secret")] string Secret,
    [property: JsonPropertyName("context")] PendingRequestContext Context);

public static class PendingRequestKind
{
    /// <summary>v0.4 default: phone signs a payload hash with the enclave keypair.</summary>
    public const string SingleSign = "single_sign";

    /// <summary>v0.5: phone imports a TOTP shared secret into local SecureStorage.</summary>
    public const string TotpProvision = "totp_provision";

    /// <summary>v0.5: phone generates a current TOTP code from a previously-provisioned secret.</summary>
    public const string TotpGenerate = "totp_generate";

    /// <summary>v0.5+ (future): bootloader requests an operator-signed JWT capability for itself or an agent.</summary>
    public const string SessionIssuance = "session_issuance";

    /// <summary>
    /// v0.5+: phone produces a WebAuthn-compatible assertion (FIDO2 / RFC 8809)
    /// for a browser-side passkey login. The bootloader stands in as the
    /// authenticator from the relying-party web app's perspective; the phone
    /// produces the actual cryptographic material (clientDataJSON +
    /// authenticatorData + signature). Foundation for the Keycloak-replacement
    /// integration where Recto-equipped users can sign in to web apps via
    /// their phone instead of password + TOTP.
    /// </summary>
    public const string WebAuthnAssert = "webauthn_assert";

    /// <summary>
    /// v0.5+: phone signs an arbitrary payload with its enclave key for
    /// PKCS#11-compatible consumers (SSH agents, OpenSSL-backed code
    /// signers, hardware-token-emulating PKCS#11 modules). Wire-shape is
    /// identical to single_sign but the <c>purpose</c> field on
    /// <see cref="PendingRequestContext"/> distinguishes the use-case so
    /// the operator's UI shows "SSH login to host.example.com" rather than
    /// just "Sign data". Foundation for v0.5+'s real PKCS#11 module on
    /// the bootloader; today the wire format + UI lands.
    /// </summary>
    public const string Pkcs11Sign = "pkcs11_sign";

    /// <summary>
    /// v0.5+: phone signs or decrypts on behalf of a phone-resident PGP
    /// key for git commit signing, encrypted-mail decryption, etc. The
    /// bootloader exposes the phone-resident PGP key via a local
    /// gpg-agent socket; each cryptographic operation flows through this
    /// kind for biometric authorization. Today: protocol DTOs + UI seam;
    /// real gpg-agent socket integration is v0.5+.
    /// </summary>
    public const string PgpSign = "pgp_sign";

    /// <summary>
    /// v0.5+: phone signs an Ethereum-shaped payload with a phone-resident
    /// secp256k1 private key derived from a BIP39 mnemonic. Three message
    /// shapes are supported via <see cref="EthMessageKind"/> in the
    /// per-request context:
    /// <list type="bullet">
    /// <item><c>personal_sign</c> — EIP-191 prefixed message hash. Phone
    /// computes <c>keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)</c>
    /// and signs the hash; result is a 65-byte r||s||v signature.</item>
    /// <item><c>typed_data</c> — EIP-712 structured-data hash. Phone computes
    /// the typed-data hash from the JSON spec in
    /// <see cref="PendingRequestContext.EthTypedDataJson"/> and signs it; same
    /// 65-byte r||s||v output shape.</item>
    /// <item><c>transaction</c> — RLP-encoded Ethereum transaction signing
    /// (EIP-1559 / 2930 / legacy). Deferred to a follow-up; protocol space
    /// reserved here so consumers can plan against the field set.</item>
    /// </list>
    /// The operator approves a single signing operation per request. Agent
    /// signing for higher-frequency consumers (e.g. an automation script
    /// invoking ETH actions on behalf of the operator) flows through
    /// <see cref="SessionIssuance"/> capability JWTs whose <c>scope</c>
    /// claims encode a per-operation cap (target contract, method selector,
    /// value cap, gas cap, expiry) — not via direct phone-side approval per
    /// invocation.
    /// </summary>
    public const string EthSign = "eth_sign";

    /// <summary>
    /// v0.5+: phone signs a Bitcoin-shaped payload with a phone-resident
    /// secp256k1 private key derived from the SAME BIP-39 mnemonic the
    /// eth_sign credential uses (different BIP-44 path tree —
    /// <c>m/84'/0'/0'/0/N</c> for native-SegWit P2WPKH default,
    /// <c>m/49'/0'</c> for nested SegWit, <c>m/44'/0'</c> for legacy
    /// P2PKH). Two message shapes are supported via
    /// <see cref="BtcMessageKind"/>:
    /// <list type="bullet">
    /// <item><c>message_signing</c> — BIP-137 compact-signature
    /// signed-message verb. Phone computes
    /// <c>double_sha256("\x18Bitcoin Signed Message:\n" + varint(len(msg)) + msg)</c>,
    /// signs it, and returns a 65-byte base64-encoded compact
    /// signature whose header byte encodes the address kind +
    /// recovery id per BIP-137.</item>
    /// <item><c>psbt</c> — BIP-174 partially-signed Bitcoin transaction.
    /// Reserved for a follow-up. Phone receives a base64-encoded PSBT,
    /// signs the inputs it controls, returns the partially-signed PSBT.</item>
    /// </list>
    /// Same operator-approval ceremony as eth_sign — biometric gate per
    /// signing operation, capability-JWT delegation for agent flows
    /// (target output, value cap, fee cap, expiry).
    /// </summary>
    public const string BtcSign = "btc_sign";
}

/// <summary>
/// Discriminator for the three shapes <see cref="PendingRequestKind.EthSign"/>
/// can carry.
/// </summary>
public static class EthMessageKind
{
    /// <summary>EIP-191 prefixed message hash.</summary>
    public const string PersonalSign = "personal_sign";

    /// <summary>EIP-712 structured-data hash.</summary>
    public const string TypedData = "typed_data";

    /// <summary>RLP-encoded transaction signing (EIP-1559 / 2930 / legacy).</summary>
    public const string Transaction = "transaction";
}

/// <summary>
/// Discriminator for the two shapes <see cref="PendingRequestKind.BtcSign"/>
/// can carry.
/// </summary>
public static class BtcMessageKind
{
    /// <summary>BIP-137 compact-signature signed-message verb.</summary>
    public const string MessageSigning = "message_signing";

    /// <summary>BIP-174 partially-signed Bitcoin transaction. Reserved.</summary>
    public const string Psbt = "psbt";
}

/// <summary>
/// Bitcoin network discriminator carried on
/// <see cref="PendingRequestContext.BtcNetwork"/>. Same address bytes
/// derive different bech32 / Base58Check strings depending on the
/// network HRP / version byte, so the phone needs to know which to
/// produce when displaying the expected signing address to the
/// operator.
/// </summary>
public static class BtcNetwork
{
    /// <summary>Bitcoin mainnet — <c>bc1q...</c> P2WPKH addresses, <c>1...</c> legacy.</summary>
    public const string Mainnet = "mainnet";

    /// <summary>Testnet (testnet3) — <c>tb1q...</c> P2WPKH, <c>m...</c>/<c>n...</c> legacy.</summary>
    public const string Testnet = "testnet";

    /// <summary>Signet — shares testnet's HRP / version bytes.</summary>
    public const string Signet = "signet";

    /// <summary>Regtest — local-dev chain with hrp <c>bcrt</c>.</summary>
    public const string Regtest = "regtest";
}
