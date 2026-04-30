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

    /// <summary>
    /// v0.6+: phone signs an ed25519-chain payload (Solana, Stellar, or
    /// XRP-ed25519) with a phone-resident ed25519 private key derived
    /// from the SAME BIP-39 mnemonic the eth_sign / btc_sign credentials
    /// use, via SLIP-0010 (NOT BIP-32 — secp256k1 vs ed25519 are
    /// different curves). Three chain trees, all hardened-only paths
    /// because SLIP-0010 ed25519 doesn't support non-hardened derivation:
    /// <list type="bullet">
    /// <item>SOL: <c>m/44'/501'/N'/0'</c> → <c>base58(pubkey32)</c>
    /// addresses (no checksum, Bitcoin alphabet — Phantom / Solflare
    /// convention).</item>
    /// <item>XLM: <c>m/44'/148'/N'</c> → StrKey <c>G…</c> addresses
    /// (RFC-4648 base32 with version byte 0x30 + CRC16-XMODEM checksum,
    /// SEP-0023 / SEP-0005).</item>
    /// <item>XRP-ed25519: <c>m/44'/144'/0'/0'/N'</c> → classic
    /// <c>r…</c> addresses (Ripple-flavored Base58Check + 0xED ed25519
    /// prefix on pubkey pre-image).</item>
    /// </list>
    /// Chain selected via <see cref="PendingRequestContext.EdChain"/>;
    /// message-kind selected via
    /// <see cref="PendingRequestContext.EdMessageKind"/> (currently
    /// only <c>message_signing</c>; <c>transaction</c> is reserved
    /// for a follow-up wave). Approval response carries both the
    /// 64-byte raw ed25519 signature in
    /// <see cref="RespondRequest.EdSignatureBase64"/> AND the 32-byte
    /// ed25519 public key in <see cref="RespondRequest.EdPubkeyHex"/>
    /// because XRP addresses are HASH160s and can't recover the pubkey
    /// (SOL and XLM addresses ARE invertible but carry the pubkey
    /// explicitly for protocol uniformity across the three chains).
    /// </summary>
    public const string EdSign = "ed_sign";
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

/// <summary>
/// Bitcoin-family coin discriminator carried on
/// <see cref="PendingRequestContext.BtcCoin"/>. The crypto primitives
/// (secp256k1, double-SHA-256, BIP-137, HASH160) are identical across
/// the family; the per-coin differences are the signed-message
/// preamble string, the address-format version bytes / bech32 HRP,
/// and the BIP-44 coin type. All four coins share the
/// <c>btc_sign</c> credential kind, distinguished by this value.
///
/// <para>Defaulting absent / null to <see cref="Bitcoin"/> preserves
/// backward compatibility with v0.5 launchers that pre-date the
/// multi-coin extension.</para>
/// </summary>
public static class BtcCoin
{
    /// <summary>Bitcoin (BTC) — default. <c>m/84'/0'/0'/0/N</c> native
    /// SegWit P2WPKH (<c>bc1q...</c>). Preamble:
    /// <c>"Bitcoin Signed Message:\n"</c>.</summary>
    public const string Bitcoin = "btc";

    /// <summary>Litecoin (LTC) — <c>m/84'/2'/0'/0/N</c> native SegWit
    /// P2WPKH (<c>ltc1q...</c>) with HRP <c>ltc</c>; legacy P2PKH
    /// version byte 0x30 (<c>L...</c>). Preamble:
    /// <c>"Litecoin Signed Message:\n"</c>.</summary>
    public const string Litecoin = "ltc";

    /// <summary>Dogecoin (DOGE) — <c>m/44'/3'/0'/0/N</c> legacy P2PKH
    /// only (<c>D...</c> address starting with version byte 0x1E).
    /// DOGE never adopted native SegWit. Preamble:
    /// <c>"Dogecoin Signed Message:\n"</c>.</summary>
    public const string Dogecoin = "doge";

    /// <summary>Bitcoin Cash (BCH) — <c>m/44'/145'/0'/0/N</c> legacy
    /// P2PKH (<c>1...</c>, same version byte as BTC's legacy). BCH
    /// retained Bitcoin's signed-message preamble post-fork; only
    /// the BIP-44 coin type and forward CashAddr surface differ
    /// (CashAddr deferred — legacy P2PKH still verifies on every
    /// BCH wallet). Preamble:
    /// <c>"Bitcoin Signed Message:\n"</c>.</summary>
    public const string BitcoinCash = "bch";
}

/// <summary>
/// Discriminator for the two shapes <see cref="PendingRequestKind.EdSign"/>
/// can carry.
/// </summary>
public static class EdMessageKind
{
    /// <summary>Recto-convention chain-specific signed-message: SHA-256
    /// of <c>chain-preamble || message_bytes</c>. Today's only wired
    /// modality.</summary>
    public const string MessageSigning = "message_signing";

    /// <summary>Chain-specific transaction-blob hashing (Solana tx hash,
    /// Stellar envelope hash with network passphrase, XRP sha512-half
    /// with TX_PREFIX). Reserved for a follow-up wave.</summary>
    public const string Transaction = "transaction";
}

/// <summary>
/// Ed25519-chain discriminator carried on
/// <see cref="PendingRequestContext.EdChain"/>. The crypto primitive
/// (raw 64-byte ed25519 signature over a 32-byte chain-specific
/// message hash) is identical across the family; per-chain
/// differences are the SLIP-0010 derivation path, the address
/// encoding, and the message preamble. All three chains share the
/// <c>ed_sign</c> credential kind, distinguished by this value.
/// </summary>
public static class EdChain
{
    /// <summary>Solana (SOL) — <c>m/44'/501'/N'/0'</c> SLIP-0010
    /// hardened path; <c>base58(pubkey32)</c> addresses (no checksum,
    /// Bitcoin alphabet — Phantom / Solflare convention). Preamble:
    /// <c>"Solana signed message:\n"</c>.</summary>
    public const string Solana = "sol";

    /// <summary>Stellar (XLM) — <c>m/44'/148'/N'</c> SLIP-0010 hardened
    /// path (SEP-0005); StrKey <c>G…</c> base32 addresses with version
    /// byte 0x30 + CRC16-XMODEM checksum. Preamble:
    /// <c>"Stellar signed message:\n"</c>.</summary>
    public const string Stellar = "xlm";

    /// <summary>XRP (ed25519) — <c>m/44'/144'/0'/0'/N'</c> SLIP-0010
    /// hardened path (Xumm / XRPL ed25519 convention); classic <c>r…</c>
    /// Base58Check addresses (Ripple alphabet) with version byte 0x00,
    /// AccountID = HASH160(0xED || pubkey32). Preamble:
    /// <c>"XRP signed message:\n"</c>.</summary>
    public const string Ripple = "xrp";
}
