using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Per-request context the operator visually confirms before approving.
/// The shape is a flat union: each <see cref="PendingRequest.Kind"/>
/// populates the fields relevant to it and leaves the others null.
/// <para>
/// Common fields (all kinds): <see cref="ChildPid"/>, <see cref="ChildArgv0"/>,
/// <see cref="RequestedAtUnix"/>, <see cref="OperationDescription"/>.
/// </para>
/// <para>
/// <c>single_sign</c> populates <see cref="PayloadHashB64u"/>.
/// </para>
/// <para>
/// <c>totp_provision</c> populates <see cref="TotpAlias"/>,
/// <see cref="TotpSecretB32"/>, and the optional algorithm parameters
/// (<see cref="TotpPeriodSeconds"/>, <see cref="TotpDigits"/>,
/// <see cref="TotpAlgorithm"/>).
/// </para>
/// <para>
/// <c>totp_generate</c> populates <see cref="TotpAlias"/> only; the phone
/// looks up the previously-provisioned secret by alias.
/// </para>
/// <para>
/// <c>session_issuance</c> populates <see cref="SessionBearer"/>,
/// <see cref="SessionScope"/>, <see cref="SessionLifetimeSeconds"/>,
/// <see cref="SessionMaxUses"/>, <see cref="SessionBootloaderId"/>. The
/// phone signs a JWT carrying these as claims and returns it via the
/// <c>session_jwt</c> field on <see cref="RespondRequest"/>.
/// </para>
/// <para>
/// <c>webauthn_assert</c> populates <see cref="WebAuthnRpId"/>,
/// <see cref="WebAuthnOrigin"/>, <see cref="WebAuthnChallengeB64u"/>, and
/// <see cref="WebAuthnUserHandleB64u"/> (optional). Phone constructs a
/// WebAuthn-shaped clientDataJSON + authenticatorData and signs them; the
/// assertion is returned via <see cref="RespondRequest.WebAuthnClientDataB64u"/>,
/// <see cref="RespondRequest.WebAuthnAuthenticatorDataB64u"/>, and the
/// existing <see cref="RespondRequest.SignatureB64u"/> field.
/// </para>
/// <para>
/// <c>eth_sign</c> populates <see cref="EthChainId"/>,
/// <see cref="EthMessageKind"/>, <see cref="EthAddress"/>,
/// <see cref="EthDerivationPath"/>, plus exactly one of
/// <see cref="EthMessageText"/> (for <c>personal_sign</c>),
/// <see cref="EthTypedDataJson"/> (for <c>typed_data</c>), or
/// <see cref="EthTransactionJson"/> (for <c>transaction</c>; reserved for
/// a follow-up). The phone derives the secp256k1 private key from its
/// BIP39 mnemonic via <see cref="EthDerivationPath"/>, computes the
/// EIP-191 / EIP-712 / RLP hash, signs, and returns the result as a
/// 65-byte r||s||v hex string in
/// <see cref="RespondRequest.EthSignatureRsv"/>.
/// </para>
/// <para>
/// <c>btc_sign</c> populates <see cref="BtcNetwork"/>,
/// <see cref="BtcMessageKind"/>, <see cref="BtcAddress"/>,
/// <see cref="BtcDerivationPath"/>, plus exactly one of
/// <see cref="BtcMessageText"/> (for <c>message_signing</c>) or
/// <see cref="BtcPsbtBase64"/> (for <c>psbt</c>; reserved). The phone
/// derives the secp256k1 private key from the SAME BIP-39 mnemonic
/// the eth_sign credential uses (different BIP-44 path tree), computes
/// the BIP-137 hash for <c>message_signing</c> or the relevant PSBT
/// per-input hashes, signs, and returns the 65-byte BIP-137 compact
/// signature base64-encoded in
/// <see cref="RespondRequest.BtcSignatureBase64"/>.
/// </para>
/// </summary>
public sealed record PendingRequestContext(
    [property: JsonPropertyName("child_pid")] int ChildPid,
    [property: JsonPropertyName("child_argv0")] string ChildArgv0,
    [property: JsonPropertyName("requested_at_unix")] long RequestedAtUnix,
    [property: JsonPropertyName("operation_description")] string OperationDescription,
    [property: JsonPropertyName("payload_hash_b64u")] string? PayloadHashB64u = null,
    [property: JsonPropertyName("totp_alias")] string? TotpAlias = null,
    [property: JsonPropertyName("totp_secret_b32")] string? TotpSecretB32 = null,
    [property: JsonPropertyName("totp_period_seconds")] int? TotpPeriodSeconds = null,
    [property: JsonPropertyName("totp_digits")] int? TotpDigits = null,
    [property: JsonPropertyName("totp_algorithm")] string? TotpAlgorithm = null,
    [property: JsonPropertyName("session_bearer")] string? SessionBearer = null,
    [property: JsonPropertyName("session_scope")] IReadOnlyList<string>? SessionScope = null,
    [property: JsonPropertyName("session_lifetime_seconds")] int? SessionLifetimeSeconds = null,
    [property: JsonPropertyName("session_max_uses")] int? SessionMaxUses = null,
    [property: JsonPropertyName("session_bootloader_id")] string? SessionBootloaderId = null,
    [property: JsonPropertyName("webauthn_rp_id")] string? WebAuthnRpId = null,
    [property: JsonPropertyName("webauthn_origin")] string? WebAuthnOrigin = null,
    [property: JsonPropertyName("webauthn_challenge_b64u")] string? WebAuthnChallengeB64u = null,
    [property: JsonPropertyName("webauthn_user_handle_b64u")] string? WebAuthnUserHandleB64u = null,
    // PKCS#11 / PGP (v0.5+): purpose tag (e.g. "ssh-login", "code-signing",
    // "git-commit", "mail-decrypt") drives the operator-UI copy so the human
    // sees what the request is for, not just opaque payload bytes. The
    // pkcs11_consumer_label / pgp_key_label fields surface which downstream
    // consumer the bootloader is sourcing the request from (SSH agent name,
    // GPG keyring entry, etc.) for additional operator context.
    [property: JsonPropertyName("purpose")] string? Purpose = null,
    [property: JsonPropertyName("pkcs11_consumer_label")] string? Pkcs11ConsumerLabel = null,
    [property: JsonPropertyName("pgp_key_label")] string? PgpKeyLabel = null,
    [property: JsonPropertyName("pgp_operation")] string? PgpOperation = null,
    // eth_sign (v0.5+): chain id (1=mainnet, 8453=Base, 11155111=Sepolia, ...),
    // message-kind discriminator (personal_sign / typed_data / transaction),
    // expected signer address (lowercase hex with 0x prefix), BIP32/BIP44
    // derivation path the phone should resolve the signing key from
    // (default "m/44'/60'/0'/0/0"), and exactly one of the three message-
    // body fields. The address field is set by the launcher / consumer at
    // request-creation time so the phone can refuse a request whose
    // derivation path produces a different address (defense against the
    // launcher accidentally crossing wires between two registered ETH
    // addresses on the same phone).
    [property: JsonPropertyName("eth_chain_id")] long? EthChainId = null,
    [property: JsonPropertyName("eth_message_kind")] string? EthMessageKind = null,
    [property: JsonPropertyName("eth_address")] string? EthAddress = null,
    [property: JsonPropertyName("eth_derivation_path")] string? EthDerivationPath = null,
    [property: JsonPropertyName("eth_message_text")] string? EthMessageText = null,
    [property: JsonPropertyName("eth_typed_data_json")] string? EthTypedDataJson = null,
    [property: JsonPropertyName("eth_transaction_json")] string? EthTransactionJson = null,
    // btc_sign (v0.5+): Bitcoin network discriminator
    // (mainnet / testnet / signet / regtest), message-kind discriminator
    // (message_signing / psbt), expected signer address (lowercase
    // bech32 for P2WPKH or Base58Check for legacy / nested-SegWit),
    // BIP32/BIP44 derivation path the phone resolves the signing key
    // from (default `m/84'/0'/0'/0/0` native SegWit), and exactly one
    // of the two message-body fields. The address field is set by the
    // launcher / consumer at request-creation time so the phone can
    // refuse a request whose derivation path produces a different
    // address. SAME mnemonic as eth_sign — different BIP-44 tree.
    [property: JsonPropertyName("btc_network")] string? BtcNetwork = null,
    [property: JsonPropertyName("btc_message_kind")] string? BtcMessageKind = null,
    [property: JsonPropertyName("btc_address")] string? BtcAddress = null,
    [property: JsonPropertyName("btc_derivation_path")] string? BtcDerivationPath = null,
    [property: JsonPropertyName("btc_message_text")] string? BtcMessageText = null,
    [property: JsonPropertyName("btc_psbt_base64")] string? BtcPsbtBase64 = null);

public static class PgpOperation
{
    public const string Sign = "sign";
    public const string Decrypt = "decrypt";
}

public static class Pkcs11Purpose
{
    public const string SshLogin = "ssh-login";
    public const string CodeSigning = "code-signing";
    public const string CertificateRequest = "certificate-request";
}
