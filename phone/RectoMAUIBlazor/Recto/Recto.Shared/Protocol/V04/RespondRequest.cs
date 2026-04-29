using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader response to a pending request. POSTed to
/// <c>/v0.4/respond/{request_id}</c>. The shape is a flat union of all
/// kind-specific result fields:
/// <list type="bullet">
/// <item><c>single_sign</c> approval populates <see cref="SignatureB64u"/>.</item>
/// <item><c>totp_provision</c> approval has no extra fields (just <see cref="Decision"/>).</item>
/// <item><c>totp_generate</c> approval populates <see cref="TotpCode"/>.</item>
/// <item><c>session_issuance</c> approval populates <see cref="SessionJwt"/>.</item>
/// <item><c>webauthn_assert</c> approval populates <see cref="WebAuthnClientDataB64u"/>,
/// <see cref="WebAuthnAuthenticatorDataB64u"/>, and reuses <see cref="SignatureB64u"/>
/// for the assertion signature over <c>authenticatorData || sha256(clientDataJSON)</c>.</item>
/// <item><c>eth_sign</c> approval populates <see cref="EthSignatureRsv"/> with
/// the 65-byte r||s||v secp256k1 signature as a hex string with <c>0x</c>
/// prefix. The phone is also expected to populate <see cref="SignatureB64u"/>
/// with its registration-key signature over the request body so the
/// bootloader can verify the response came from the paired phone (same
/// guarantee single_sign provides).</item>
/// <item><c>btc_sign</c> approval populates
/// <see cref="BtcSignatureBase64"/> with the 65-byte BIP-137 compact
/// signature (header || r || s) base64-encoded (88 chars typical).
/// Header byte encodes recovery id + intended address kind per BIP-137
/// §"Header byte values". As with eth_sign, <see cref="SignatureB64u"/>
/// is also populated with the phone's registration-key Ed25519
/// envelope so the bootloader proves response provenance.</item>
/// </list>
/// Denial of any kind populates <see cref="Reason"/> instead.
/// </summary>
public sealed record RespondRequest(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("signature_b64u")] string? SignatureB64u = null,
    [property: JsonPropertyName("totp_code")] string? TotpCode = null,
    [property: JsonPropertyName("session_jwt")] string? SessionJwt = null,
    [property: JsonPropertyName("reason")] string? Reason = null,
    [property: JsonPropertyName("webauthn_client_data_b64u")] string? WebAuthnClientDataB64u = null,
    [property: JsonPropertyName("webauthn_authenticator_data_b64u")] string? WebAuthnAuthenticatorDataB64u = null,
    [property: JsonPropertyName("eth_signature_rsv")] string? EthSignatureRsv = null,
    [property: JsonPropertyName("btc_signature_base64")] string? BtcSignatureBase64 = null);

public static class RespondDecision
{
    public const string Approved = "approved";
    public const string Denied = "denied";
}
