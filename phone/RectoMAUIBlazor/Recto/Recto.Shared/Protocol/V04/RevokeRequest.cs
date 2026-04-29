using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader revocation request. POSTed to
/// <c>/v0.4/manage/revoke</c>. The surviving phone signs the bootloader's
/// fresh challenge with its enclave key; the bootloader verifies against
/// the surviving phone's registered public key, then removes
/// <see cref="TargetPhoneId"/> from its registered-phones roster.
/// <para>
/// In v0.4.0 a phone can revoke any other phone registered with the same
/// bootloader (single-operator assumption). v0.6+ multi-user models tighten
/// the authorization rules.
/// </para>
/// </summary>
public sealed record RevokeRequest(
    [property: JsonPropertyName("revoking_phone_id")] string RevokingPhoneId,
    [property: JsonPropertyName("target_phone_id")] string TargetPhoneId,
    [property: JsonPropertyName("challenge")] string Challenge,
    [property: JsonPropertyName("signature_b64u")] string SignatureB64u);
