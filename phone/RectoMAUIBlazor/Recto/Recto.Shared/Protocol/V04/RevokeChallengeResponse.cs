using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Response shape for <c>GET /v0.4/manage/revoke_challenge?phone_id=&lt;self&gt;</c>.
/// The phone signs the challenge bytes and includes the signature in
/// the subsequent <c>POST /v0.4/manage/revoke</c> body, proving it
/// authored the revocation. Single-use, 60s TTL, same shape as the
/// pairing challenge.
/// </summary>
public sealed record RevokeChallengeResponse(
    [property: JsonPropertyName("challenge_b64u")] string ChallengeB64u,
    [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);
