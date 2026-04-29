using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>POST /v0.4/register</c> &mdash; pairing confirmation
/// plus the list of secrets the operator has authorized this phone to gate.
/// </summary>
public sealed record RegistrationResponse(
    [property: JsonPropertyName("registered")] bool Registered,
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("bootloader_id")] string BootloaderId,
    [property: JsonPropertyName("managed_secrets")] IReadOnlyList<ManagedSecretInfo> ManagedSecrets);

public sealed record ManagedSecretInfo(
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("secret")] string Secret,
    [property: JsonPropertyName("algorithm")] string Algorithm);
