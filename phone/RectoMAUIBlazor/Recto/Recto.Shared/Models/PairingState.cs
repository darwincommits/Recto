using System;
using System.Collections.Generic;

namespace Recto.Shared.Models;

/// <summary>
/// Per-bootloader pairing record persisted across app launches.
/// One pairing per phone in v0.4; multi-bootloader federation is v0.6+.
/// </summary>
/// <param name="PhoneId">Persistent phone identifier (uuid4) the bootloader knows us by.</param>
/// <param name="BootloaderId">The bootloader's id (uuid4) returned during pairing.</param>
/// <param name="BootloaderUrl">HTTPS URL the phone reaches the bootloader at.</param>
/// <param name="ManagedSecrets">Secrets the bootloader said this phone gates.</param>
/// <param name="PairedAt">UTC timestamp of pairing.</param>
/// <param name="BootloaderSpkiPin">
/// Round-6 cert-pinning addition. The SPKI hash (SHA-256 of
/// <c>SubjectPublicKeyInfo</c>, base64url-encoded) of the bootloader's TLS
/// cert as observed during pairing. Subsequent connections MUST present a
/// cert with the same SPKI; mismatch fails validation regardless of
/// system-trust outcome (which is what makes self-signed LAN bootloaders
/// viable post-pairing). Null on pairings made before round 6 landed; the
/// pairing flow falls back to system-trust-only validation in that case.
/// </param>
public sealed record PairingState(
    string PhoneId,
    string BootloaderId,
    string BootloaderUrl,
    IReadOnlyList<ManagedSecretRef> ManagedSecrets,
    DateTimeOffset PairedAt,
    string? BootloaderSpkiPin = null);

public sealed record ManagedSecretRef(string Service, string Secret, string Algorithm);
