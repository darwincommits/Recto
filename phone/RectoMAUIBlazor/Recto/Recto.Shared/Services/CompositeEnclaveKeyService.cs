using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Decorator that wraps two <see cref="IEnclaveKeyService"/> implementations
/// (a primary, typically hardware-backed; and a fallback, typically the
/// software impl). Tries the primary first; on specific failure modes
/// falls back to the secondary.
/// <para>
/// The intent is graceful degradation in edge cases where the hardware
/// enclave fails: a Pixel device whose StrongBox is misbehaving, an iOS
/// device whose Secure Enclave's biometric ACL got corrupted by a system
/// restore, etc. The fallback impl is the same software-Ed25519 path that
/// Windows / Mac Catalyst dev hosts use, so the phone stays functional
/// even when the enclave is unavailable.
/// </para>
/// <para>
/// SECURITY NOTE: when the fallback fires, the operator's signature is
/// produced by software-resident key material rather than enclave-protected
/// material. This degrades the security model. Production deployments
/// should ship with this decorator OFF by default (the platform impl runs
/// directly without a fallback) and enable it only after real-device
/// failure data shows the trade-off is worthwhile. v0.4.1 ships the
/// decorator code; v0.5+ adds operator-visible UI to opt in.
/// </para>
/// <para>
/// The composite reports its <see cref="Algorithm"/> as the PRIMARY's
/// algorithm. If the fallback uses a different algorithm (e.g. primary
/// is ecdsa-p256, fallback is ed25519), the bootloader will reject the
/// fallback's signatures during verification because it was registered
/// against the primary's public key. This is by design: an algorithm
/// mismatch should fail loudly, not silently. To use composite fallback
/// across algorithms, both impls must produce keys under the SAME
/// algorithm; mixing requires re-pairing.
/// </para>
/// </summary>
public sealed class CompositeEnclaveKeyService : IEnclaveKeyService
{
    private readonly IEnclaveKeyService _primary;
    private readonly IEnclaveKeyService _fallback;

    public CompositeEnclaveKeyService(IEnclaveKeyService primary, IEnclaveKeyService fallback)
    {
        _primary = primary ?? throw new ArgumentNullException(nameof(primary));
        _fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
    }

    public string Algorithm => _primary.Algorithm;

    public async Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
    {
        var primaryResult = await _primary.GenerateAsync(keyAlias, ct).ConfigureAwait(false);
        if (primaryResult.IsSuccess) return primaryResult;
        if (!ShouldFallback(primaryResult.Error)) return primaryResult;
        return await _fallback.GenerateAsync(keyAlias, ct).ConfigureAwait(false);
    }

    public async Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        var primaryResult = await _primary.KeyExistsAsync(keyAlias, ct).ConfigureAwait(false);
        if (primaryResult.IsSuccess) return primaryResult;
        if (!ShouldFallback(primaryResult.Error)) return primaryResult;
        return await _fallback.KeyExistsAsync(keyAlias, ct).ConfigureAwait(false);
    }

    public async Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        var primaryResult = await _primary.GetPublicKeyAsync(keyAlias, ct).ConfigureAwait(false);
        if (primaryResult.IsSuccess) return primaryResult;
        if (!ShouldFallback(primaryResult.Error)) return primaryResult;
        return await _fallback.GetPublicKeyAsync(keyAlias, ct).ConfigureAwait(false);
    }

    public async Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        var primaryResult = await _primary.SignAsync(keyAlias, message, ct).ConfigureAwait(false);
        if (primaryResult.IsSuccess) return primaryResult;
        if (!ShouldFallback(primaryResult.Error)) return primaryResult;
        return await _fallback.SignAsync(keyAlias, message, ct).ConfigureAwait(false);
    }

    public async Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
    {
        // Delete on BOTH so a fallback-resident key doesn't outlive its
        // primary. Failures are tolerated: we want the operator to be
        // able to wipe the key even if one of the underlying paths errored.
        var primaryResult = await _primary.DeleteAsync(keyAlias, ct).ConfigureAwait(false);
        var fallbackResult = await _fallback.DeleteAsync(keyAlias, ct).ConfigureAwait(false);
        return primaryResult.IsSuccess || fallbackResult.IsSuccess
            ? Result.Success()
            : primaryResult; // surface primary's error so the user-visible message is consistent
    }

    /// <summary>
    /// Decides whether a primary-impl failure should trigger fallback.
    /// True for transient / hardware-availability errors (the kind that
    /// software fallback can paper over); false for user-driven failures
    /// (cancelled biometric, explicit denial) where falling back to a
    /// different signing path would violate the operator's intent.
    /// </summary>
    private static bool ShouldFallback(Error error)
    {
        var message = (error.Message ?? string.Empty).ToLowerInvariant();

        // Don't fall back when the user explicitly cancelled or denied:
        // their intent was "no", not "try a different path".
        if (FallbackBlockingPhrases.Any(phrase => message.Contains(phrase)))
        {
            return false;
        }

        // Fall back on hardware availability / configuration failures.
        return FallbackTriggerPhrases.Any(phrase => message.Contains(phrase));
    }

    private static readonly IReadOnlyList<string> FallbackBlockingPhrases = new[]
    {
        "cancelled",
        "canceled",
        "user denied",
        "negative button",
        "biometric cancelled",
    };

    private static readonly IReadOnlyList<string> FallbackTriggerPhrases = new[]
    {
        "strongbox", "tee unavailable", "keystore", "enclave unavailable",
        "errsecparam", "errsecunimplemented", "errsecnotavailable",
        "nosuchalgorithmexception", "providerexception",
        "secure enclave", "biometric not enrolled",
    };
}

internal static class CompositeFallbackEnumerableExtensions
{
    public static bool Any(this IReadOnlyList<string> source, Func<string, bool> predicate)
    {
        foreach (var item in source)
        {
            if (predicate(item)) return true;
        }
        return false;
    }
}
