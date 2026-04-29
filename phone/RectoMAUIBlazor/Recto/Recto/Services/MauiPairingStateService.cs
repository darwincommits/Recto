using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// MAUI-side persistence for the phone's pairing record + persistent phone id.
/// Both live in <see cref="SecureStorage"/> &mdash; the pairing JSON under
/// <c>recto.phone.pairing</c>, the phone id under <c>recto.phone.id</c>.
/// </summary>
public sealed class MauiPairingStateService : IPairingStateService
{
    private const string PhoneIdKey = "recto.phone.id";
    private const string PairingStateKey = "recto.phone.pairing";

    public async Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
    {
        try
        {
            var json = await SecureStorage.Default.GetAsync(PairingStateKey).ConfigureAwait(false);
            if (string.IsNullOrEmpty(json))
            {
                return Result.Success<PairingState?>(null);
            }

            var state = JsonSerializer.Deserialize<PairingState>(json);
            return Result.Success(state);
        }
        catch (Exception ex)
        {
            return Result.Failure<PairingState?>(Error.Failure($"Failed to read pairing state: {ex.Message}"));
        }
    }

    public async Task<Result> SaveAsync(PairingState state, CancellationToken ct)
    {
        try
        {
            var json = JsonSerializer.Serialize(state);
            await SecureStorage.Default.SetAsync(PairingStateKey, json).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure($"Failed to save pairing state: {ex.Message}"));
        }
    }

    public Task<Result> ClearAsync(CancellationToken ct)
    {
        try
        {
            SecureStorage.Default.Remove(PairingStateKey);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to clear pairing state: {ex.Message}")));
        }
    }

    public async Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct)
    {
        try
        {
            var existing = await SecureStorage.Default.GetAsync(PhoneIdKey).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(existing))
            {
                return Result.Success(existing);
            }

            var newId = Guid.NewGuid().ToString();
            await SecureStorage.Default.SetAsync(PhoneIdKey, newId).ConfigureAwait(false);
            return Result.Success(newId);
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure($"Failed to get phone id: {ex.Message}"));
        }
    }
}
