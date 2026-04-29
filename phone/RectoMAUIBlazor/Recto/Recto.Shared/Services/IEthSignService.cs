using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side Ethereum signing service. Owns a BIP39 mnemonic in
/// platform <c>SecureStorage</c>, derives secp256k1 keypairs at
/// arbitrary BIP32/BIP44 paths, and signs EIP-191 / EIP-712 / RLP
/// digests on operator approval. The Python launcher / bootloader
/// tier never holds a private key &mdash; it only sends signing
/// requests; this service is the only code path that ever
/// materializes the secret bytes, and they never leave the phone.
///
/// <para>
/// Every <c>eth_sign</c> approval through Home.razor flows through
/// <see cref="SignPersonalSignAsync"/> (or the typed_data /
/// transaction siblings, future). The result is a 65-byte
/// <c>r||s||v</c> hex string that the phone returns via
/// <c>RespondRequest.EthSignatureRsv</c>; the Python bootloader
/// validates structural shape only and forwards the signature opaque
/// to the consumer (smart contract on chain, off-chain verifier,
/// capability-JWT scope enforcer, etc.).
/// </para>
///
/// <para>
/// Mnemonic creation is one-shot per <paramref name="alias"/> at the
/// service layer &mdash; <see cref="EnsureMnemonicAsync"/> generates a
/// fresh 24-word BIP39 mnemonic if none exists, otherwise returns the
/// existing account derived at the default path. Operators wanting to
/// import an existing mnemonic from another wallet use
/// <see cref="ImportMnemonicAsync"/> at v0.6+ (not in v0.5+ groundwork).
/// </para>
///
/// <para>
/// Threat model: the BIP39 mnemonic is the master secret. Loss of
/// the phone (and SecureStorage erased) means the keys are
/// unrecoverable unless the operator wrote the mnemonic down at
/// generation time. Future v0.6+ adds an export-mnemonic flow gated
/// on biometric + a destructive-confirmation modal so the operator
/// can back up. The current cut never displays the mnemonic in UI
/// (no accidental shoulder-surf risk during dev iteration).
/// </para>
/// </summary>
public interface IEthSignService
{
    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/> from
    /// the mnemonic stored under <paramref name="alias"/>. If no mnemonic
    /// exists yet, generates a fresh 24-word BIP39 mnemonic, persists it
    /// in <c>SecureStorage</c>, and returns the freshly-derived account.
    /// </summary>
    Task<Result<EthAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. Fails
    /// with <c>NotFound</c> if no mnemonic is provisioned for the alias.
    /// </summary>
    Task<Result<EthAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// True if a mnemonic has been provisioned for <paramref name="alias"/>.
    /// </summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Signs an EIP-191 personal_sign message with the secp256k1 key
    /// derived at <paramref name="derivationPath"/>. Computes
    /// <c>keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)</c>
    /// and produces a 65-byte <c>r||s||v</c> signature, returned as a
    /// 0x-prefixed hex string (132 chars total).
    /// </summary>
    /// <returns>
    /// Hex string with <c>0x</c> prefix, exactly 132 chars including
    /// the prefix. The <c>v</c> byte uses the modern EIP-155 base
    /// (<c>0</c> or <c>1</c>) plus 27, so MetaMask / Trust / Ledger
    /// accept the canonical <c>27</c>/<c>28</c> values.
    /// </returns>
    Task<Result<string>> SignPersonalSignAsync(
        string alias,
        string derivationPath,
        string message,
        CancellationToken ct);

    /// <summary>
    /// Removes the mnemonic stored under <paramref name="alias"/>.
    /// Intended for the Settings "Unpair all" emergency wipe and
    /// future per-alias revocation. No-op if absent.
    /// </summary>
    Task<Result> ClearAsync(string alias, CancellationToken ct);
}
