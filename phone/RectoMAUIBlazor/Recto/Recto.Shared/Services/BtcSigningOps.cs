using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Recto.Shared.Services;

/// <summary>
/// Pure-math Bitcoin signing primitives the phone-side
/// <c>IBtcSignService</c> impl composes. RIPEMD-160 (BouncyCastle's
/// <see cref="RipeMD160Digest"/>), HASH160, double-SHA-256, bech32
/// encoding (BIP-173), BIP-137 signed-message hash, secp256k1 ECDSA
/// sign with RFC 6979 deterministic-k + v-recovery, BIP-137 compact
/// signature encoding, P2WPKH address derivation.
///
/// <para>
/// Shares the secp256k1 curve with <c>EthSigningOps</c>; reuses
/// <see cref="EthSigningOps.SignWithRecovery"/>'s internals via the
/// shared BouncyCastle setup. The differences are: Bitcoin uses
/// double-SHA-256 (not Keccak-256) for the message digest, encodes
/// the signature as a 65-byte compact form with a header byte (not
/// Ethereum's r||s||v with v=27/28), and uses bech32 / Base58Check
/// for the address (not Keccak-256 last-20-bytes).
/// </para>
///
/// <para>
/// Wave-5 home: lives in Recto.Shared so Recto.Shared.Tests can reach
/// it via the existing project reference. Cross-platform pure
/// BouncyCastle math, no MAUI deps.
/// </para>
/// </summary>
public static class BtcSigningOps
{
    private static readonly X9ECParameters Secp256k1 =
        Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

    private static readonly ECDomainParameters Domain =
        new(Secp256k1.Curve, Secp256k1.G, Secp256k1.N, Secp256k1.H);

    // Bech32 charset (BIP-173).
    private const string Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Bech32Const = 1;
    private const uint Bech32mConst = 0x2BC830A3;

    // ---------------------------------------------------------------
    // Hashes
    // ---------------------------------------------------------------

    /// <summary>RIPEMD-160 hash (20-byte digest) via BouncyCastle.</summary>
    public static byte[] Ripemd160(byte[] data)
    {
        var d = new RipeMD160Digest();
        d.BlockUpdate(data, 0, data.Length);
        var output = new byte[20];
        d.DoFinal(output, 0);
        return output;
    }

    /// <summary>Bitcoin's HASH160 = RIPEMD-160(SHA-256(data)). 20-byte output.</summary>
    public static byte[] Hash160(byte[] data)
    {
        return Ripemd160(SHA256.HashData(data));
    }

    /// <summary>Bitcoin's omnipresent SHA-256(SHA-256(data)). 32-byte output.</summary>
    public static byte[] DoubleSha256(byte[] data)
    {
        return SHA256.HashData(SHA256.HashData(data));
    }

    /// <summary>
    /// BIP-137 signed-message hash:
    /// <c>double_sha256(0x18 || "Bitcoin Signed Message:\n" || varint(len(msg)) || msg)</c>.
    /// The <c>0x18</c> magic prefix byte (24 = length of the literal
    /// string <c>"Bitcoin Signed Message:\n"</c>) is the BIP-137 magic
    /// that distinguishes a message-signing preimage from any other
    /// secp256k1 hash. Without it, signatures recover to a different
    /// public key than what Bitcoin Core's <c>verifymessage</c>
    /// computes, breaking cross-wallet verification.
    /// </summary>
    public static byte[] SignedMessageHash(string message)
    {
        var msgBytes = Encoding.UTF8.GetBytes(message);
        var prefixStr = Encoding.ASCII.GetBytes("Bitcoin Signed Message:\n");
        var varint = EncodeVarint((ulong)msgBytes.Length);
        var combined = new byte[1 + prefixStr.Length + varint.Length + msgBytes.Length];
        combined[0] = 0x18;
        Buffer.BlockCopy(prefixStr, 0, combined, 1, prefixStr.Length);
        Buffer.BlockCopy(varint, 0, combined, 1 + prefixStr.Length, varint.Length);
        Buffer.BlockCopy(msgBytes, 0, combined, 1 + prefixStr.Length + varint.Length, msgBytes.Length);
        return DoubleSha256(combined);
    }

    private static byte[] EncodeVarint(ulong n)
    {
        if (n < 0xFD) return new[] { (byte)n };
        if (n <= 0xFFFF)
            return new byte[] { 0xFD, (byte)(n & 0xFF), (byte)((n >> 8) & 0xFF) };
        if (n <= 0xFFFFFFFFu)
            return new byte[] { 0xFE,
                (byte)(n & 0xFF), (byte)((n >> 8) & 0xFF),
                (byte)((n >> 16) & 0xFF), (byte)((n >> 24) & 0xFF) };
        return new byte[] { 0xFF,
            (byte)(n & 0xFF), (byte)((n >> 8) & 0xFF),
            (byte)((n >> 16) & 0xFF), (byte)((n >> 24) & 0xFF),
            (byte)((n >> 32) & 0xFF), (byte)((n >> 40) & 0xFF),
            (byte)((n >> 48) & 0xFF), (byte)((n >> 56) & 0xFF) };
    }

    // ---------------------------------------------------------------
    // Public-key compression
    // ---------------------------------------------------------------

    /// <summary>
    /// Convert Ethereum's 64-byte uncompressed public key (X || Y) to
    /// Bitcoin's 33-byte compressed form (0x02 || X for even Y,
    /// 0x03 || X for odd Y).
    /// </summary>
    public static byte[] CompressPublicKey(byte[] pubkey64)
    {
        if (pubkey64 is null || pubkey64.Length != 64)
            throw new ArgumentException("Public key must be 64 bytes (X||Y).", nameof(pubkey64));
        var x = pubkey64.AsSpan(0, 32).ToArray();
        var yLowByte = pubkey64[63];
        var compressed = new byte[33];
        compressed[0] = (byte)(0x02 + (yLowByte & 1));
        Buffer.BlockCopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    // ---------------------------------------------------------------
    // Bech32 encoding (BIP-173)
    // ---------------------------------------------------------------

    /// <summary>
    /// Encode a SegWit address per BIP-173 (witver=0) or BIP-350
    /// (witver=1+, bech32m). <paramref name="hrp"/> is the
    /// human-readable part — <c>"bc"</c> for mainnet, <c>"tb"</c> for
    /// testnet/signet, <c>"bcrt"</c> for regtest.
    /// </summary>
    public static string Bech32Encode(string hrp, int witnessVersion, byte[] program)
    {
        if (witnessVersion < 0 || witnessVersion > 16)
            throw new ArgumentException($"Witness version must be 0..16, got {witnessVersion}.", nameof(witnessVersion));
        var spec = witnessVersion == 0 ? Bech32Const : Bech32mConst;
        var converted = ConvertBits(program, 8, 5, pad: true);
        if (converted is null)
            throw new ArgumentException("Program could not be converted to 5-bit groups.", nameof(program));
        var data = new int[1 + converted.Length];
        data[0] = witnessVersion;
        Array.Copy(converted, 0, data, 1, converted.Length);
        var checksum = Bech32CreateChecksum(hrp, data, spec);
        var combined = new int[data.Length + checksum.Length];
        Array.Copy(data, 0, combined, 0, data.Length);
        Array.Copy(checksum, 0, combined, data.Length, checksum.Length);
        var sb = new StringBuilder(hrp.Length + 1 + combined.Length);
        sb.Append(hrp);
        sb.Append('1');
        foreach (var d in combined) sb.Append(Bech32Charset[d]);
        return sb.ToString();
    }

    private static uint Bech32Polymod(int[] values)
    {
        uint[] generator = { 0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3 };
        uint chk = 1;
        foreach (var v in values)
        {
            var b = chk >> 25;
            chk = ((chk & 0x1FFFFFF) << 5) ^ (uint)v;
            for (int i = 0; i < 5; i++)
            {
                if (((b >> i) & 1) != 0) chk ^= generator[i];
            }
        }
        return chk;
    }

    private static int[] Bech32HrpExpand(string hrp)
    {
        var result = new int[hrp.Length * 2 + 1];
        for (int i = 0; i < hrp.Length; i++) result[i] = hrp[i] >> 5;
        result[hrp.Length] = 0;
        for (int i = 0; i < hrp.Length; i++) result[hrp.Length + 1 + i] = hrp[i] & 31;
        return result;
    }

    private static int[] Bech32CreateChecksum(string hrp, int[] data, uint specConst)
    {
        var hrpExpanded = Bech32HrpExpand(hrp);
        var values = new int[hrpExpanded.Length + data.Length + 6];
        Array.Copy(hrpExpanded, 0, values, 0, hrpExpanded.Length);
        Array.Copy(data, 0, values, hrpExpanded.Length, data.Length);
        // Trailing 6 zeros for the checksum slots.
        var polymod = Bech32Polymod(values) ^ specConst;
        var result = new int[6];
        for (int i = 0; i < 6; i++)
            result[i] = (int)((polymod >> (5 * (5 - i))) & 31);
        return result;
    }

    private static int[]? ConvertBits(byte[] data, int fromBits, int toBits, bool pad)
    {
        int acc = 0;
        int bits = 0;
        var result = new System.Collections.Generic.List<int>();
        var maxv = (1 << toBits) - 1;
        var maxAcc = (1 << (fromBits + toBits - 1)) - 1;
        foreach (var value in data)
        {
            if (value < 0 || (value >> fromBits) != 0) return null;
            acc = ((acc << fromBits) | value) & maxAcc;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                result.Add((acc >> bits) & maxv);
            }
        }
        if (pad)
        {
            if (bits != 0) result.Add((acc << (toBits - bits)) & maxv);
        }
        else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0)
        {
            return null;
        }
        return result.ToArray();
    }

    // ---------------------------------------------------------------
    // Address derivation
    // ---------------------------------------------------------------

    private static readonly System.Collections.Generic.Dictionary<string, string> NetworkHrps = new()
    {
        ["mainnet"] = "bc",
        ["testnet"] = "tb",
        ["signet"] = "tb",
        ["regtest"] = "bcrt",
    };

    /// <summary>
    /// Derive a Bitcoin P2WPKH (native-SegWit) address from a 64-byte
    /// uncompressed public key. Compresses the pubkey, takes HASH160,
    /// bech32-encodes with the network's HRP at witver=0.
    /// </summary>
    public static string AddressFromPublicKeyP2wpkh(byte[] pubkey64, string network)
    {
        if (!NetworkHrps.TryGetValue(network, out var hrp))
            throw new ArgumentException($"Unknown network '{network}'.", nameof(network));
        var pub33 = CompressPublicKey(pubkey64);
        var h160 = Hash160(pub33);
        return Bech32Encode(hrp, 0, h160);
    }

    // ---------------------------------------------------------------
    // BIP-137 compact signature
    // ---------------------------------------------------------------

    /// <summary>
    /// Sign a 32-byte message hash with secp256k1 ECDSA + RFC 6979
    /// deterministic-k. Returns a 65-byte BIP-137 compact signature
    /// (header || r || s). The header byte encodes the recovery id +
    /// address kind: for P2WPKH default (the only kind we support
    /// today), <c>header = 27 + 12 + recovery_id</c> = 39..42.
    /// <c>s</c> is canonicalized to the low-s form per Bitcoin Core's
    /// signature-acceptance rules.
    /// </summary>
    /// <param name="msgHash">32-byte hash (e.g. output of <see cref="SignedMessageHash"/>).</param>
    /// <param name="privateKey">32-byte secp256k1 private key.</param>
    /// <returns>65 bytes: <c>header</c> (1) || <c>r</c> (32) || <c>s</c> (32).</returns>
    public static byte[] SignCompactBip137(byte[] msgHash, byte[] privateKey)
    {
        if (msgHash is null || msgHash.Length != 32)
            throw new ArgumentException("Message hash must be 32 bytes.", nameof(msgHash));
        if (privateKey is null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));

        var d = new BigInteger(1, privateKey);
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(d, Domain));
        var sig = signer.GenerateSignature(msgHash);
        var r = sig[0];
        var s = sig[1];

        var halfN = Secp256k1.N.ShiftRight(1);
        if (s.CompareTo(halfN) > 0) s = Secp256k1.N.Subtract(s);

        // Compute expected pubkey for v-recovery comparison.
        var expectedPub = EthSigningOps.PublicKeyFromPrivate(privateKey);

        for (int recId = 0; recId < 2; recId++)
        {
            // Build a fake Ethereum-style rsv with v=27+recId so we can
            // reuse EthSigningOps.RecoverPublicKey for the recovery
            // check. Bitcoin and Ethereum share secp256k1; the recovery
            // math is identical.
            var rsv = new byte[65];
            CopyFixed32(r, rsv, 0);
            CopyFixed32(s, rsv, 32);
            rsv[64] = (byte)(27 + recId);
            var recovered = EthSigningOps.RecoverPublicKey(msgHash, rsv);
            if (recovered is not null && BytesEqual(recovered, expectedPub))
            {
                // BIP-137 P2WPKH header byte: 27 + 12 + recId = 39..42.
                var compactSig = new byte[65];
                compactSig[0] = (byte)(27 + 12 + recId);
                CopyFixed32(r, compactSig, 1);
                CopyFixed32(s, compactSig, 33);
                return compactSig;
            }
        }
        throw new InvalidOperationException(
            "BIP-137 v-recovery failed: neither recId 0 nor 1 recovered the signing public key.");
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static byte[] UnsignedFixed32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length == 32) return bytes;
        if (bytes.Length > 32) throw new InvalidOperationException("Value exceeds 32 bytes.");
        var padded = new byte[32];
        Buffer.BlockCopy(bytes, 0, padded, 32 - bytes.Length, bytes.Length);
        return padded;
    }

    private static void CopyFixed32(BigInteger value, byte[] dest, int offset)
    {
        var bytes = UnsignedFixed32(value);
        Buffer.BlockCopy(bytes, 0, dest, offset, 32);
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
