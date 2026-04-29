using System;
using System.Linq;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Recto.Shared.Services;

/// <summary>
/// Pure-math Ethereum signing primitives the phone-side
/// <c>IEthSignService</c> impl composes. Keccak-256, secp256k1 ECDSA
/// sign with RFC 6979 deterministic-k + v-recovery, EIP-191 hash,
/// public-key + address derivation from a 32-byte private key.
///
/// <para>
/// All math is BouncyCastle-backed so this works identically across
/// every MAUI target (Windows, Mac Catalyst, iOS Simulator, iOS
/// device, Android). No platform-specific crypto. No
/// <c>System.Security.Cryptography</c> for the curve work — .NET
/// stdlib doesn't ship secp256k1 (the curve is intentionally absent
/// because of historical concerns; Ethereum / Bitcoin use it anyway,
/// so we reach for BC).
/// </para>
///
/// <para>
/// Wave-4 home: this class lives in Recto.Shared so Recto.Shared.Tests
/// can reach it via the existing project reference. Cross-platform
/// math has no MAUI deps; the platform-specific orchestrator
/// (<c>MauiEthSignService</c>) stays in the host project where
/// <c>Microsoft.Maui.Storage.SecureStorage</c> is available.
/// </para>
/// </summary>
public static class EthSigningOps
{
    private static readonly X9ECParameters Secp256k1 =
        Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

    private static readonly ECDomainParameters Domain =
        new(Secp256k1.Curve, Secp256k1.G, Secp256k1.N, Secp256k1.H);

    /// <summary>
    /// Generate a fresh 32-byte secp256k1 private key from a CSPRNG.
    /// The key value is in <c>[1, n-1]</c> per ECDSA convention.
    /// </summary>
    public static byte[] GeneratePrivateKey()
    {
        var rng = new SecureRandom();
        BigInteger d;
        do
        {
            var bytes = new byte[32];
            rng.NextBytes(bytes);
            d = new BigInteger(1, bytes);
        }
        while (d.SignValue == 0 || d.CompareTo(Secp256k1.N) >= 0);
        return UnsignedFixed32(d);
    }

    /// <summary>
    /// Compute the 64-byte uncompressed public key (X || Y, big-endian,
    /// no <c>0x04</c> prefix, no DER) from a 32-byte private key.
    /// This is Ethereum's wire format, not Bitcoin's compressed form.
    /// </summary>
    public static byte[] PublicKeyFromPrivate(byte[] privateKey)
    {
        if (privateKey is null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
        var d = new BigInteger(1, privateKey);
        var q = Domain.G.Multiply(d).Normalize();
        var x = UnsignedFixed32(q.AffineXCoord.ToBigInteger());
        var y = UnsignedFixed32(q.AffineYCoord.ToBigInteger());
        var pub = new byte[64];
        Buffer.BlockCopy(x, 0, pub, 0, 32);
        Buffer.BlockCopy(y, 0, pub, 32, 32);
        return pub;
    }

    /// <summary>
    /// Keccak-256 (32-byte digest). Original-Keccak padding (<c>0x01</c>),
    /// NOT FIPS-202 SHA3-256 padding (<c>0x06</c>). Ethereum addresses,
    /// EIP-191 hashes, EIP-712 hashes, transaction hashes, contract
    /// function selectors all use this exact variant.
    /// </summary>
    public static byte[] Keccak256(byte[] data)
    {
        var d = new KeccakDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var output = new byte[32];
        d.DoFinal(output, 0);
        return output;
    }

    /// <summary>
    /// EIP-191 personal_sign hash:
    /// <c>keccak256(0x19 || "Ethereum Signed Message:\n" || len(message) || message)</c>.
    /// Matches what every consumer-grade ETH wallet (MetaMask, Trust,
    /// Coinbase Wallet, Ledger Live) computes when the user clicks
    /// "Sign Message" on a string. The leading <c>0x19</c> byte is
    /// the EIP-191 version byte and is non-negotiable — without it,
    /// signatures produced here recover to a different public key
    /// than what Solidity's <c>ECDSA.recover()</c> +
    /// <c>MessageHashUtils.toEthSignedMessageHash()</c> compute,
    /// breaking cross-wallet / on-chain verification.
    /// </summary>
    public static byte[] PersonalSignHash(string message)
    {
        var msgBytes = System.Text.Encoding.UTF8.GetBytes(message);
        var prefix = $"Ethereum Signed Message:\n{msgBytes.Length}";
        var prefixBytes = System.Text.Encoding.UTF8.GetBytes(prefix);
        // Layout: [0x19] || prefix bytes || message bytes.
        // The 0x19 version byte is per EIP-191 §"Specification of the
        // Initial Version" (version byte = 0x45 for 'E', NO, wait —
        // the version byte is 0x45 for EIP-191 V1; the leading 0x19
        // is the "validator" / structured-data discriminator that
        // distinguishes EIP-191 envelopes from other signing forms.
        // Reference:
        // https://eips.ethereum.org/EIPS/eip-191#specification-of-the-initial-version)
        var combined = new byte[1 + prefixBytes.Length + msgBytes.Length];
        combined[0] = 0x19;
        Buffer.BlockCopy(prefixBytes, 0, combined, 1, prefixBytes.Length);
        Buffer.BlockCopy(msgBytes, 0, combined, 1 + prefixBytes.Length, msgBytes.Length);
        return Keccak256(combined);
    }

    /// <summary>
    /// 0x-prefixed lowercase hex Ethereum address derived from a
    /// 64-byte uncompressed public key. Address is the last 20 bytes
    /// of <c>keccak256(pubkey64)</c>.
    /// </summary>
    public static string AddressFromPublicKey(byte[] pubkey64)
    {
        if (pubkey64 is null || pubkey64.Length != 64)
            throw new ArgumentException("Public key must be 64 bytes.", nameof(pubkey64));
        var h = Keccak256(pubkey64);
        var addrBytes = new byte[20];
        Buffer.BlockCopy(h, 12, addrBytes, 0, 20);
        return "0x" + ToLowerHex(addrBytes);
    }

    /// <summary>
    /// Sign a 32-byte message hash with secp256k1 ECDSA + RFC 6979
    /// deterministic-k. Returns a 65-byte <c>r||s||v</c> signature.
    /// The <c>s</c> value is canonicalized to the low-s form
    /// (<c>s &lt; n/2</c>) per Ethereum's signature acceptance rules.
    /// The <c>v</c> byte is <c>27</c> or <c>28</c> (legacy
    /// canonical encoding); add the chain id prefix at the consumer
    /// layer if EIP-155 replay protection is needed.
    /// </summary>
    /// <param name="msgHash">32-byte hash the signer is signing (e.g. output of <see cref="PersonalSignHash"/>).</param>
    /// <param name="privateKey">32-byte secp256k1 private key.</param>
    /// <returns>65 bytes: <c>r</c> (32) || <c>s</c> (32) || <c>v</c> (1).</returns>
    public static byte[] SignWithRecovery(byte[] msgHash, byte[] privateKey)
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

        // Canonicalize to low-s: if s > n/2, replace with n - s.
        // Ethereum (post-EIP-2) rejects high-s signatures.
        var halfN = Secp256k1.N.ShiftRight(1);
        if (s.CompareTo(halfN) > 0)
            s = Secp256k1.N.Subtract(s);

        // Compute the expected public key once so v-recovery can compare.
        var expectedPub = PublicKeyFromPrivate(privateKey);

        // Try recovery ids 0 and 1; whichever recovers the right pub key wins.
        for (int recId = 0; recId < 2; recId++)
        {
            var recovered = TryRecoverPublicKey(msgHash, r, s, recId);
            if (recovered is not null && BytesEqual(recovered, expectedPub))
            {
                var rsv = new byte[65];
                CopyFixed32(r, rsv, 0);
                CopyFixed32(s, rsv, 32);
                rsv[64] = (byte)(27 + recId); // legacy canonical v
                return rsv;
            }
        }
        throw new InvalidOperationException("v-recovery failed: neither recId 0 nor 1 recovered the signing public key.");
    }

    /// <summary>
    /// Recover the signer's public key from <c>(msg_hash, r, s, v)</c>.
    /// Returns 64 bytes <c>X||Y</c>. Returns null if recovery fails
    /// (e.g. <c>r</c> not on curve, recovered point at infinity).
    /// Used internally for v-recovery; exposed for completeness.
    /// </summary>
    public static byte[]? RecoverPublicKey(byte[] msgHash, byte[] rsv)
    {
        if (msgHash is null || msgHash.Length != 32) return null;
        if (rsv is null || rsv.Length != 65) return null;
        var r = new BigInteger(1, rsv.AsSpan(0, 32).ToArray());
        var s = new BigInteger(1, rsv.AsSpan(32, 32).ToArray());
        var v = rsv[64];
        var recId = v >= 27 ? v - 27 : v;
        if (recId is < 0 or > 1) return null; // recIds 2/3 cover r >= n; rare, rejected for parity with Ethereum canonical acceptance.
        return TryRecoverPublicKey(msgHash, r, s, recId);
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static byte[]? TryRecoverPublicKey(byte[] msgHash, BigInteger r, BigInteger s, int recId)
    {
        // Reference: SEC1 §4.1.6, with the recId bit selecting Y parity.
        // We only call this with recId ∈ {0, 1}; recId 2/3 (covering r >= n)
        // is rare on secp256k1 and explicitly rejected at the public surface
        // for parity with Ethereum's canonical signature acceptance.
        var n = Secp256k1.N;
        var i = BigInteger.ValueOf(recId / 2);
        var x = r.Add(i.Multiply(n));
        // Curve field characteristic — public API regardless of the
        // curve's concrete subtype. (`SecP256K1Curve` itself is internal
        // in BouncyCastle.Cryptography 2.x; reaching for it directly
        // breaks the build.)
        var p = Secp256k1.Curve.Field.Characteristic;
        if (x.CompareTo(p) >= 0) return null;

        ECPoint R;
        try { R = DecompressPoint(recId & 1, x); }
        catch { return null; }
        if (R is null) return null;

        // nR == infinity check
        var nR = R.Multiply(n).Normalize();
        if (!nR.IsInfinity) return null;

        var e = new BigInteger(1, msgHash);
        var eInvNeg = BigInteger.Zero.Subtract(e).Mod(n);
        var rInv = r.ModInverse(n);
        var srInv = rInv.Multiply(s).Mod(n);
        var eInvrInv = rInv.Multiply(eInvNeg).Mod(n);

        // Q = r^-1 (sR - eG)
        var Q = ECAlgorithms.SumOfTwoMultiplies(Domain.G, eInvrInv, R, srInv).Normalize();
        if (Q.IsInfinity) return null;

        var qx = UnsignedFixed32(Q.AffineXCoord.ToBigInteger());
        var qy = UnsignedFixed32(Q.AffineYCoord.ToBigInteger());
        var pub = new byte[64];
        Buffer.BlockCopy(qx, 0, pub, 0, 32);
        Buffer.BlockCopy(qy, 0, pub, 32, 32);
        return pub;
    }

    private static ECPoint DecompressPoint(int yParity, BigInteger x)
    {
        // Compressed point form: 0x02 = even y, 0x03 = odd y.
        var compressed = new byte[33];
        compressed[0] = (byte)(0x02 + yParity);
        var xBytes = UnsignedFixed32(x);
        Buffer.BlockCopy(xBytes, 0, compressed, 1, 32);
        return Secp256k1.Curve.DecodePoint(compressed);
    }

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

    private static string ToLowerHex(byte[] bytes)
    {
        var hex = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            hex[i * 2] = ToHexChar(b >> 4);
            hex[i * 2 + 1] = ToHexChar(b & 0xF);
        }
        return new string(hex);
    }

    private static char ToHexChar(int nibble) => (char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
}
