"""Bitcoin-side helpers for the btc_sign credential kind (v0.5+).

This module is the launcher / bootloader / consumer-facing side of the
btc_sign flow. It does NOT hold private keys — those live exclusively
on the phone, derived at signing time from the operator's BIP-39 mnemonic
in platform secure storage at the BIP-44 path
``m/84'/0'/0'/0/N`` (default native-SegWit) or its sister paths
(``m/49'/0'`` nested SegWit, ``m/44'/0'`` legacy). The Python side here
only produces digests to be signed (BIP-137 message hash) and verifies
the resulting signatures against the (known) phone-derived address.

Threat model
------------

- Private keys are NEVER on this Python side. Every operation here is
  either (a) hashing a payload to produce something the phone signs,
  (b) verifying a 65-byte BIP-137 compact signature returned by the
  phone matches an expected address, or (c) deriving an address from a
  public key for display in operator UI. The phone-side MAUI service
  (IBtcSignService) does the actual private-key arithmetic.
- secp256k1 verification is delegated to ``recto.ethereum`` since
  Ethereum and Bitcoin use the same curve. Pure-Python, not constant
  time, but no private-key operation runs through it.
- RIPEMD-160 is implemented from scratch because Python's
  ``hashlib.new("ripemd160")`` only works on OpenSSL builds that ship
  the legacy provider, which most modern distros don't enable by
  default. ISO/IEC 10118-3 reference implementation; pinned by test
  vectors below.
- Bech32 / bech32m encoding (BIP-173 / BIP-350) is also pure-Python.
  Bech32 powers native-SegWit P2WPKH addresses; bech32m powers Taproot
  P2TR (reserved for a follow-up).

Public surface
--------------

- ``ripemd160(data: bytes) -> bytes`` — 20-byte RIPEMD-160 hash.
- ``hash160(data: bytes) -> bytes`` — RIPEMD-160(SHA-256(data)). Used
  for P2WPKH and P2PKH address derivation.
- ``double_sha256(data: bytes) -> bytes`` — Bitcoin's omnipresent
  SHA-256(SHA-256(x)) compose.
- ``signed_message_hash(message: bytes) -> bytes`` — BIP-137 hash:
  ``double_sha256("\\x18Bitcoin Signed Message:\\n" + varint(len(msg)) + msg)``.
- ``compress_public_key(pubkey64: bytes) -> bytes`` — 64-byte X||Y
  uncompressed → 33-byte compressed (0x02/0x03 + X).
- ``bech32_encode(hrp: str, witness_version: int, program: bytes) -> str``
  — BIP-173 (witver=0) or BIP-350 (witver=1+) bech32m encoding.
- ``bech32_decode(addr: str) -> tuple[str, int, bytes]`` — reverse;
  returns ``(hrp, witness_version, program)``.
- ``address_from_public_key(pubkey64, network="mainnet", kind="p2wpkh") -> str``
  — derive a Bitcoin address from the 64-byte uncompressed public key.
  ``kind`` ∈ ``{"p2wpkh", "p2pkh", "p2sh-p2wpkh"}``; default is the
  modern native-SegWit form (lowercase ``bc1q...`` on mainnet,
  ``tb1q...`` on testnet).
- ``parse_compact_signature(sig: str | bytes) -> tuple[int, int, int, str]``
  — split a 65-byte BIP-137 compact signature (header || r || s) into
  ``(r, s, recovery_id, address_kind)``.
- ``recover_public_key(msg_hash: bytes, compact_sig) -> bytes`` — given
  a 32-byte message hash and a 65-byte BIP-137 compact signature
  (raw bytes or base64), return the 64-byte public key that signed.
- ``recover_address(msg_hash, compact_sig, network="mainnet") -> str``
  — convenience wrapper: recover signer's P2WPKH address.
- ``verify_signature(msg_hash, compact_sig, expected_address, network="mainnet") -> bool``
  — recover-then-compare; returns True iff the recovered address
  matches ``expected_address`` (case-insensitive on bech32 hrp/witprog).

Optional extra
--------------

This module is in the ``recto[bitcoin]`` extra. It uses only the
Python standard library (``hashlib`` for SHA-256, ``int``/``pow`` for
modular arithmetic in dependencies via ``recto.ethereum``), so
installing the extra adds no new dependencies — it just gates the
import path so consumers that don't need BTC support don't pay the
import cost.
"""

from __future__ import annotations

import base64
import hashlib

from recto.ethereum import _ec_mul, _SECP256K1_GX, _SECP256K1_GY, _y_from_x  # type: ignore[attr-defined]
from recto.ethereum import recover_public_key as _eth_recover_public_key

__all__ = [
    "ripemd160",
    "hash160",
    "double_sha256",
    "signed_message_hash",
    "compress_public_key",
    "bech32_encode",
    "bech32_decode",
    "address_from_public_key",
    "parse_compact_signature",
    "recover_public_key",
    "recover_address",
    "verify_signature",
]


# ---------------------------------------------------------------------------
# RIPEMD-160 (ISO/IEC 10118-3 reference implementation, pure Python)
# Reference: Dobbertin, Bosselaers, Preneel, "RIPEMD-160: A Strengthened
# Version of RIPEMD" (1996). Pure-Python because OpenSSL legacy provider
# isn't reliably enabled across distros / Windows / macOS Python builds.
# ---------------------------------------------------------------------------


_RIPEMD160_K_LEFT = (
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
)
_RIPEMD160_K_RIGHT = (
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
)

_RIPEMD160_R_LEFT = (
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
    3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
    1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
    4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
)
_RIPEMD160_R_RIGHT = (
    5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
    6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
   15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
    8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
   12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
)
_RIPEMD160_S_LEFT = (
   11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
    7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
   11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
   11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
    9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
)
_RIPEMD160_S_RIGHT = (
    8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
    9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
    9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
   15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
    8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
)


def _rotl32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _ripemd160_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | ((~x) & 0xFFFFFFFF & z)
    if j < 48:
        return (x | ((~y) & 0xFFFFFFFF)) ^ z
    if j < 64:
        return (x & z) | (y & ((~z) & 0xFFFFFFFF))
    return x ^ (y | ((~z) & 0xFFFFFFFF))


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 hash (20-byte digest). Pure-Python reference impl."""
    # Initial state per RIPEMD-160 spec.
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Pad to a multiple of 64 bytes: message + 0x80 + zeros + 8-byte LE length-in-bits.
    msg = bytearray(data)
    msg_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    msg.extend(msg_len_bits.to_bytes(8, "little"))

    for offset in range(0, len(msg), 64):
        block = msg[offset:offset + 64]
        w = [int.from_bytes(block[i * 4:(i + 1) * 4], "little") for i in range(16)]

        a_l, b_l, c_l, d_l, e_l = h0, h1, h2, h3, h4
        a_r, b_r, c_r, d_r, e_r = h0, h1, h2, h3, h4

        for j in range(80):
            # Left line
            t = (a_l
                 + _ripemd160_f(j, b_l, c_l, d_l)
                 + w[_RIPEMD160_R_LEFT[j]]
                 + _RIPEMD160_K_LEFT[j // 16]) & 0xFFFFFFFF
            t = (_rotl32(t, _RIPEMD160_S_LEFT[j]) + e_l) & 0xFFFFFFFF
            a_l, e_l, d_l, c_l, b_l = e_l, d_l, _rotl32(c_l, 10), b_l, t

            # Right line
            t = (a_r
                 + _ripemd160_f(79 - j, b_r, c_r, d_r)
                 + w[_RIPEMD160_R_RIGHT[j]]
                 + _RIPEMD160_K_RIGHT[j // 16]) & 0xFFFFFFFF
            t = (_rotl32(t, _RIPEMD160_S_RIGHT[j]) + e_r) & 0xFFFFFFFF
            a_r, e_r, d_r, c_r, b_r = e_r, d_r, _rotl32(c_r, 10), b_r, t

        # Combine the two lines per RIPEMD-160 spec (note the rotation
        # of state slots in the combine step).
        t = (h1 + c_l + d_r) & 0xFFFFFFFF
        h1 = (h2 + d_l + e_r) & 0xFFFFFFFF
        h2 = (h3 + e_l + a_r) & 0xFFFFFFFF
        h3 = (h4 + a_l + b_r) & 0xFFFFFFFF
        h4 = (h0 + b_l + c_r) & 0xFFFFFFFF
        h0 = t

    return (
        h0.to_bytes(4, "little")
        + h1.to_bytes(4, "little")
        + h2.to_bytes(4, "little")
        + h3.to_bytes(4, "little")
        + h4.to_bytes(4, "little")
    )


def hash160(data: bytes) -> bytes:
    """Bitcoin's HASH160 = RIPEMD-160(SHA-256(data)). 20-byte output.
    Used for P2WPKH and P2PKH address derivation."""
    return ripemd160(hashlib.sha256(data).digest())


def double_sha256(data: bytes) -> bytes:
    """Bitcoin's omnipresent SHA-256(SHA-256(data)). 32-byte output."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Bitcoin signed-message (BIP-137)
# ---------------------------------------------------------------------------


def _varint_encode(n: int) -> bytes:
    """Bitcoin compact-size unsigned integer encoding. Used by the
    BIP-137 message-prefix length field."""
    if n < 0:
        raise ValueError(f"varint cannot encode negative {n}")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise ValueError(f"varint too large: {n}")


def signed_message_hash(message: bytes) -> bytes:
    """Compute the Bitcoin signed-message hash (BIP-137).

    Layout:
        double_sha256(0x18 || "Bitcoin Signed Message:\\n"
                      || varint(len(msg)) || msg)

    Where 0x18 is the magic prefix byte (24 = length of the literal
    string "Bitcoin Signed Message:\\n"). This is what every
    consumer-grade Bitcoin wallet (Bitcoin Core, Electrum, hardware
    wallets) computes when the user clicks "Sign Message" on a string.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    prefix_str = b"Bitcoin Signed Message:\n"
    prefix = bytes([len(prefix_str)]) + prefix_str
    body = _varint_encode(len(message)) + message
    return double_sha256(prefix + body)


# ---------------------------------------------------------------------------
# Public-key compression
# ---------------------------------------------------------------------------


def compress_public_key(pubkey64: bytes) -> bytes:
    """Convert Ethereum's 64-byte uncompressed public key (X || Y) to
    Bitcoin's 33-byte compressed form (0x02 || X for even Y, 0x03 || X
    for odd Y).

    secp256k1 is the same curve for both ecosystems; the encoding
    differs because Bitcoin pre-dates the uncompressed default and
    optimizes for transaction size.
    """
    if pubkey64 is None or len(pubkey64) != 64:
        raise ValueError(f"public key must be 64 bytes (X||Y), got {len(pubkey64) if pubkey64 else 0}")
    x = pubkey64[:32]
    y = int.from_bytes(pubkey64[32:], "big")
    return bytes([0x02 + (y & 1)]) + x


# ---------------------------------------------------------------------------
# Bech32 / bech32m encoding (BIP-173 / BIP-350)
# ---------------------------------------------------------------------------


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int], spec_const: int) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec_const
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> int | None:
    """Return the spec constant (BECH32 or BECH32M) the address checksums
    against, or None if the checksum is invalid for either."""
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if polymod == _BECH32_CONST:
        return _BECH32_CONST
    if polymod == _BECH32M_CONST:
        return _BECH32M_CONST
    return None


def _convert_bits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool) -> list[int] | None:
    """Group of bits → group of bits regrouping. Used to convert 8-bit
    bytes to 5-bit bech32 chunks (and vice versa)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits) != 0:
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, witness_version: int, program: bytes) -> str:
    """Encode a SegWit address per BIP-173 (witver=0) or BIP-350
    (witver=1+, bech32m). ``hrp`` is the human-readable part — ``"bc"``
    for mainnet, ``"tb"`` for testnet, ``"bcrt"`` for regtest."""
    if witness_version < 0 or witness_version > 16:
        raise ValueError(f"witness version must be 0..16, got {witness_version}")
    spec_const = _BECH32_CONST if witness_version == 0 else _BECH32M_CONST
    converted = _convert_bits(program, 8, 5, pad=True)
    if converted is None:
        raise ValueError("program could not be converted to 5-bit groups")
    data = [witness_version] + converted
    checksum = _bech32_create_checksum(hrp, data, spec_const)
    combined = data + checksum
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def bech32_decode(addr: str) -> tuple[str, int, bytes]:
    """Decode a bech32 / bech32m SegWit address back to
    ``(hrp, witness_version, program_bytes)``. Raises ValueError on
    malformed addresses, unknown HRPs, or checksum failures."""
    if not addr or len(addr) > 90:
        raise ValueError(f"address has invalid length {len(addr) if addr else 0}")
    # Bech32 mixed-case is forbidden; case-fold lowercase.
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("bech32 address must be all-lowercase or all-uppercase, not mixed")
    addr = addr.lower()
    sep = addr.rfind("1")
    if sep < 1 or sep + 7 > len(addr):
        raise ValueError("bech32 address missing or misplaced separator '1'")
    hrp = addr[:sep]
    data_part = addr[sep + 1:]
    data = []
    for c in data_part:
        idx = _BECH32_CHARSET.find(c)
        if idx < 0:
            raise ValueError(f"bech32 character '{c}' not in charset")
        data.append(idx)
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        raise ValueError("bech32 checksum invalid")
    witness_version = data[0]
    program_5bit = data[1:-6]
    program = _convert_bits(program_5bit, 5, 8, pad=False)
    if program is None:
        raise ValueError("bech32 program conversion failed")
    if witness_version == 0 and spec != _BECH32_CONST:
        raise ValueError("witness v0 must use bech32 (BIP-173), not bech32m")
    if witness_version != 0 and spec != _BECH32M_CONST:
        raise ValueError("witness v1+ must use bech32m (BIP-350), not bech32")
    if witness_version == 0 and len(program) not in (20, 32):
        raise ValueError(f"witness v0 program must be 20 or 32 bytes, got {len(program)}")
    return hrp, witness_version, bytes(program)


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------


_NETWORK_HRPS = {
    "mainnet": "bc",
    "testnet": "tb",
    "signet": "tb",   # signet shares testnet's HRP
    "regtest": "bcrt",
}


def address_from_public_key(
    pubkey64: bytes,
    network: str = "mainnet",
    kind: str = "p2wpkh",
) -> str:
    """Derive a Bitcoin address from a 64-byte uncompressed public key.

    ``kind`` selects the address type:
    - ``"p2wpkh"`` (default) — native SegWit, bech32 ``bc1q...`` /
      ``tb1q...``. Modern wallets default to this.
    - ``"p2pkh"`` — legacy Base58Check ``1...`` / ``m...`` / ``n...``.
    - ``"p2sh-p2wpkh"`` — nested SegWit, Base58Check ``3...`` / ``2...``.

    All three derive from HASH160 of the COMPRESSED public key; only
    the encoding differs. P2TR (Taproot, witver=1, x-only pubkey,
    bech32m) is reserved for a follow-up.
    """
    if network not in _NETWORK_HRPS:
        raise ValueError(f"network must be one of {list(_NETWORK_HRPS)}, got {network!r}")
    pub33 = compress_public_key(pubkey64)
    h160 = hash160(pub33)
    if kind == "p2wpkh":
        hrp = _NETWORK_HRPS[network]
        return bech32_encode(hrp, witness_version=0, program=h160)
    if kind == "p2pkh":
        version = 0x00 if network == "mainnet" else 0x6F
        return _base58check_encode(bytes([version]) + h160)
    if kind == "p2sh-p2wpkh":
        # Redeem script: OP_0 <20-byte hash160> = 0x00 0x14 <hash160>.
        redeem = b"\x00\x14" + h160
        version = 0x05 if network == "mainnet" else 0xC4
        return _base58check_encode(bytes([version]) + hash160(redeem))
    raise ValueError(
        f"address kind must be one of p2wpkh / p2pkh / p2sh-p2wpkh, got {kind!r}"
    )


_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_encode(payload: bytes) -> str:
    """Base58Check encoding for legacy / nested-SegWit Bitcoin addresses.
    Just enough Base58 to support the two non-bech32 address kinds; we
    don't expose decode publicly because the Recto v0.5+ scope only
    surfaces native-SegWit addresses to the operator UI."""
    checksum = double_sha256(payload)[:4]
    data = payload + checksum

    # Count leading zeros for the leading-1s prefix.
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break
    # Convert to base-58.
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_BASE58_ALPHABET[r])
    out.reverse()
    return ("1" * leading_zeros) + out.decode("ascii")


# ---------------------------------------------------------------------------
# BIP-137 compact signature parsing + recovery
# ---------------------------------------------------------------------------


def parse_compact_signature(sig: str | bytes) -> tuple[int, int, int, str]:
    """Split a 65-byte BIP-137 compact signature into its components.

    Accepts either:
    - 65 raw bytes
    - a base64 string (88 chars typical, possibly with trailing `=` padding)

    Returns ``(r, s, recovery_id, address_kind)`` where:
    - ``r`` and ``s`` are the secp256k1 ECDSA scalars as ints
    - ``recovery_id`` is 0..3 (matches what
      ``recto.ethereum.recover_public_key`` consumes after the
      header-byte ↔ rsv-v conversion)
    - ``address_kind`` ∈ ``{"p2pkh-uncompressed", "p2pkh", "p2sh-p2wpkh", "p2wpkh"}``
      derived from the header byte's encoding (BIP-137 §"Header byte
      values").

    Header byte encoding (BIP-137):
        27 + recovery_id                   → P2PKH uncompressed
        27 + 4 + recovery_id (= 31..34)    → P2PKH compressed
        27 + 8 + recovery_id (= 35..38)    → P2SH-P2WPKH (nested SegWit)
        27 + 12 + recovery_id (= 39..42)   → P2WPKH (native SegWit)
    """
    if isinstance(sig, str):
        sig_bytes = base64.b64decode(sig.strip(), validate=False)
    else:
        sig_bytes = bytes(sig)
    if len(sig_bytes) != 65:
        raise ValueError(f"compact signature must be 65 bytes, got {len(sig_bytes)}")
    header = sig_bytes[0]
    if header < 27 or header > 42:
        raise ValueError(f"BIP-137 header byte must be in 27..42, got {header}")
    rel = header - 27
    if rel < 4:
        recovery_id = rel
        address_kind = "p2pkh-uncompressed"
    elif rel < 8:
        recovery_id = rel - 4
        address_kind = "p2pkh"
    elif rel < 12:
        recovery_id = rel - 8
        address_kind = "p2sh-p2wpkh"
    else:
        recovery_id = rel - 12
        address_kind = "p2wpkh"
    r = int.from_bytes(sig_bytes[1:33], "big")
    s = int.from_bytes(sig_bytes[33:65], "big")
    return r, s, recovery_id, address_kind


def _ethereum_rsv_from_btc(r: int, s: int, recovery_id: int) -> bytes:
    """Convert Bitcoin BIP-137 (r, s, recovery_id) into the Ethereum
    r||s||v wire format that ``recto.ethereum.recover_public_key``
    consumes. v = 27 + recovery_id (canonical legacy form, what the
    Ethereum recover function expects)."""
    return (
        r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
        + bytes([27 + recovery_id])
    )


def recover_public_key(msg_hash: bytes, compact_sig: str | bytes) -> bytes:
    """Recover the 64-byte uncompressed public key (X||Y) that signed
    ``msg_hash`` to produce ``compact_sig``.

    ``msg_hash`` must be the 32-byte hash the signer signed (e.g. the
    output of ``signed_message_hash``).

    Delegates to ``recto.ethereum.recover_public_key`` since secp256k1
    is the same curve. The only Bitcoin-specific work is parsing the
    BIP-137 header byte into the recovery id.
    """
    if len(msg_hash) != 32:
        raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")
    r, s, recovery_id, _ = parse_compact_signature(compact_sig)
    rsv = _ethereum_rsv_from_btc(r, s, recovery_id)
    return _eth_recover_public_key(msg_hash, rsv)


def recover_address(
    msg_hash: bytes,
    compact_sig: str | bytes,
    network: str = "mainnet",
) -> str:
    """Recover the P2WPKH address that signed ``msg_hash`` to produce
    ``compact_sig``.

    The BIP-137 header byte ENCODES the address kind the signer
    intended (P2WPKH / P2SH-P2WPKH / P2PKH / P2PKH-uncompressed). We
    return the address kind matching the header byte so verifiers
    don't have to guess across the address-kind union.
    """
    pubkey = recover_public_key(msg_hash, compact_sig)
    _, _, _, kind = parse_compact_signature(compact_sig)
    if kind == "p2pkh-uncompressed":
        # Uncompressed P2PKH: HASH160 of the 65-byte uncompressed pub
        # (0x04 || X || Y), then Base58Check.
        version = 0x00 if network == "mainnet" else 0x6F
        h160 = hash160(b"\x04" + pubkey)
        return _base58check_encode(bytes([version]) + h160)
    return address_from_public_key(pubkey, network=network, kind=kind)


def verify_signature(
    msg_hash: bytes,
    compact_sig: str | bytes,
    expected_address: str,
    network: str = "mainnet",
) -> bool:
    """Recover the signer from ``compact_sig`` and check it matches
    ``expected_address``. Returns False rather than raising on any
    malformed-signature path so consumer code can branch on the
    boolean without try/except."""
    try:
        recovered = recover_address(msg_hash, compact_sig, network=network)
    except (ValueError, OverflowError):
        return False
    return recovered.lower() == expected_address.lower()
