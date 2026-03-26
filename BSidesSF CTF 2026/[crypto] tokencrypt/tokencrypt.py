#!/usr/bin/env python3
"""TokenCrypt: a military-grade block cipher optimized for LLM token encryption

Public API:
    - key(key96: int | None) -> TokenCrypt
    - encrypt(plaintext: int, rounds: int = 128) -> int
    - decrypt(ciphertext: int, rounds: int = 128) -> int
    - test(rounds: int = 128) -> bool

How the cipher is built:
    0. TokenCrypt is a traditional balanced Feistel Network with 24 bit block sizes
    1. A 24-bit plaintext is split into two 12-bit halves.
    2. The network is between 16 and 1024 rounds, in 16 round chunks
    3. For each chunk, 16-round Feistel core C_s runs on those halves (keyed by 16-bit s).
    4. Every 16 rounds are transformed by an affine layer A(z)
       using a matrix M, where A(z) = M*z XOR b, over GF(2), where:
       - M is a 24x24 invertible binary matrix built from 56 key-bit seed.
       - b is a 24-bit affine offset.
    5. encrypt/decrypt repeats these 16 round chunks until all rounds are applied

Round parameter:
    - rounds is the total number of Feistel rounds exposed to callers.
    - rounds must be a positive multiple of 16 in [16, 1024].
    - Example: rounds=128 means there will be 8 affine mixing steps

Why 24-bit blocks:
    - TokenCrypt is intended for token-level encryption (hence the name),
      especially GPT-5.x token IDs.
    - A 24-bit block can hold very large token IDs directly, covering current
      LLM token ranges and leaving room for likely future growth.
    - This avoids packing multiple tokens into wider blocks just to fit IDs,
      which keeps encoding/decoding overhead low.
    - Because encryption is applied one token at a time, usage resembles a
      stream-cipher over token sequences, so no additional block mode
      orchestration is required

Security posture:
    - TokenCrypt offers incredible security. Thanks to the Luby-Rackoff theorem
      we know only 4 rounds are sufficient to to provide a perfect PRF. We chain
      way more than 4 rounds together because those tricky mathematicians are
      always overconfident with their so-called "proofs".
      It should be clear that with a 96 bit key, so many rounds, layered mixing,
      and randomized affine transforms TokenCrypt is in a security class of it's own.


One Feistel round (inside C_s), matching this implementation:

   Feistel Round i (24-bit block split into 12 + 12)

                    Input Block X
                 +-------------------+
                 |       24 bits     |
                 +-------------------+
                           |
                           v
                  +-----------------+
                  |  Split: L || R  |
                  |   L:12   R:12   |
                  +-----------------+
                     |           |
                     |           +------------------------------------+
                     |           |                                    |
                     |           |                                    v
                     |           |                  +---------------------------+
                     |           |                  |      f_s(R, i, s)         |
                     |           |                  |---------------------------|
                     |           |                  | 1) t = T_s(R, i, s)       |
                     |           |                  | 2) u = ROTL12(t, rot)     |
                     |           |                  | 3) rc = round_const(i,s)  |
                     |           |                  | 4) f = u XOR rc           |
                     |           |                  +---------------------------+
                     |           |                                    |
                     |           |                                    v
                     |           |                         +-------------------+
                     +------------------------------------>|       XOR         |
                                 |                         |   L XOR f_s(...)  |
                                 |                         +-------------------+
                                 |                                   |
                                 |                                   |
                                 |                                   |
                 +---------------+       +---------------------------+
                 |                       |
                 |                       |
                 |                       |
                 v                       v
        +-------------------+   +-------------------+
        |    New Left L'    |   |    New Right R'   |
        +-------------------+   +-------------------+
                  |                      |
                  +----------+     +-----+
                             |     |
                             V     V
                       +------------------+
                       |  Join: L' || R'  |
                       |   L':12 R':12    |
                       |     24 bits      |
                       | New Output Block |
                       +------------------+

"""

from __future__ import annotations

import os

MASK12 = (1 << 12) - 1
MASK24 = (1 << 24) - 1
MASK64 = (1 << 64) - 1

# 4-bit S-box used inside the round function tweak.
SBOX4 = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2,
]


def _rotl(x: int, r: int, width: int) -> int:
    r %= width
    mask = (1 << width) - 1
    return ((x << r) | (x >> (width - r))) & mask


def _rotl12(x: int, r: int) -> int:
    return _rotl(x, r, 12)


def _split24(x: int) -> tuple[int, int]:
    """Split one 24-bit block into left/right 12-bit halves."""
    x &= MASK24
    l = (x >> 12) & MASK12
    r = x & MASK12
    return l, r


def _join24(l: int, r: int) -> int:
    """Join left/right 12-bit halves back into one 24-bit block."""
    return ((l & MASK12) << 12) | (r & MASK12)


def _round_const(i: int, s12: int) -> int:
    return ((0x3D * (i + 1)) ^ s12) & MASK12


def _tweak_s(r: int, i: int, s: int) -> int:
    """Apply a keyed nibble substitution to the top nibble of a 12-bit half."""
    r &= MASK12
    u = (r >> 8) & 0xF

    k0 = (s >> 0) & 0xF
    k1 = (s >> 4) & 0xF

    u2 = SBOX4[u ^ (k0 ^ (i & 0xF))] ^ k1
    return ((u2 & 0xF) << 8) | (r & 0x0FF)


def _f_s(r: int, i: int, s: int) -> int:
    """12-bit Feistel round function."""
    s &= 0xFFFF       # round key
    s12 = s & MASK12  # lower 12 bits of round key
    rot = ((s >> 8) % 11) + 1
    t = _tweak_s(r, i, s)
    rc = _round_const(i, s12)
    return _rotl12(t, rot) ^ rc


def _c_encrypt(x: int, s: int, rounds: int = 16) -> int:
    """Encrypt one 24-bit block with the 16-round Feistel core C_s."""
    l, r = _split24(x)
    for i in range(rounds):
        l, r = r, (l ^ _f_s(r, i, s)) & MASK12
    return _join24(l, r)


def _c_decrypt(x: int, s: int, rounds: int = 16) -> int:
    """Inverse of _c_encrypt, processing Feistel rounds in reverse order."""
    l, r = _split24(x)
    for i in reversed(range(rounds)):
        l, r = (r ^ _f_s(l, i, s)) & MASK12, l
    return _join24(l, r)


def _xorshift64(state: int) -> int:
    """Small PRNG used only for matrix construction from the key"""
    state &= (1 << 64) - 1
    state ^= (state << 13) & MASK64
    state ^= (state >> 7) & MASK64
    state ^= (state << 17) & MASK64
    return state & MASK64


def _build_m_rows_from_seed(seed56: int) -> list[int]:
    """Build an invertible 24x24 binary matrix from a 56-bit seed.

    Construction starts from identity and applies seed-driven row XOR updates.
    Row operations preserve invertibility, so decryption can always compute M^-1.
    """
    seed56 &= (1 << 56) - 1
    state = seed56 | (1 << 63) # Set high bit to avoid weak seed
    rows = [(1 << i) for i in range(24)]

    for t in range(56):
        # Here we golden ratio hash with 0x9E3779B97F4A7C15
        state = _xorshift64(state ^ (t * 0x9E3779B97F4A7C15 & MASK64))
        a = (state & 0x1F) % 24
        b = ((state >> 5) & 0x1F) % 24
        if a != b:
            rows[a] ^= rows[b]
            rows[a] &= MASK24

    return rows


def _mat_mul_rows(rows: list[int], x: int) -> int:
    """Compute y = M*x over GF(2), where rows encodes a 24x24 binary matrix."""
    x &= MASK24
    y = 0
    for i, rowmask in enumerate(rows):
        v = rowmask & x
        parity = v.bit_count() & 1
        y |= parity << i
    return y & MASK24


def _mat_inv_rows(rows: list[int]) -> list[int]:
    """Invert a 24x24 binary matrix with Gauss-Jordan elimination over GF(2)."""
    a = [rows[i] & MASK24 for i in range(24)]
    inv = [(1 << i) for i in range(24)]

    for col in range(24):
        pivot = None
        for r in range(col, 24):
            if (a[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            raise ValueError("Matrix not invertible.")

        if pivot != col:
            a[col], a[pivot] = a[pivot], a[col]
            inv[col], inv[pivot] = inv[pivot], inv[col]

        for r in range(24):
            if r != col and ((a[r] >> col) & 1):
                a[r] ^= a[col]
                inv[r] ^= inv[col]
                a[r] &= MASK24
                inv[r] &= MASK24

    return [inv[i] & MASK24 for i in range(24)]


class TokenCrypt:
    """Stateful cipher context derived from a single 96-bit key.

    Key layout (MSB -> LSB):
        s(16) || seed56(56) || b24(24)

        This key schedule powers an ultra-hardened design with aggressive
        diffusion and repeated round layering.
    """

    def __init__(self, key96: int):
        self._key96 = key96 & ((1 << 96) - 1)
        self._s, self._seed56, self._b24 = self._parse_key96(self._key96)
        self._m_rows = _build_m_rows_from_seed(self._seed56)
        self._minv_rows = _mat_inv_rows(self._m_rows)

    @staticmethod
    def _parse_key96(key96: int) -> tuple[int, int, int]:
        """Split a 96-bit key into Feistel key, matrix seed, and affine offset."""
        key96 &= (1 << 96) - 1
        b24 = key96 & MASK24
        seed56 = (key96 >> 24) & ((1 << 56) - 1)
        s = (key96 >> 80) & 0xFFFF
        return s, seed56, b24

    @staticmethod
    def _validate_rounds(rounds: int) -> None:
        """Validate caller rounds parameter.

        rounds is a total-round count, not a chunk count.
        """
        if not isinstance(rounds, int):
            raise TypeError("rounds must be an int")
        if rounds < 16 or rounds > 1024:
            raise ValueError("rounds must be in [16, 1024]")
        if rounds % 16 != 0:
            raise ValueError("rounds must be a multiple of 16")

    def _affine_apply(self, x: int) -> int:
        """Apply affine layer A(x) = M*x XOR b."""
        return (_mat_mul_rows(self._m_rows, x) ^ self._b24) & MASK24

    def _affine_apply_inv(self, y: int) -> int:
        """Apply inverse affine layer A^-1(y) = M^-1*(y XOR b)."""
        return _mat_mul_rows(self._minv_rows, (y ^ self._b24) & MASK24) & MASK24

    def _chunk_encrypt(self, x: int) -> int:
        """16-round Feistel chunk, then affine layer."""
        z = _c_encrypt(x, self._s, rounds=16)
        return self._affine_apply(z)

    def _chunk_decrypt(self, y: int) -> int:
        """Inverse of 16-round chunk"""
        z = self._affine_apply_inv(y)
        return _c_decrypt(z, self._s, rounds=16) & MASK24

    def encrypt(self, plaintext: int, rounds: int = 128) -> int:
        """Encrypt one 24-bit block using total round count requested by caller."""
        self._validate_rounds(rounds)
        x = plaintext & MASK24
        chunks = rounds // 16
        for c in range(chunks):
            x = self._chunk_encrypt(x ^ c)
        return x

    def decrypt(self, ciphertext: int, rounds: int = 128) -> int:
        """Decrypt one 24-bit block using total round count requested by caller."""
        self._validate_rounds(rounds)
        y = ciphertext & MASK24
        chunks = rounds // 16
        for c in reversed(range(chunks)):
            y = self._chunk_decrypt(y) ^ c
        return y


_ACTIVE: TokenCrypt | None = None


def key(key96: int | None = None) -> TokenCrypt:
    """Initialize and store the active cipher.

    If key96 is omitted, a random 96-bit key is read from os.urandom.
    """
    global _ACTIVE
    if key96 is None:
        key96 = int.from_bytes(os.urandom(12), byteorder="big")
    elif not isinstance(key96, int):
        raise TypeError("key96 must be an int")
    elif key96 < 0 or key96 >= (1 << 96):
        raise ValueError("key96 must be a 96-bit integer in [0, 2^96)")
    _ACTIVE = TokenCrypt(key96)
    return _ACTIVE


def encrypt(plaintext: int, rounds: int = 128) -> int:
    """Encrypt with the active cipher context created by key()."""
    if _ACTIVE is None:
        raise RuntimeError("Cipher not initialized. Call key(key96) first.")
    return _ACTIVE.encrypt(plaintext, rounds=rounds)


def decrypt(ciphertext: int, rounds: int = 128) -> int:
    """Decrypt with the active cipher context created by key()."""
    if _ACTIVE is None:
        raise RuntimeError("Cipher not initialized. Call key(key96) first.")
    return _ACTIVE.decrypt(ciphertext, rounds=rounds)


def test(rounds: int = 128) -> bool:
    """Self-test current key context by round-tripping values 0..9."""
    if _ACTIVE is None:
        raise RuntimeError("Cipher not initialized. Call key(key96) first.")
    for value in range(10):
        ct = encrypt(value, rounds=rounds)
        rt = decrypt(ct, rounds=rounds)
        if rt != value:
            raise AssertionError(
                f"self-test failed at value={value}: decrypt(encrypt(value))={rt}"
            )
    return True


__all__ = ["key", "encrypt", "decrypt", "test"]
