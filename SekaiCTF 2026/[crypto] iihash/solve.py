#!/usr/bin/env python3
"""
SEKAI CTF 2026 - Iihash solver

Attack outline:
  1. Query a chosen-message XXH3-128 collision family twice. One family
     leaks the seed's low half; the other leaks the high half.
  2. Recover the 64-bit XXH3 seed from the two collision equations.
  3. Construct a 320-byte preimage whose digest is exactly
     b"Give me the flag", then submit it.

Dependencies:
    python3 -m pip install xxhash fpylll cysignals
"""
from __future__ import annotations

import argparse
import base64
import gc
import hashlib
import itertools
import math
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Sequence

try:
    import xxhash
except ImportError as exc:
    raise SystemExit(
        "missing dependency: xxhash\n"
        "install with: python3 -m pip install xxhash fpylll cysignals"
    ) from exc

try:
    from fpylll import BKZ, LLL, IntegerMatrix
except ImportError as exc:
    raise SystemExit(
        "missing dependency: fpylll\n"
        "install with: python3 -m pip install xxhash fpylll cysignals"
    ) from exc


HOST = "iihash.chals.sekai.team"
PORT = 1337
MASK64 = (1 << 64) - 1
B32 = 1 << 32

P32_1 = 0x9E3779B1
P32_2 = 0x85EBCA77
P32_3 = 0xC2B2AE3D
P64_1 = 0x9E3779B185EBCA87
P64_2 = 0xC2B2AE3D27D4EB4F
P64_3 = 0x165667B19E3779F9
P64_4 = 0x85EBCA77C2B2AE63
P64_5 = 0x27D4EB2F165667C5
PMX1 = 0x165667919E3779F9

TARGET_DIGEST = b"Give me the flag"
# Inverse XXH3 avalanche of the low/high halves of TARGET_DIGEST.
TARGET_PRE_LO = 0x26D73906E5B3B9F7
TARGET_PRE_HI = 0x00B0C1155830D0A5

# XXH3_kSecret from xxHash 0.8.x.
KSECRET = bytes(
    [
        0xB8, 0xFE, 0x6C, 0x39, 0x23, 0xA4, 0x4B, 0xBE,
        0x7C, 0x01, 0x81, 0x2C, 0xF7, 0x21, 0xAD, 0x1C,
        0xDE, 0xD4, 0x6D, 0xE9, 0x83, 0x90, 0x97, 0xDB,
        0x72, 0x40, 0xA4, 0xA4, 0xB7, 0xB3, 0x67, 0x1F,
        0xCB, 0x79, 0xE6, 0x4E, 0xCC, 0xC0, 0xE5, 0x78,
        0x82, 0x5A, 0xD0, 0x7D, 0xCC, 0xFF, 0x72, 0x21,
        0xB8, 0x08, 0x46, 0x74, 0xF7, 0x43, 0x24, 0x8E,
        0xE0, 0x35, 0x90, 0xE6, 0x81, 0x3A, 0x26, 0x4C,
        0x3C, 0x28, 0x52, 0xBB, 0x91, 0xC3, 0x00, 0xCB,
        0x88, 0xD0, 0x65, 0x8B, 0x1B, 0x53, 0x2E, 0xA3,
        0x71, 0x64, 0x48, 0x97, 0xA2, 0x0D, 0xF9, 0x4E,
        0x38, 0x19, 0xEF, 0x46, 0xA9, 0xDE, 0xAC, 0xD8,
        0xA8, 0xFA, 0x76, 0x3F, 0xE3, 0x9C, 0x34, 0x3F,
        0xF9, 0xDC, 0xBB, 0xC7, 0xC7, 0x0B, 0x4F, 0x1D,
        0x8A, 0x51, 0xE0, 0x4B, 0xCD, 0xB4, 0x59, 0x31,
        0xC8, 0x9F, 0x7E, 0xC9, 0xD9, 0x78, 0x73, 0x64,
        0xEA, 0xC5, 0xAC, 0x83, 0x34, 0xD3, 0xEB, 0xC3,
        0xC5, 0x81, 0xA0, 0xFF, 0xFA, 0x13, 0x63, 0xEB,
        0x17, 0x0D, 0xDD, 0x51, 0xB7, 0xF0, 0xDA, 0x49,
        0xD3, 0x16, 0x55, 0x26, 0x29, 0xD4, 0x68, 0x9E,
        0x2B, 0x16, 0xBE, 0x58, 0x7D, 0x47, 0xA1, 0xFC,
        0x8F, 0xF8, 0xB8, 0xD1, 0x7A, 0xD0, 0x31, 0xCE,
        0x45, 0xCB, 0x3A, 0x8F, 0x95, 0x16, 0x04, 0x28,
        0xAF, 0xD7, 0xFB, 0xCA, 0xBB, 0x4B, 0x40, 0x7E,
    ]
)

# A 1024-byte message has 15 ordinary stripes and one separate final stripe.
# q=7..14 appears once in every accumulator lane among those 15 stripes.
COLLISION_QS = tuple(range(7, 15))
COLLISION_B = 4
COLLISION_LEN = 1024
COLLISION_DOMAIN_BITS = len(COLLISION_QS) * COLLISION_B  # 32
COLLISION_SIGNS = tuple(1 if q % 2 == 0 else -1 for q in COLLISION_QS)
COLLISION_KWORDS = tuple(
    int.from_bytes(KSECRET[8 * q : 8 * q + 8], "little")
    for q in COLLISION_QS
)
ZERO_WORD_HEX = "0000000000000000"
COLLISION_LAYOUT = tuple(
    (j + lane - COLLISION_QS[0])
    if COLLISION_QS[0] <= j + lane <= COLLISION_QS[-1]
    else -1
    for j in range(16)
    for lane in range(8)
)

HASH_RE = re.compile(rb"\[\+\] Hash: ([0-9a-fA-F]{32})")
FLAG_RE = re.compile(rb"SEKAI\{[^\r\n}]*\}")
POW_RE = re.compile(
    rb"curl\s+-sSfL\s+https://pwn\.red/pow\s*\|\s*sh\s+-s\s+([^\r\n ]+)"
)


def u64(data: bytes, offset: int = 0) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def custom_secret(seed: int) -> bytes:
    out = bytearray(192)
    for off in range(0, 192, 16):
        left = (u64(KSECRET, off) + seed) & MASK64
        right = (u64(KSECRET, off + 8) - seed) & MASK64
        out[off : off + 8] = left.to_bytes(8, "little")
        out[off + 8 : off + 16] = right.to_bytes(8, "little")
    return bytes(out)


def fold_mul(a: int, b: int) -> int:
    product = a * b
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def splitmix64(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return (value ^ (value >> 31)) & MASK64


def permute32(counter: int, key: int) -> int:
    """A small Feistel permutation: unique, but less structured than counter order."""
    left = (counter >> 16) & 0xFFFF
    right = counter & 0xFFFF
    for rnd in range(6):
        f = splitmix64(right ^ key ^ (rnd * 0x9E3779B97F4A7C15)) & 0xFFFF
        left, right = right, (left ^ f) & 0xFFFF
    return (left << 16) | right


def decode_assignment(value: int, b: int = COLLISION_B) -> tuple[int, ...]:
    mask = (1 << b) - 1
    return tuple((value >> (b * i)) & mask for i in range(len(COLLISION_QS)))


def collision_message_hex(assignment: Sequence[int], mode: str, b: int = 4) -> str:
    shift = (32 - b) if mode == "low" else (64 - b)
    word_hex = [
        ((t << shift) & MASK64).to_bytes(8, "little").hex()
        for t in range(1 << b)
    ]
    return "".join(
        ZERO_WORD_HEX if index < 0 else word_hex[assignment[index]]
        for index in COLLISION_LAYOUT
    )


def family_tables(seed: int, b: int, mode: str) -> list[list[int]]:
    shift = (32 - b) if mode == "low" else (64 - b)
    secret = custom_secret(seed)
    result: list[list[int]] = []
    for q in COLLISION_QS:
        word = u64(secret, 8 * q)
        base = (word & 0xFFFFFFFF) * (word >> 32)
        row = []
        for t in range(1 << b):
            data = t << shift
            mixed = word ^ data
            delta = (
                (mixed & 0xFFFFFFFF) * (mixed >> 32) + data - base
            ) & MASK64
            row.append(delta)
        result.append(row)
    return result


def collision_equation_holds(
    seed: int,
    b: int,
    mode: str,
    left: Sequence[int],
    right: Sequence[int],
) -> bool:
    tables = family_tables(seed, b, mode)
    gl = sum(table[t] for table, t in zip(tables, left)) & MASK64
    gr = sum(table[t] for table, t in zip(tables, right)) & MASK64
    return gl == gr


# ---------------------------------------------------------------------------
# Seed recovery from one high-half family collision and one low-half collision
# ---------------------------------------------------------------------------


def cfun(nibble: int, value: int) -> int:
    return (nibble ^ value) - nibble


def carry_intervals() -> list[tuple[int, int]]:
    boundaries = {0, B32}
    for word, sign in zip(COLLISION_KWORDS, COLLISION_SIGNS):
        low = word & 0xFFFFFFFF
        point = B32 - low if sign == 1 else low + 1
        if 0 < point < B32:
            boundaries.add(point)
    ordered = sorted(boundaries)
    return list(zip(ordered, ordered[1:]))


def high_bases_for_low(low_seed: int) -> list[int]:
    result = []
    for word, sign in zip(COLLISION_KWORDS, COLLISION_SIGNS):
        low = word & 0xFFFFFFFF
        high = word >> 32
        if sign == 1:
            result.append((high + int(low + low_seed >= B32)) & 0xFFFFFFFF)
        else:
            result.append((high - int(low < low_seed)) & 0xFFFFFFFF)
    return result


def high_intervals(low_seed: int, b: int) -> list[tuple[int, int]]:
    """Intervals where every high secret word and its top b bits are affine."""
    step = 1 << (32 - b)
    boundaries = {0, B32}
    for base, sign in zip(high_bases_for_low(low_seed), COLLISION_SIGNS):
        for k in range(1 << b):
            if sign == 1:
                point = (k * step - base) % B32
            else:
                point = (base - k * step + 1) % B32
            if 0 < point < B32:
                boundaries.add(point)
    ordered = sorted(boundaries)
    return list(zip(ordered, ordered[1:]))


def secret_word_parts(low_seed: int, high_seed: int) -> list[tuple[int, int]]:
    seed = (high_seed << 32) | low_seed
    result = []
    for word, sign in zip(COLLISION_KWORDS, COLLISION_SIGNS):
        value = (word + sign * seed) & MASK64
        result.append((value & 0xFFFFFFFF, value >> 32))
    return result


def affine_low_words(low_representative: int) -> list[tuple[int, int]]:
    result = []
    for word, sign in zip(COLLISION_KWORDS, COLLISION_SIGNS):
        value = ((word & 0xFFFFFFFF) + sign * low_representative) % B32
        result.append((sign, value - sign * low_representative))
    return result


def affine_high_words(
    low_seed: int, high_representative: int
) -> list[tuple[int, int]]:
    result = []
    for base, sign in zip(high_bases_for_low(low_seed), COLLISION_SIGNS):
        value = (base + sign * high_representative) % B32
        result.append((sign, value - sign * high_representative))
    return result


def solve_linear_mod_interval(
    coefficient: int,
    constant: int,
    modulus: int,
    lower: int,
    upper: int,
) -> list[int] | None:
    """Solve coefficient*x + constant == 0 mod modulus in [lower, upper)."""
    coefficient %= modulus
    rhs = (-constant) % modulus
    if coefficient == 0:
        return None if rhs == 0 else []
    divisor = math.gcd(coefficient, modulus)
    if rhs % divisor:
        return []
    reduced_modulus = modulus // divisor
    root = (
        pow(coefficient // divisor, -1, reduced_modulus)
        * (rhs // divisor)
    ) % reduced_modulus
    first = (lower - root + reduced_modulus - 1) // reduced_modulus
    last = (upper - 1 - root) // reduced_modulus
    if last < first:
        return []
    return [root + k * reduced_modulus for k in range(first, last + 1)]


def collision_coefficients(
    left: Sequence[int], right: Sequence[int], nibbles: Sequence[int]
) -> list[int]:
    return [
        cfun(nibble, a) - cfun(nibble, b)
        for nibble, a, b in zip(nibbles, left, right)
    ]


def recover_seed_candidates(
    high_collision: tuple[Sequence[int], Sequence[int]],
    low_collision: tuple[Sequence[int], Sequence[int]],
    b_high: int = COLLISION_B,
    b_low: int = COLLISION_B,
) -> list[int]:
    high_left, high_right = high_collision
    low_left, low_right = low_collision
    q_high = 1 << (32 + b_high)
    q_low = 1 << (32 + b_low)
    shift_high = 32 - b_high
    shift_low = 32 - b_low

    stage: list[tuple[int, int, int]] = []
    for low_lo, low_hi in carry_intervals():
        for high_lo, high_hi in high_intervals(low_lo, b_high):
            parts = secret_word_parts(low_lo, high_lo)
            high_nibbles = [high >> shift_high for _, high in parts]
            coefficients = collision_coefficients(
                high_left, high_right, high_nibbles
            )
            affine = affine_low_words(low_lo)
            a_value = sum(
                coefficient * sign
                for coefficient, (sign, _) in zip(coefficients, affine)
            )
            b_value = sum(
                coefficient * base
                for coefficient, (_, base) in zip(coefficients, affine)
            )
            b_value += sum(
                a - b for a, b in zip(high_left, high_right)
            ) * (1 << 32)
            solutions = solve_linear_mod_interval(
                a_value, b_value, q_high, low_lo, low_hi
            )
            if solutions:
                stage.extend((low_seed, high_lo, high_hi) for low_seed in solutions)

    candidates: list[int] = []
    for low_seed, high_lo, high_hi in stage:
        parts = secret_word_parts(low_seed, high_lo)
        low_nibbles = [low >> shift_low for low, _ in parts]
        coefficients = collision_coefficients(low_left, low_right, low_nibbles)
        affine = affine_high_words(low_seed, high_lo)
        a_value = sum(
            coefficient * sign
            for coefficient, (sign, _) in zip(coefficients, affine)
        )
        b_value = sum(
            coefficient * base
            for coefficient, (_, base) in zip(coefficients, affine)
        )
        b_value += sum(a - b for a, b in zip(low_left, low_right))
        solutions = solve_linear_mod_interval(
            a_value, b_value, q_low, high_lo, high_hi
        )
        if not solutions:
            continue
        for high_seed in solutions:
            seed = (high_seed << 32) | low_seed
            if collision_equation_holds(
                seed, b_high, "high", high_left, high_right
            ) and collision_equation_holds(
                seed, b_low, "low", low_left, low_right
            ):
                candidates.append(seed)
    return sorted(set(candidates))


# ---------------------------------------------------------------------------
# Folded-multiplication inversion and target preimage construction
# ---------------------------------------------------------------------------


def invert_fold_mul(constant: int, target: int, block_size: int = 25) -> list[int]:
    """
    Invert fold_mul(constant, x) with a modular-subset-sum lattice.

    If q=floor(constant*x/2^64), then
        constant*x = q*2^64 + (target xor q).
    Expanding target xor q turns divisibility by constant into a 64-variable
    modular subset sum. The short vector has 64 coordinates in {-1,+1}.
    """
    constant &= MASK64
    target &= MASK64
    if constant == 0:
        return [0] if target == 0 else []

    modulus = constant
    coefficients = []
    for bit in range(64):
        target_bit = (target >> bit) & 1
        coefficient = (
            pow(2, bit, modulus)
            * ((1 << 64) + 1 - 2 * target_bit)
        ) % modulus
        coefficients.append(coefficient)
    rhs = (-target) % modulus

    dimension = 66
    basis = IntegerMatrix(dimension, dimension)
    for row in range(64):
        basis[row, row] = 2
        basis[row, 65] = coefficients[row]
    for column in range(64):
        basis[64, column] = 1
    basis[64, 64] = 1
    basis[64, 65] = rhs
    basis[65, 65] = modulus

    LLL.reduction(basis, delta=0.99)
    BKZ.reduction(basis, BKZ.Param(block_size=block_size, max_loops=4))

    solutions = []
    for row in range(dimension):
        vector = [int(basis[row, column]) for column in range(dimension)]
        for sign in (1, -1):
            bits = [sign * vector[index] for index in range(64)]
            extra = sign * vector[64]
            final = sign * vector[65]
            if final != 0 or extra != -1 or any(v not in (-1, 1) for v in bits):
                continue
            quotient = sum(((bits[index] + 1) // 2) << index for index in range(64))
            if quotient >= constant:
                continue
            numerator = quotient * (1 << 64) + (target ^ quotient)
            if numerator % constant:
                continue
            value = numerator // constant
            if value < (1 << 64) and fold_mul(constant, value) == target:
                solutions.append(value)
    return sorted(set(solutions))


def solve_fold_sum(
    constant0: int,
    constant1: int,
    target: int,
    rng: random.Random,
    max_attempts: int = 250,
) -> tuple[int, int, int] | None:
    for attempt in range(1, max_attempts + 1):
        left = rng.getrandbits(64)
        right_target = (target - fold_mul(constant0, left)) & MASK64
        right_solutions = invert_fold_mul(constant1, right_target, block_size=25)
        if right_solutions:
            right = right_solutions[0]
            assert (
                fold_mul(constant0, left) + fold_mul(constant1, right)
            ) & MASK64 == target
            return left, right, attempt
    return None


def construct_target_accumulators(seed: int) -> list[int]:
    secret = custom_secret(seed)
    low_a = [u64(secret, 11 + 16 * i) for i in range(4)]
    low_b = [u64(secret, 19 + 16 * i) for i in range(4)]
    high_a = [u64(secret, 117 + 16 * i) for i in range(4)]
    high_b = [u64(secret, 125 + 16 * i) for i in range(4)]
    delta_a = [a ^ b for a, b in zip(low_a, high_a)]
    delta_b = [a ^ b for a, b in zip(low_b, high_b)]

    low_target = (TARGET_PRE_LO - 320 * P64_1) & MASK64
    high_start = (~((320 * P64_2) & MASK64)) & MASK64
    high_target = (TARGET_PRE_HI - high_start) & MASK64
    rng = random.Random(seed ^ 0x4949484153482026)

    # Try every partition of the four accumulator pairs. Two pairs contribute
    # only to the low merge and the other two only to the high merge.
    for low_indices in itertools.combinations(range(4), 2):
        low_set = set(low_indices)
        high_indices = tuple(i for i in range(4) if i not in low_set)

        # For each controlled pair, zero either the first or second factor of
        # the unwanted merge. This gives two possible constants (delta_a/b).
        for low_options in itertools.product(("a", "b"), repeat=2):
            low_constants = [
                delta_a[index] if option == "a" else delta_b[index]
                for index, option in zip(low_indices, low_options)
            ]
            low_solution = solve_fold_sum(
                low_constants[0], low_constants[1], low_target, rng
            )
            if low_solution is None:
                continue

            for high_options in itertools.product(("a", "b"), repeat=2):
                high_constants = [
                    delta_a[index] if option == "a" else delta_b[index]
                    for index, option in zip(high_indices, high_options)
                ]
                high_solution = solve_fold_sum(
                    high_constants[0], high_constants[1], high_target, rng
                )
                if high_solution is None:
                    continue

                accumulators = [0] * 8
                for index, option, value in zip(
                    low_indices, low_options, low_solution[:2]
                ):
                    if option == "a":
                        # high first factor = 0; low = fold(delta_a, value)
                        accumulators[2 * index] = high_a[index]
                        accumulators[2 * index + 1] = low_b[index] ^ value
                    else:
                        # high second factor = 0; low = fold(value, delta_b)
                        accumulators[2 * index] = low_a[index] ^ value
                        accumulators[2 * index + 1] = high_b[index]

                for index, option, value in zip(
                    high_indices, high_options, high_solution[:2]
                ):
                    if option == "a":
                        # low first factor = 0; high = fold(delta_a, value)
                        accumulators[2 * index] = low_a[index]
                        accumulators[2 * index + 1] = high_b[index] ^ value
                    else:
                        # low second factor = 0; high = fold(value, delta_b)
                        accumulators[2 * index] = high_a[index] ^ value
                        accumulators[2 * index + 1] = low_b[index]

                # Exact local check of the two pre-avalanche merge values.
                merged_low = (320 * P64_1) & MASK64
                merged_high = high_start
                for i in range(4):
                    merged_low = (
                        merged_low
                        + fold_mul(
                            accumulators[2 * i] ^ low_a[i],
                            accumulators[2 * i + 1] ^ low_b[i],
                        )
                    ) & MASK64
                    merged_high = (
                        merged_high
                        + fold_mul(
                            accumulators[2 * i] ^ high_a[i],
                            accumulators[2 * i + 1] ^ high_b[i],
                        )
                    ) & MASK64
                if merged_low == TARGET_PRE_LO and merged_high == TARGET_PRE_HI:
                    print(
                        "[+] Fold sums solved "
                        f"(low attempts={low_solution[2]}, high attempts={high_solution[2]})"
                    )
                    return accumulators
    raise RuntimeError("failed to construct target accumulator state")


def construct_preimage(seed: int, target_accumulators: Sequence[int]) -> bytes:
    """
    Realize any requested 8-word accumulator state with a 320-byte message.

    Every selected data word differs from its stripe secret in only one 32-bit
    half, so low32(diff)*high32(diff)=0. Accumulation then reduces to direct
    additions into the partner lane. Two variable words plus three fixed words
    can realize an arbitrary 64-bit sum, including the carry between halves.
    """
    secret = custom_secret(seed)
    initial = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1]
    payload = bytearray(320)

    for source_lane in range(8):
        secret_words = [
            u64(secret, stripe * 8 + source_lane * 8)
            for stripe in range(4)
        ]
        secret_words.append(u64(secret, 121 + source_lane * 8))

        destination_lane = source_lane ^ 1
        required_sum = (
            target_accumulators[destination_lane] - initial[destination_lane]
        ) & MASK64
        fixed_sum = sum(secret_words[2:]) & MASK64
        residual = (required_sum - fixed_sum) & MASK64

        high0 = secret_words[0] >> 32
        low1 = secret_words[1] & 0xFFFFFFFF
        variable_low = ((residual & 0xFFFFFFFF) - low1) & 0xFFFFFFFF
        carry = int(variable_low + low1 >= B32)
        variable_high = ((residual >> 32) - high0 - carry) & 0xFFFFFFFF

        data_words = [
            (high0 << 32) | variable_low,
            (variable_high << 32) | low1,
            secret_words[2],
            secret_words[3],
            secret_words[4],
        ]
        assert sum(data_words) & MASK64 == required_sum
        for data_word, secret_word in zip(data_words, secret_words):
            difference = data_word ^ secret_word
            assert (difference & 0xFFFFFFFF) * (difference >> 32) == 0

        for stripe in range(4):
            offset = stripe * 64 + source_lane * 8
            payload[offset : offset + 8] = data_words[stripe].to_bytes(8, "little")
        offset = 256 + source_lane * 8
        payload[offset : offset + 8] = data_words[4].to_bytes(8, "little")

    result = bytes(payload)
    digest = xxhash.xxh3_128(result, seed=seed).digest()
    if digest != TARGET_DIGEST:
        raise RuntimeError(
            f"local preimage verification failed: got {digest.hex()}, "
            f"expected {TARGET_DIGEST.hex()}"
        )
    return result


# ---------------------------------------------------------------------------
# Network / proof-of-work
# ---------------------------------------------------------------------------


def cached_pow_candidates() -> list[Path]:
    home = Path.home()
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    names = [
        "redpwnpow-v0.1.2-linux-amd64",
        "redpwnpow-v0.1.2-linux-arm64",
        "redpwnpow-v0.1.2-linux-armv6l",
    ]
    candidates = [cache_root / "redpwnpow" / name for name in names]
    found = shutil.which("redpwnpow")
    if found:
        candidates.append(Path(found))
    return candidates


def find_pow_solver() -> Path | None:
    for candidate in cached_pow_candidates():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def prepare_pow_solver() -> Path:
    solver = find_pow_solver()
    if solver is not None:
        print(f"[*] Using cached PoW solver: {solver}")
        return solver

    print("[*] Caching pwn.red PoW solver before opening the timed connection")
    bootstrap = "s.AAAAAA==.AQ=="
    command = (
        "set -o pipefail; "
        "curl --connect-timeout 10 --max-time 45 -sSfL https://pwn.red/pow "
        f"| sh -s {bootstrap}"
    )
    subprocess.run(
        ["bash", "-lc", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=True,
    )
    solver = find_pow_solver()
    if solver is None:
        raise RuntimeError("pwn.red helper ran, but no cached solver was found")
    print(f"[+] Cached PoW solver: {solver}")
    return solver


class Remote:
    def __init__(self, host: str, port: int, timeout: float = 120.0):
        self.sock = socket.create_connection((host, port), timeout=20.0)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_more(self) -> bytes:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("remote closed the connection")
        self.buffer.extend(chunk)
        return chunk

    def recv_until(self, marker: bytes, limit: int = 4_000_000) -> bytes:
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            if len(self.buffer) > limit:
                raise RuntimeError(f"receive buffer exceeded {limit} bytes")
            self.recv_more()

    def recv_hashes(self, count: int) -> list[bytes]:
        hashes: list[bytes] = []
        while len(hashes) < count:
            while True:
                match = HASH_RE.search(self.buffer)
                if match is None:
                    break
                hashes.append(bytes.fromhex(match.group(1).decode("ascii")))
                del self.buffer[: match.end()]
                if len(hashes) == count:
                    return hashes
            self.recv_more()
        return hashes

    def recv_to_end_or_flag(self, timeout: float = 30.0) -> bytes:
        self.sock.settimeout(timeout)
        result = bytearray(self.buffer)
        self.buffer.clear()
        while True:
            flag = FLAG_RE.search(result)
            if flag:
                return bytes(result)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return bytes(result)
            if not chunk:
                return bytes(result)
            result.extend(chunk)


def solve_pow(remote: Remote, solver: Path) -> None:
    banner = remote.recv_until(b"solution: ")
    match = POW_RE.search(banner)
    if not match:
        text = banner.decode(errors="replace")
        raise RuntimeError(f"could not parse PoW command:\n{text}")
    challenge = match.group(1).decode("ascii")
    print(f"[*] PoW challenge: {challenge}")
    started = time.monotonic()
    proc = subprocess.run(
        [str(solver), challenge],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )
    solutions = [
        line.strip()
        for line in proc.stdout.splitlines()
        if re.fullmatch(r"s\.[A-Za-z0-9+/=]+", line.strip())
    ]
    if proc.returncode != 0 or not solutions:
        raise RuntimeError(
            f"PoW solver failed rc={proc.returncode}; "
            f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
        )
    solution = solutions[-1]
    remote.send(solution.encode("ascii") + b"\n")
    print(f"[+] PoW solved in {time.monotonic() - started:.2f}s")
    # Consume the first menu prompt. It is safe if extra menu text remains.
    remote.recv_until(b"> ")


def query_one_hash(remote: Remote, payload: bytes) -> bytes:
    remote.send(b"1\n" + payload.hex().encode("ascii") + b"\n")
    return remote.recv_hashes(1)[0]


def find_remote_collision(
    remote: Remote,
    mode: str,
    max_queries: int,
    batch_size: int,
    permutation_key: int,
) -> tuple[tuple[int, ...], tuple[int, ...], int]:
    print(
        f"[*] Searching {mode}-half collision "
        f"(b={COLLISION_B}, max={max_queries:,}, batch={batch_size})"
    )
    seen: dict[bytes, int] = {}
    start = time.monotonic()
    processed = 0

    while processed < max_queries:
        amount = min(batch_size, max_queries - processed)
        assignments: list[int] = []
        commands: list[str] = []
        for offset in range(amount):
            value = permute32(processed + offset, permutation_key)
            assignment = decode_assignment(value)
            assignments.append(value)
            commands.append("1\n")
            commands.append(collision_message_hex(assignment, mode))
            commands.append("\n")

        remote.send("".join(commands).encode("ascii"))
        digests = remote.recv_hashes(amount)

        collision = None
        for digest, value in zip(digests, assignments):
            previous = seen.get(digest)
            if previous is not None and previous != value and collision is None:
                collision = (decode_assignment(previous), decode_assignment(value))
            else:
                seen[digest] = value

        processed += amount
        if collision is not None:
            elapsed = time.monotonic() - start
            print(
                f"[+] {mode}-half collision after {processed:,} queries "
                f"({processed / max(elapsed, 1e-9):,.0f} q/s)"
            )
            del seen
            gc.collect()
            return collision[0], collision[1], processed

        if processed % max(10_000, batch_size * 32) == 0:
            elapsed = time.monotonic() - start
            print(
                f"    {mode}: {processed:,}/{max_queries:,} "
                f"({processed / max(elapsed, 1e-9):,.0f} q/s)",
                flush=True,
            )

    del seen
    gc.collect()
    raise RuntimeError(
        f"no {mode}-half collision found after {max_queries:,} queries; "
        "retry with a fresh connection or increase --max-queries"
    )


# ---------------------------------------------------------------------------
# End-to-end solve / self-test
# ---------------------------------------------------------------------------


def find_offline_collision(
    seed: int, mode: str, max_queries: int, permutation_key: int
) -> tuple[tuple[int, ...], tuple[int, ...], int]:
    tables = family_tables(seed, COLLISION_B, mode)
    seen: dict[int, int] = {}
    for counter in range(max_queries):
        value = permute32(counter, permutation_key)
        cursor = value
        total = 0
        for table in tables:
            t = cursor & 0xF
            cursor >>= 4
            total = (total + table[t]) & MASK64
        previous = seen.get(total)
        if previous is not None and previous != value:
            return decode_assignment(previous), decode_assignment(value), counter + 1
        seen[total] = value
    raise RuntimeError(f"offline {mode} collision not found")


def self_test() -> None:
    seed = 0x123456789ABCDEF0
    print(f"[*] Self-test seed: {seed:#018x}")
    high = find_offline_collision(seed, "high", 1_200_000, 0x48494748)
    low = find_offline_collision(seed, "low", 1_200_000, 0x4C4F5721)
    print(f"[+] Offline collisions: high={high[2]:,}, low={low[2]:,}")
    candidates = recover_seed_candidates(high[:2], low[:2])
    if seed not in candidates:
        raise RuntimeError(
            f"seed recovery self-test failed: got {[hex(x) for x in candidates]}"
        )
    print(f"[+] Seed recovery self-test passed ({len(candidates)} candidate(s))")
    accumulators = construct_target_accumulators(seed)
    payload = construct_preimage(seed, accumulators)
    assert len(payload) == 320
    assert xxhash.xxh3_128(payload, seed=seed).digest() == TARGET_DIGEST
    print("[+] Preimage self-test passed")


def run_live(args: argparse.Namespace) -> None:
    pow_solver = None if args.no_pow else prepare_pow_solver()
    remote = Remote(args.host, args.port, timeout=args.socket_timeout)
    try:
        print(f"[*] Connected to {args.host}:{args.port}")
        if pow_solver is not None:
            solve_pow(remote, pow_solver)
        else:
            remote.recv_until(b"> ")

        rng = random.SystemRandom()
        high_collision = find_remote_collision(
            remote,
            "high",
            args.max_queries,
            args.batch_size,
            rng.getrandbits(64),
        )
        low_collision = find_remote_collision(
            remote,
            "low",
            args.max_queries,
            args.batch_size,
            rng.getrandbits(64),
        )

        print("[*] Recovering the 64-bit seed from collision equations")
        candidates = recover_seed_candidates(high_collision[:2], low_collision[:2])
        if not candidates:
            raise RuntimeError("collision equations produced no seed candidate")
        print(
            "[+] Algebraic seed candidates: "
            + ", ".join(f"{candidate:#018x}" for candidate in candidates)
        )

        probe = b"\x00" * 320
        remote_probe = query_one_hash(remote, probe)
        candidates = [
            candidate
            for candidate in candidates
            if xxhash.xxh3_128(probe, seed=candidate).digest() == remote_probe
        ]
        if len(candidates) != 1:
            raise RuntimeError(
                f"probe did not isolate one seed; remaining: "
                f"{[hex(x) for x in candidates]}"
            )
        seed = candidates[0]
        print(f"[+] Recovered seed: {seed:#018x}")

        print("[*] Constructing an exact XXH3-128 preimage for b'Give me the flag'")
        accumulators = construct_target_accumulators(seed)
        payload = construct_preimage(seed, accumulators)
        print(
            f"[+] Local verification: "
            f"{xxhash.xxh3_128(payload, seed=seed).digest()!r}"
        )

        remote.send(b"2\n" + payload.hex().encode("ascii") + b"\n")
        response = remote.recv_to_end_or_flag(timeout=30.0)
        sys.stdout.buffer.write(response)
        if response and not response.endswith(b"\n"):
            print()
        match = FLAG_RE.search(response)
        if not match:
            raise RuntimeError("server did not return a SEKAI{...} flag")
        print(f"[+] FLAG: {match.group(0).decode('ascii')}")
    finally:
        remote.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve SEKAI CTF Iihash")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument(
        "--max-queries",
        type=int,
        default=1_200_000,
        help="maximum hash queries per collision family",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=384,
        help="queries pipelined before each receive pass",
    )
    parser.add_argument("--socket-timeout", type=float, default=120.0)
    parser.add_argument("--no-pow", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            run_live(args)
        return 0
    except KeyboardInterrupt:
        print("\n[-] interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.environ.get("IIHASH_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
