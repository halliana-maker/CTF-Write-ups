#!/usr/bin/env python3
# Thinking Space II Revenge solver
# Put this file next to uov.py (or one directory above dist/uov.py), then run:
#   python3 solve_ts2_revenge.py

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

try:
    from pwn import remote, context
except ImportError:
    print('[-] missing pwntools: pip install pwntools', file=sys.stderr)
    raise

# Find the challenge's uov.py.
HERE = Path(__file__).resolve().parent
for p in [HERE, HERE / 'dist', Path.cwd(), Path.cwd() / 'dist']:
    sys.path.insert(0, str(p))

try:
    from uov import uov_1p_pkc as uov
    from Crypto.Hash import SHAKE256
except ImportError as e:
    print('[-] could not import uov.py / pycryptodome.', file=sys.stderr)
    print('    Run from the extracted dist directory and install: pip install pycryptodome', file=sys.stderr)
    raise

THOUGHT = b'I am thinking of the flag'
ZERO44 = bytes(44)


def shake(x: bytes, out_len: int = 44) -> bytes:
    return SHAKE256.new(x).read(out_len)


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def vadd(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# GF(256) arithmetic tables, using the same field as uov.py.
MUL = [[0] * 256 for _ in range(256)]
for _a in range(256):
    for _b in range(256):
        MUL[_a][_b] = uov.gf256_mul(_a, _b)
INV = [0] * 256
for _a in range(1, 256):
    INV[_a] = uov.gf_inv(_a)


def rref(mat, ncols=None):
    A = [bytearray(row) for row in mat]
    if not A:
        return A, []
    if ncols is None:
        ncols = len(A[0])

    r = 0
    pivots = []
    for c in range(ncols):
        pr = None
        for i in range(r, len(A)):
            if A[i][c]:
                pr = i
                break
        if pr is None:
            continue

        A[r], A[pr] = A[pr], A[r]
        inv = INV[A[r][c]]
        if inv != 1:
            mt = MUL[inv]
            row = A[r]
            for j in range(c, len(row)):
                row[j] = mt[row[j]]

        for i in range(len(A)):
            if i != r and A[i][c]:
                f = A[i][c]
                mt = MUL[f]
                row_i = A[i]
                row_r = A[r]
                for j in range(c, len(row_i)):
                    row_i[j] ^= mt[row_r[j]]

        pivots.append(c)
        r += 1
        if r == len(A):
            break
    return A, pivots


def solve_linear(A, b):
    aug = [bytearray(row) + bytearray([rhs]) for row, rhs in zip(A, b)]
    R, pivots = rref(aug, len(A[0]))
    n = len(A[0])
    x = bytearray(n)
    for i, c in enumerate(pivots):
        x[c] = R[i][n]
    for row in R:
        if not any(row[:n]) and row[n]:
            return None
    return bytes(x)


def nullspace(A, ncols):
    R, pivots = rref(A, ncols)
    pivot_set = set(pivots)
    free_cols = [c for c in range(ncols) if c not in pivot_set]
    basis = []
    for f in free_cols:
        x = bytearray(ncols)
        x[f] = 1
        for i, pc in enumerate(pivots):
            x[pc] = R[i][f]
        basis.append(bytes(x))
    return basis


def rank_basis(vecs, n=112):
    if not vecs:
        return []
    R, _ = rref(vecs, n)
    return [bytes(row[:n]) for row in R if any(row[:n])]


def combine(coeffs, basis, n=112):
    out = bytearray(n)
    for c, b in zip(coeffs, basis):
        if c:
            mt = MUL[c]
            for i, x in enumerate(b):
                out[i] ^= mt[x]
    return bytes(out)


def nonzero(v: bytes):
    return [(i, x) for i, x in enumerate(v) if x]


def unpack_public_pairs(epk: bytes):
    """Return public polar coefficients for off-diagonal variable pairs."""
    v, m = uov.v, uov.m
    p1 = uov.unpack_mtri(epk[:uov.p1_sz], v)
    p2 = uov.unpack_mrect(epk[uov.p1_sz:], v, m)
    p3 = uov.unpack_mtri(epk[uov.p1_sz + uov.p2_sz:], m)

    pairs = {}
    for i in range(v):
        for j in range(i + 1, v):
            if p1[i][j]:
                pairs[(i, j)] = p1[i][j]
    for i in range(v):
        for j in range(m):
            if p2[i][j]:
                pairs[(i, v + j)] = p2[i][j]
    for i in range(m):
        for j in range(i + 1, m):
            if p3[i][j]:
                pairs[(v + i, v + j)] = p3[i][j]
    return pairs


def polar_sparse(ai, bi, pairs) -> bytes:
    """Vector-valued polar form B(a,b)=P(a+b)+P(a)+P(b), as 44 bytes."""
    y = 0
    get = pairs.get
    gfm = uov.gf_mulm
    for i, av in ai:
        mav = MUL[av]
        for j, bv in bi:
            if i == j:
                continue
            if i < j:
                coeff = get((i, j))
            else:
                coeff = get((j, i))
            if coeff:
                scalar = mav[bv]
                if scalar:
                    y ^= gfm(coeff, scalar)
    return y.to_bytes(44)


def dot_lam(lam: bytes, vec44: bytes) -> int:
    acc = 0
    for a, b in zip(lam, vec44):
        if a and b:
            acc ^= MUL[a][b]
    return acc


def pubmap(v: bytes, epk: bytes) -> bytes:
    return uov.pubmap(v, epk)


def forge_signature(pk: bytes, signed_sig: bytes, signed_msg: bytes, target_msg: bytes = THOUGHT) -> bytes:
    epk = uov.expand_pk(pk)
    pairs = unpack_public_pairs(epk)

    q = signed_sig[:44]          # leaked P(v || 0)
    s = signed_sig[44:156]       # actual 112-byte signature vector
    salt = signed_sig[156:172]
    t = shake(signed_msg + salt)
    assert pubmap(s, epk) == t, 'service returned an invalid signature?'

    # 1) Recover the restricted vinegar vector v0=(v[0..43],0..0).
    #    Since o=s+v0 is an oil-space vector, P(o)=0, so
    #    B(v0,s)=P(v0)+P(s)=q+t.  This is linear in the 44 unknown bytes.
    ns = nonzero(s)
    cols = [polar_sparse([(j, 1)], ns, pairs) for j in range(44)]
    A = [[cols[c][r] for c in range(44)] for r in range(44)]
    v44 = solve_linear(A, bxor(q, t))
    if v44 is None:
        raise RuntimeError('failed to recover v')
    v0 = v44 + bytes(68)
    if pubmap(v0, epk) != q:
        raise RuntimeError('bad v recovery')

    oil = vadd(s, v0)
    if pubmap(oil, epk) != ZERO44:
        raise RuntimeError('recovered vector is not in the zero set')

    # 2) Use the known oil vector to linearize the oil-space recovery.
    #    K = ker(B(oil, .)) has dimension 68 and contains the hidden oil space.
    noil = nonzero(oil)
    cols = [polar_sparse(noil, [(j, 1)], pairs) for j in range(112)]
    Kmat = [[cols[c][r] for c in range(112)] for r in range(44)]
    Kbasis = nullspace(Kmat, 112)
    if len(Kbasis) != 68:
        raise RuntimeError(f'unexpected K dimension {len(Kbasis)}')

    Ksp = [nonzero(b) for b in Kbasis]
    N = len(Kbasis)

    # Precompute vector-valued polar form on K.
    BK = [[b''] * N for _ in range(N)]
    for i in range(N):
        for j in range(i, N):
            BK[i][j] = polar_sparse(Ksp[i], Ksp[j], pairs)

    # 3) A random scalar combination of the restricted quadratic forms has
    #    a radical that lies in the hidden oil space.  A few such radicals
    #    span the whole 44-dimensional oil space.
    oil_basis = [oil]
    for _ in range(16):
        lam = os.urandom(44)
        M = []
        for i in range(N):
            row = bytearray(N)
            for j in range(N):
                row[j] = dot_lam(lam, BK[i][j] if i <= j else BK[j][i])
            M.append(row)
        ker = nullspace(M, N)
        candidates = [combine(c, Kbasis) for c in ker]
        oil_basis = rank_basis(oil_basis + candidates, 112)
        if len(oil_basis) >= 44:
            break
    if len(oil_basis) < 44:
        raise RuntimeError(f'only recovered {len(oil_basis)} oil-space vectors')
    oil_basis = oil_basis[:44]

    # 4) Sign the target with the same recovered vinegar v0.
    target_salt = os.urandom(16)
    target_hash = shake(target_msg + target_salt)
    nv0 = nonzero(v0)
    imgs = [polar_sparse(nv0, nonzero(b), pairs) for b in oil_basis]
    D = [[imgs[c][r] for c in range(44)] for r in range(44)]
    coeff = solve_linear(D, bxor(target_hash, q))
    if coeff is None:
        raise RuntimeError('oil differential matrix was singular')

    oil_part = combine(coeff, oil_basis)
    sig_vec = vadd(v0, oil_part)
    forged = b'X' * 44 + sig_vec + target_salt  # first 44 bytes are ignored by verify()

    if pubmap(sig_vec, epk) != target_hash:
        raise RuntimeError('forgery self-check failed')
    return forged


def solve_pow(token: str, manual: bool = False) -> bytes:
    if not manual:
        cmd = f"python3 <(curl -sSL https://goo.gle/kctf-pow) solve {shlex.quote(token)}"
        try:
            return subprocess.check_output(
                cmd,
                shell=True,
                executable='/bin/bash',
                timeout=180,
            ).strip()
        except Exception as e:
            print(f'[!] automatic PoW failed: {e}', file=sys.stderr)
    print('Paste PoW solution: ', end='', flush=True)
    return sys.stdin.readline().strip().encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='chal.sieberr.live')
    ap.add_argument('--port', default=20006, type=int)
    ap.add_argument('--msg', default='hello')
    ap.add_argument('--manual-pow', action='store_true')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    context.log_level = 'debug' if args.verbose else 'info'
    signed_msg = args.msg.encode()
    if signed_msg == THOUGHT:
        raise SystemExit('chosen signing message must not equal the target thought')

    io = remote(args.host, args.port)

    buf = io.recvuntil(b'> ', timeout=60)
    m = re.search(
        rb'python3\s+<\(curl\s+-sSL\s+https://goo\.gle/kctf-pow\)\s+solve\s+(s\.[^\s]+)',
        buf,
    )
    if not m:
        m = re.search(rb'\bsolve\s+(s\.[A-Za-z0-9+/_=.-]+)', buf)
    if not m:
        sys.stderr.buffer.write(b'[-] could not parse PoW banner:\n' + buf + b'\n')
        raise RuntimeError('could not parse kCTF PoW token')

    token = m.group(1).decode()
    print('[+] PoW token:', token)
    io.sendline(solve_pow(token, args.manual_pow))
    io.recvuntil(b'Press enter to proceed to the challenge')
    io.sendline(b'')

    pk_hex = io.recvline().strip().decode()
    while not re.fullmatch(r'[0-9a-fA-F]+', pk_hex or ''):
        pk_hex = io.recvline().strip().decode()
    pk = bytes.fromhex(pk_hex)
    print('[+] got pk bytes:', len(pk))

    io.recvuntil(b'msg: ')
    io.sendline(signed_msg)
    sig_hex = io.recvline().strip().decode()
    signed_sig = bytes.fromhex(sig_hex)
    print('[+] got one signature bytes:', len(signed_sig))

    print('[*] recovering oil space and forging target signature...')
    forged = forge_signature(pk, signed_sig, signed_msg)
    print('[+] forged signature bytes:', len(forged))

    io.recvuntil(b'sig: ')
    io.sendline(forged.hex().encode())
    print(io.recvall(timeout=20).decode(errors='replace'))


if __name__ == '__main__':
    main()
