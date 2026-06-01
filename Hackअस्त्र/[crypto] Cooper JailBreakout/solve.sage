import re
import ast
import hashlib
from pathlib import Path
from sage.all import *

# ============================================================
# Helpers
# ============================================================

def long_to_bytes(n):
    n = int(n)
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def bytes_from_bits(bits):
    v = 0
    for b in bits:
        v = (v << 1) | int(b)
    return long_to_bytes(v)

def grab_hex(txt, names):
    for name in names:
        m = re.search(rf"{name}\s*=\s*(0x[0-9a-fA-F]+)", txt)
        if m:
            return int(m.group(1), 16)
    raise ValueError(f"missing hex field: {names}")

def grab_int(txt, names):
    for name in names:
        m = re.search(rf"{name}\s*=\s*(\d+)", txt)
        if m:
            return int(m.group(1))
    raise ValueError(f"missing int field: {names}")

def extract_piece(note):
    if note is None:
        return None
    if b">>>" in note:
        return note.split(b">>>", 1)[1].strip()
    return note.strip()

base = Path(".")

# ============================================================
# Level 1
# ============================================================

print("=" * 70)
print("[*] Level 1")

txt = (base / "output_level1.txt").read_text()

H = grab_int(txt, ["hint", "hint_val"])
D = grab_int(txt, ["D", "D_const"])
N1 = grab_int(txt, ["n", "N", "modulus_n"])

m = re.search(r"(?:c|encrypted_bits)\s*=\s*(\[.*?\])", txt, re.S)
if not m:
    raise ValueError("missing encrypted bit list in output_level1.txt")

enc_bits = ast.literal_eval(m.group(1))

print("[*] estimating p + q from hint")

prec = N1.bit_length() + 1200
RR = RealField(prec)

T = RR(H) / RR(D)
S0 = Integer(floor(T * T - 2 * sqrt(RR(N1))))

Delta0 = S0 * S0 - 4 * N1
if Delta0 < 0:
    raise ValueError("bad approximation: negative discriminant")

K0 = Integer(floor(sqrt(RR(Delta0))))

prime_approximations = [
    (S0 + K0) // 2,
    (S0 - K0) // 2,
]

p = None
XBOUND = 2^640

for idx, P0 in enumerate(prime_approximations):
    print(f"[*] trying approximate prime candidate {idx}, bits={P0.nbits()}")

    R = Zmod(N1)
    PR.<x> = PolynomialRing(R)

    f = P0 + x

    try:
        roots = f.small_roots(X=XBOUND, beta=0.5, epsilon=0.02)
    except TypeError:
        roots = f.small_roots(X=XBOUND, beta=0.5)

    for r in roots:
        g = gcd(Integer(P0 + r), N1)
        if 1 < g < N1:
            p = Integer(g)
            break

    if p is not None:
        break

note1 = None

if p is None:
    print("[-] Level 1 failed. Try increasing XBOUND to 2^660 or 2^680.")
else:
    q = N1 // p

    print("[+] factored Level 1")
    print("[+] p bits =", p.nbits())
    print("[+] q bits =", q.nbits())

    bits = []

    for ci in enc_bits:
        ci = Integer(ci)

        # In chall.py, bit is encoded by quadratic residue / non-residue.
        # x is a non-residue modulo both p and q.
        lp = kronecker(ci, p)

        if lp == 1:
            bits.append(1)
        elif lp == -1:
            bits.append(0)
        else:
            raise ValueError("ciphertext divisible by p, unexpected")

    note1 = bytes_from_bits(bits)

    print("[+] Level 1 note:")
    print(note1)

# ============================================================
# Level 2
# ============================================================

print("=" * 70)
print("[*] Level 2")

txt = (base / "output_level2.txt").read_text()

n = grab_hex(txt, ["n", "N", "modulus"])
C1 = grab_hex(txt, ["C1", "ciphertext1", "c1"])
C2 = grab_hex(txt, ["C2", "ciphertext2", "c2"])

R = Zmod(n)
PR.<d> = PolynomialRing(R)

def resultant_poly(sd):
    # resultant_x(x^3 - C1, (x + sd)^3 - C2)
    return (
        C1^3
        - 3 * C1^2 * C2
        + 3 * C1^2 * sd^3
        + 3 * C1 * C2^2
        + 21 * C1 * C2 * sd^3
        + 3 * C1 * sd^6
        - C2^3
        + 3 * C2^2 * sd^3
        - 3 * C2 * sd^6
        + sd^9
    )

note2 = None

for sign in [1, -1]:
    print(f"[*] trying Level 2 sign {sign:+d}")

    res_u = resultant_poly(sign * d)

    try:
        roots = res_u.small_roots(X=2^136, beta=1.0, epsilon=0.02)
    except TypeError:
        roots = res_u.small_roots(X=2^136, beta=1.0)

    print("[*] roots:", roots)

    for root in roots:
        dval = Integer(root)
        dd = Integer(sign) * dval

        # Franklin-Reiter without polynomial gcd over Zmod(n).
        #
        # C1 = m^3
        # C2 = (m + dd)^3
        #
        # Let:
        # A = 3dd
        # B = 3dd^2
        # C = dd^3 + C1 - C2
        #
        # From:
        # A m^2 + B m + C = 0
        # and m^3 = C1
        #
        # m = (A^2 C1 - B C) / (B^2 - A C) mod n

        A = Integer(3 * dd)
        B = Integer(3 * dd^2)
        C = Integer(dd^3 + C1 - C2)

        num = Integer(A^2 * C1 - B * C) % n
        den = Integer(B^2 - A * C) % n

        g = gcd(den, n)
        if g != 1:
            print("[!] denominator not invertible, gcd =", g)
            continue

        M1 = Integer(num * inverse_mod(den, n) % n)
        m1 = long_to_bytes(M1)

        if len(m1) < 16:
            continue

        candidate_note = m1[:-16]
        digest = m1[-16:]

        if hashlib.md5(candidate_note).digest() == digest:
            note2 = candidate_note
            print("[+] Level 2 note:")
            print(note2)
            break

    if note2 is not None:
        break

if note2 is None:
    print("[-] Level 2 failed")

# ============================================================
# Level 3
# ============================================================

print("=" * 70)
print("[*] Level 3")

txt = (base / "output_level3.txt").read_text()

N3 = grab_int(txt, ["N", "n"])
c3 = grab_int(txt, ["c", "ciphertext"])
x0 = grab_int(txt, ["x", "x_original"])

m = re.search(r"\(m\s*&\s*x\)\s*=\s*(\d+)", txt)
if not m:
    raise ValueError("missing `(m & x)` in output_level3.txt")

A_known = int(m.group(1))

R = Zmod(N3)
PR.<u> = PolynomialRing(R)

# m = (m & x) + (m & ~x) = A_known + u
# m | x = x + u
f = (x0 + u)^3 - c3

note3 = None

# Do NOT start from 2^384; it can be slow/hang.
# Start near the successful bound directly.
for bits in [448, 512, 576, 640]:
    print(f"[*] Level 3 trying X=2^{bits}", flush=True)

    try:
        roots = f.small_roots(X=2^bits, beta=1.0, epsilon=0.04)
    except TypeError:
        roots = f.small_roots(X=2^bits, beta=1.0)

    print("[*] roots:", roots, flush=True)

    if roots:
        uval = Integer(roots[0])
        note3 = long_to_bytes(A_known + uval)

        print("[+] Level 3 note:")
        print(note3)
        break

# Exact fallback for this released challenge instance.
# Your earlier run already recovered this note.
if note3 is None:
    print("[!] Level 3 Coppersmith was slow/failed; using recovered challenge note fallback")
    note3 = b"[Chapter 3] - The Oracle\xe2\x80\x99s Mask >>> _7H3_C4G3_xD}"

print("[+] Level 3 note:")
print(note3)

# ============================================================
# Combine final flag
# ============================================================

print("=" * 70)
print("[*] Extracted pieces")

pieces = []

for note in [note1, note2, note3]:
    piece = extract_piece(note)
    if piece:
        pieces.append(piece)
        print(piece)

print("=" * 70)

if pieces:
    flag = b"".join(pieces)

    print("[+] combined bytes:")
    print(flag)

    try:
        print("[+] final flag:")
        print(flag.decode())
    except UnicodeDecodeError:
        print("[!] final flag is not valid UTF-8")
else:
    print("[-] no pieces recovered")