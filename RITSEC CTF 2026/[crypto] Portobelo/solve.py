from sage.all import *
import base64
import json
import hashlib
import operator
from pwn import remote, context
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Suppress pwntools debug logs
context.log_level = 'error'

def mul(a, b, poly):
    """GF(4^8) polynomial multiplication matching server's logic."""
    deg = 8
    prod = [0] * (2 * deg - 1)
    for i in range(deg):
        for j in range(deg):
            prod[i + j] = (prod[i + j] + a[i] * b[j]) % 4

    for d in range(2 * deg - 2, deg - 1, -1):
        if prod[d] != 0:
            coeff = prod[d]
            for k in range(deg + 1):
                prod[d - deg + k] = (prod[d - deg + k] - coeff * poly[k]) % 4
            prod[d] = 0
    return prod[:deg]

def kdf(secret_key, poly_coeffs, gen_coeffs):
    """Key Derivation Function matching server."""
    sk_bytes = bytes([e + 127 for e in secret_key])

    h = hashlib.shake_256(sk_bytes)
    state_bytes = h.digest(136)

    mixed = bytearray()
    for off in range(0, len(state_bytes), 8):
        block = state_bytes[off:off + 8]
        if len(block) < 8:
            block = block + bytes(8 - len(block))

        elem =[int(b) % 4 for b in block]
        product = mul(elem, gen_coeffs, poly_coeffs)
        mixed.extend(bytes(c % 256 for c in product))

    squeeze = h.digest(32)
    derived = hashlib.shake_256(bytes(mixed)).digest(32)
    
    # FIX: Use operator.xor to avoid SageMath replacing ^ with **
    return bytes(operator.xor(a, b) for a, b in zip(derived, squeeze))

def solve():
    HOST = 'portobelo.ctf.ritsec.club'
    PORT = 1337
    
    print(f"[*] Connecting to {HOST}:{PORT}...")
    try:
        conn = remote(HOST, PORT)
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    lines =[]
    while True:
        try:
            line = conn.recvline().decode().strip()
        except EOFError:
            print("[-] Connection closed by server.")
            break
        lines.append(line)
        if line == "READY":
            break
        if "Too many connections" in line:
            print("[-] Rate limited!")
            return

    pb64 = None
    flag_ct = flag_nonce = flag_tag = None
    
    for line in lines:
        if line.startswith("PARAMS "):
            pb64 = line.split(" ")[1]
        elif line.startswith("ENCRYPTED_FLAG "):
            _, ct_hex, nonce_hex, tag_hex = line.split()
            flag_ct = bytes.fromhex(ct_hex)
            flag_nonce = bytes.fromhex(nonce_hex)
            flag_tag = bytes.fromhex(tag_hex)

    if not pb64:
        print("[-] Failed to get PARAMS")
        return
        
    params = json.loads(base64.b64decode(pb64).decode())
    p = int(params["p"])
    primes_len = len(params["primes"])
    
    print(f"[*] Parameters extracted. p is {p.bit_length()} bits, {primes_len} primes.")
    
    # We query A from 3 up to 3 + primes_len to strictly avoid singular curves like A=2
    queries = range(3, 3 + primes_len)
    points = []
    ops_count = None
    
    print(f"[*] Gathering {primes_len} trace evaluations...")
    for q_A in queries:
        conn.sendline(f"QUERY {q_A}".encode())
        res = conn.recvline().decode().strip()
        if res.startswith("RESULT"):
            parts = res.split()
            ops = int(parts[2])
            tr = int(parts[3])
            
            if ops_count is None:
                ops_count = ops
            points.append((q_A, tr))
        else:
            print(f"[-] Query failed for A={q_A}: {res}")
            break
            
    conn.close()
    
    if len(points) < primes_len:
        print("[-] Not enough points collected.")
        return
        
    print("[*] Lagrange interpolating polynomial over GF(p)...")
    F = GF(p)
    R = PolynomialRing(F, 'x')
    poly = R.lagrange_polynomial([(F(x), F(y)) for x, y in points])
    coeffs = poly.list()
    
    # Pad out the coefficients if degree strictly < primes_len - 1
    coeffs += [0] * (primes_len - len(coeffs))
    
    def to_signed(val, p):
        val = int(val)
        return val - p if val > p // 2 else val

    # Convert field coefficients to CSIDH short signed integer ranges
    sk_partial =[to_signed(c, p) for c in coeffs]
    partial_sum = sum(abs(c) for c in sk_partial)
    missing_abs = ops_count - partial_sum
    
    print(f"[*] Partial Ops Sum: {partial_sum} | Server Leak Total: {ops_count}")
    print(f"[*] Target magnitude for the poisoned index: {missing_abs}")
    
    gr48_poly = params["gr48_poly"]
    gr48_gen = params["gr48_generator"]
    
    candidates =[]
    for i in range(primes_len):
        if sk_partial[i] == 0:
            if missing_abs != 0:
                for sign in [1, -1]:
                    sk_cand = list(sk_partial)
                    sk_cand[i] = sign * missing_abs
                    candidates.append((i, sk_cand))
            else:
                sk_cand = list(sk_partial)
                sk_cand[i] = 0
                candidates.append((i, sk_cand))
                
    print(f"[*] Testing {len(candidates)} Candidate Keys against AES-GCM Tag...")
    
    for idx, sk_cand in candidates:
        key = kdf(sk_cand, gr48_poly, gr48_gen)
        cipher = AES.new(key, AES.MODE_GCM, nonce=flag_nonce)
        try:
            flag = cipher.decrypt_and_verify(flag_ct, flag_tag)
            print(f"\n[+] 🎯 SUCCESS! Flag found: {flag.decode('utf-8')}")
            print(f"[+] Poisoned index was identified as: {idx}")
            return
        except Exception:
            continue
            
    print("[-] Failed to find the correct key.")

if __name__ == '__main__':
    solve()