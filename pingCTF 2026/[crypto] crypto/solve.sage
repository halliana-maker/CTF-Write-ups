# Execute with: sage solve.sage
import json
import hashlib
import itertools
from pwn import *
from Crypto.Cipher import AES
from sage.all import crt, GF, EllipticCurve, prime_range, inverse_mod, prod

# Suppress verbose pwntools connection logs
context.log_level = 'error'

# NIST P-192 Parameters
p = 6277101735386680763835789423207666416083908700390324961279
n_curve = 6277101735386680763835789423176059013767194773182842284081

target = n_curve
moduli =[]
points =[]

# Primes between 5000 and 50000 gives an optimal balance:
# - Minimal primes needed (about 13-14)
# - Small number of CRT sign combinations (~8192 to 16384)
# - Fast brute-force for MAC (~25000 hashes max per prime locally)
primes_list = list(prime_range(5000, 50000))

print("[*] Finding Invalid Curves with smooth subgroup orders...")
b = 1
F = GF(p)
while target > 1:
    try:
        # Avoid singular curves (where discriminant is 0)
        E = EllipticCurve(F, [-3, b])
    except ArithmeticError:
        b += 1
        continue
        
    N = E.order()
    for q in primes_list:
        if N % q == 0 and q not in moduli:
            P = E.random_point()
            P_q = (N // q) * P
            if P_q == E(0):
                continue
            
            moduli.append(q)
            points.append(P_q)
            target //= q
            print(f"[*] Harvested prime factor {q:<5} | Target remaining bit-length: {target.nbits() if target > 0 else 0}")
            if target <= 1:
                break
    b += 1

print(f"[+] Successfully harvested {len(moduli)} primes. M = prod(q_i) > n_curve.")

host = '178.104.42.20'
port = 55137
print(f"[*] Connecting to {host}:{port}")

try:
    io = remote(host, port)
    
    io.recvuntil(b"Data (hex): ")
    data_hex = io.recvline().strip().decode()
    data = bytes.fromhex(data_hex)
    nonce, ciphertext = data[:8], data[8:]
    
    print(f"[*] Captured Nonce: {nonce.hex()}")
    
    remainders =[]
    
    for P_q, q in zip(points, moduli):
        # Extract X, Y robustly avoiding higher-level wrapper overheads
        x_val, y_val = int(P_q[0]), int(P_q[1])
        
        io.recvuntil(b"Enter your public point R_A in JSON format [x, y]:")
        io.sendline(json.dumps([x_val, y_val]).encode())
        
        resp = io.recvline().decode().strip()
        while not resp:
            resp = io.recvline().decode().strip()
            
        # Exception thrown implies the shared point is at infinity -> b_priv == 0 mod q
        if "ValueError" in resp:
            print(f"[*] b_priv % {q} == 0")
            remainders.append([0])
            continue
            
        if "MAC:" not in resp:
            print(f"[!] Unexpected response: {resp}")
            break
            
        mac_str = resp.split("MAC: ")[1].strip()
        
        found = False
        current = P_q
        
        # Iterating up to q // 2 covers all possible x-coordinates
        for k in range(1, (q // 2) + 1):
            hx = int(current[0])
            ss = hashlib.sha256(hx.to_bytes(24, "big")).digest()
            cmac = hashlib.sha256(ss).hexdigest()
            if cmac == mac_str:
                # Store both the positive and negative subgroup roots due to X-coordinate mapping ambiguity
                if k == q - k:
                    remainders.append([k])
                else:
                    remainders.append([k, q - k])
                found = True
                print(f"[+] Recovered b_priv % {q} in [{k}, {q-k}]")
                break
            current += P_q
            
        if not found:
            raise ValueError(f"Failed to find congruency for q={q}")

    io.close()

    total_combos = prod(len(opts) for opts in remainders)
    print(f"\n[*] Resolving X-coordinate ambiguity...")
    print(f"[*] Testing {total_combos} combinations using optimized CRT...")
    
    # Precompute mathematical CRT Basis for ultra-fast iterative testing
    M = prod(moduli)
    basis =[]
    for q in moduli:
        M_i = M // q
        inv = inverse_mod(M_i, q)
        basis.append(M_i * inv)
        
    def check_combinations():
        for combo in itertools.product(*remainders):
            b_cand = sum((c * b) for c, b in zip(combo, basis)) % M
            
            aes_key = hashlib.sha256(str(b_cand).encode()).digest()
            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
            
            # Since CTR acts as a stream cipher, partially decrypt first block to verify `ping{` flag header
            pt = cipher.decrypt(ciphertext[:16])
            if b"ping{" in pt:
                cipher_full = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
                return cipher_full.decrypt(ciphertext)
        return None

    flag = check_combinations()
    if flag:
        print(f"\nFLAG RECOVERED: {flag.decode('utf-8', errors='ignore')}")
    else:
        print("[-] Decryption failed. Something went wrong.")

except Exception as e:
    print(f"[!] Critical Error: {e}")


# Output: 
# [*] Finding Invalid Curves with smooth subgroup orders...
# [*] Harvested prime factor 8123  | Target remaining bit-length: 180
# [*] Harvested prime factor 6899  | Target remaining bit-length: 167
# [*] Harvested prime factor 17209 | Target remaining bit-length: 153
# [*] Harvested prime factor 22619 | Target remaining bit-length: 138
# [*] Harvested prime factor 23581 | Target remaining bit-length: 124
# [*] Harvested prime factor 30949 | Target remaining bit-length: 109
# [*] Harvested prime factor 14797 | Target remaining bit-length: 95
# [*] Harvested prime factor 23321 | Target remaining bit-length: 80
# [*] Harvested prime factor 31729 | Target remaining bit-length: 65
# [*] Harvested prime factor 34673 | Target remaining bit-length: 50
# [*] Harvested prime factor 25601 | Target remaining bit-length: 36
# [*] Harvested prime factor 7481  | Target remaining bit-length: 23
# [*] Harvested prime factor 10463 | Target remaining bit-length: 10
# [*] Harvested prime factor 16057 | Target remaining bit-length: 0
# [+] Successfully harvested 14 primes. M = prod(q_i) > n_curve.
# [*] Connecting to 178.104.42.20:55137
# [*] Captured Nonce: 2543ec25c599f333
# [+] Recovered b_priv % 8123 in [1023, 7100]
# [+] Recovered b_priv % 6899 in [1186, 5713]
# [+] Recovered b_priv % 17209 in [7939, 9270]
# [+] Recovered b_priv % 22619 in [6260, 16359]
# [+] Recovered b_priv % 23581 in [739, 22842]
# [+] Recovered b_priv % 30949 in [13468, 17481]
# [+] Recovered b_priv % 14797 in [7349, 7448]
# [+] Recovered b_priv % 23321 in [4318, 19003]
# [+] Recovered b_priv % 31729 in [14891, 16838]
# [+] Recovered b_priv % 34673 in [8686, 25987]
# [+] Recovered b_priv % 25601 in [9062, 16539]
# [+] Recovered b_priv % 7481 in [1821, 5660]
# [+] Recovered b_priv % 10463 in [2535, 7928]
# [+] Recovered b_priv % 16057 in [1864, 14193]

# [*] Resolving X-coordinate ambiguity...
# [*] Testing 16384 combinations using optimized CRT...

# FLAG RECOVERED: ping{b_p4r4m3t3r_d03snt_m4tt3r_h3r3}