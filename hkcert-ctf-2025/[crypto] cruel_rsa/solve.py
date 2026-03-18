#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.number import long_to_bytes
import itertools

# --- Challenge Data ---
n = 8073736467273664280056643912209398524942152147328656910931152412352288220476046078152045937002526657533942284160476452038914249779936821603053211888330755
e = 36346110007425305872660997908648011390452485009167380402907988449045651435844811625907
c = 8042279705649954745962644909235780183674555369775538455015331686608683922326562829164835918982642084136603628007677118144681339970688028985720674063973679

# Factors retrieved from FactorDB
factors = [3, 3, 5, 11, 13, 241, 19913, 27479, 8817293, 1609668743, 
           21744410757863, 1791152102074579, 2640729780285917881567, 
           561544524741926577700278571, 11606767999414698455890262045272382868998286949]

# Group into prime powers (e.g., 3, 3 -> 9)
from collections import Counter
counts = Counter(factors)
ppowers = [p**k for p, k in counts.items()]

print(f"[*] Solving RSA with smooth modulus N...")
print(f"[*] Factors: {ppowers}")

all_roots = []

for mod in ppowers:
    R = IntegerModRing(mod)
    cc = R(c)
    
    # Calculate roots modulo p^k
    # .nth_root(e, all=True) automatically handles gcd(e, phi) > 1 logic
    try:
        roots = cc.nth_root(e, all=True)
        # Convert Sage integers to Python ints
        current_roots = [int(r) for r in roots]
        all_roots.append(current_roots)
    except ValueError:
        print(f"[!] No roots found for factor {mod}")
        exit()

print(f"[*] Total combinations to check: {prod(len(r) for r in all_roots)}")

# Brute force the small number of CRT combinations
for combo in itertools.product(*all_roots):
    m_val = crt(list(combo), ppowers)
    try:
        flag_candidate = long_to_bytes(int(m_val))
        if b"flag{" in flag_candidate:
            print(f"\n[+] FLAG RECOVERED: {flag_candidate.decode()}")
            break
    except:
        continue