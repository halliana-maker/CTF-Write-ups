# HKCERT CTF 2025 - cruel_rsa Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *cute rsa? oh nonono, so cruel*
 

## TL;DR
The challenge generates an RSA modulus $N$ using a loop that explicitly **rejects** prime numbers for $p$ and $q$. This results in $N$ being a "smooth" number (composed of many small factors) rather than a semiprime. We factor $N$ instantly using **FactorDB**, solve the discrete logarithm $m^e \equiv c$ modulo each small prime power, and recombine the result using the Chinese Remainder Theorem (CRT) to recover the flag.

---

## 1. Reconnaissance & Analysis

We are provided with a Python script and the output parameters ($N, e, c$, and partial private keys $dm, dl$).

### The "Cruel" Logic
The standard RSA key generation involves finding two large primes $p$ and $q$. However, looking closely at the generation loop in `chal.py`:

```python
while 1:
    p = q = 0
    # CRITICAL VULNERABILITY HERE
    while is_prime(p) or len(bin(p)) - 2 != nbit // 2:
        a = randint(...)
        p = 2 * g * a + 1 
    # AND HERE
    while is_prime(q) or len(bin(q)) - 2 != nbit // 2:
        b = randint(...)
        q = 2 * g * b + 1
```

The condition `while is_prime(p)` means the loop **continues** as long as `p` is prime. It only breaks (accepts the number) when `p` is **COMPOSITE**.

This effectively creates a **Fake Modulus**. Instead of $N = p \times q$ where $p, q$ are primes, we have $N = (\prod f_i) \times (\prod g_j)$, a composite of composites.

### The Red Herring
The challenge provides `dm` (middle bits of $d$) and `dl` (least significant bits of $d$). In a standard RSA challenge, this would scream **Coppersmith's Attack** (Partial Key Exposure). However, given that $N$ is fundamentally broken by being smooth, these hints are unnecessary distractions intended to send solvers down a rabbit hole of lattice attacks.

## 2. Exploitation Strategy

Since $N$ is composed of many small prime factors, we don't need the private key $d$ to decrypt. We can attack the ciphertext directly using the **Chinese Remainder Theorem (CRT)**.

### Step 1: Factoring N
We plugged $N$ into [FactorDB](http://factordb.com/) (or ran a quick `ecm` / `pollard_rho` check).
The factors appeared instantly:
$$N = 3^2 \times 5 \times 11 \times 13 \times 241 \times \dots \times P_{large}$$
Even the largest factors were small enough (approx 150 bits) to handle easily.

### Step 2: Solving Modulo Prime Powers
We need to solve $x^e \equiv c \pmod{N}$.
We decompose this into a system of congruences:
$$x^e \equiv c \pmod{p_i^{k_i}}$$

For each prime power factor $q = p_i^{k_i}$:
1.  **Unique Root:** If $\gcd(e, \phi(q)) = 1$, we compute $d_i = e^{-1} \pmod{\phi(q)}$ and $m_i = c^{d_i} \pmod q$.
2.  **Multiple Roots:** If $\gcd(e, \phi(q)) = g > 1$, there are $g$ possible roots. We calculate all of them.

In this specific challenge, $\gcd(e, \phi(N)) = 3$, meaning there are 3 possible plaintexts.

### Step 3: Recombination (CRT)
We take the roots found for each factor and combine them using SageMath's `crt()`. Since the branching factor was small (only 3 combinations), we simply checked all resulting candidates for the string format `flag{`.

## 3. Solution Script

```python
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
```


**Flag:** `flag{Y0u_kNow_h0w_7o_f4cTor1z3_phI}`

## Conclusion
The challenge title "cruel_rsa" is ironic. The author was "cruel" to the RSA algorithm by forcing it to use composite numbers, which made it "kind" (easy) for us to solve. Always check `is_prime` logic in CTF challenges—negated checks are a common implementation bug pattern!