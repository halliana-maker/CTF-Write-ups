# C0ll1d3r - Firebird Internal CTF 2022 Writeup
**Description:** "Find a collision for my hash algorithm! It is basically military-graded: The output is 256-bit long, and discrete log is hard! I even made it harder such that you don't even have the public parameters!     
Connect at archive.cryptohack.org 9391"

## 1. TL;DR
1. **Parameter Leak:** Exploited the fact that sequential 1-byte inputs (`'a'`, `'b'`, `'c'`, `'d'`) increment the integer representation by exactly 1. This creates quadratic relations between the hashes that allow us to recover the hidden 256-bit prime $p$ via GCD.
2. **Lattice Reduction:** Converted the hash collision requirement (Fermat's Little Theorem exponent congruence modulo $p-1$) into a Closest Vector Problem (CVP). Used LLL reduction to generate a valid collision string composed entirely of lowercase letters.

## 2. What data/file we have and what is special
We are provided with `chall.py`. Here are the core mechanics and constraints:
* **Hidden Parameters:** A random 256-bit prime $p$ and a generator $g$ are created on connection; both are unknown to us.
* **The Hash Function:** $H(m) = g^{\operatorname{int}(b'\texttt{SECUREHASH\_}' + m)} \pmod p$
* **Constraints:** 
  * We are allowed exactly **5 queries** per session.
  * Inputs must strictly match the regex `^[a-z]+$` (only lowercase letters).
* **The Goal:** Provide a string $m \neq \text{"pleasegivemetheflag"}$ that produces the exact same hash as `"pleasegivemetheflag"`.

### Interaction Details
* **Player:** Sends a lowercase string.
* **Server:** Replies with `h(b'<string>') = <hex_hash>`.
* **Win Condition:** If the output hash matches the hash of `"pleasegivemetheflag"`, the server prints the flag.

## 3. Problem Analysis (In-Depth)
The problem consists of two distinct mathematical hurdles:

### Phase 1: Recovering the Secret Prime $p$
Because we don't know $p$ or $g$, we can't do any modular arithmetic. However, look at how the payload is constructed: `int.from_bytes(b'SECUREHASH_' + m, 'big')`.
If we query single-character strings `a`, `b`, `c`, and `d`, their ASCII values are 97, 98, 99, 100.
Because it's Big-Endian, incrementing the last byte increments the total integer value $M$ by exactly 1!
* $H_a = g^M \pmod p$
* $H_b = g^{M+1} \pmod p = H_a \cdot g \pmod p$
* $H_c = g^{M+2} \pmod p = H_a \cdot g^2 \pmod p$

Over the integers (without the modulo), this means:
$$H_b^2 - H_a \cdot H_c = k_1 \cdot p$$
$$H_c^2 - H_b \cdot H_d = k_2 \cdot p$$
$$(H_b \cdot H_c) - (H_a \cdot H_d) = k_3 \cdot p$$

By querying 4 sequential characters, calculating these equations, and taking the Greatest Common Divisor (GCD) of the results, we can isolate the hidden prime $p$!

### Phase 2: Finding the Collision
To forge a hash, we need $g^{M'} \equiv g^{M_{\text{target}}} \pmod p$.
By Fermat's Little Theorem, this holds true if:
$$M' \equiv M_{\text{target}} \pmod{p-1}$$

Our forged integer $M'$ is constructed as `SECUREHASH_` + `[a-z]*`. 
We can model this as a sum of base-256 digits. If we pick a payload length of $L = 75$ characters, we have 75 unknown variables $x_i \in [97, 122]$. We need to solve:
$$\text{Prefix} \cdot 256^{75} + \sum_{i=0}^{74} x_i \cdot 256^i \equiv M_{\text{target}} \pmod{p-1}$$

This is a classic **Subset Sum / Knapsack problem** embedded in a modular equation. We can solve it by building a matrix and using the **LLL lattice reduction algorithm**. To make it easier for LLL, we center the variables by shifting them around 'n' (ASCII 110), making the target range $[-13, 12]$.

## 4. Initial Guesses / First Try
* *Attempt 1:* Maybe discrete log? No, 256 bits is too large for standard algorithms like Baby-step Giant-step or Pollard's rho, plus we don't even know $p$.
* *Attempt 2:* Length extension attack? No, this isn't SHA-256 or MD5. It's an algebraic hash. 
* *Realization:* Because the hash relies entirely on algebraic properties (exponentiation), we can completely break it by treating the letters as mathematical variables. 

## 5. Exploitation Walkthrough / Flag Recovery

Here is the exact `SageMath` script used to automatically leak the prime, build the lattice matrix, extract the string, and retrieve the flag:

```python
from sage.all import *
from pwn import *
import re

def solve():
    # context.log_level = 'debug'
    r = remote('archive.cryptohack.org', 9391)

    print("[*] Leaking hashes to recover the secret prime p...")
    h_vals =[]
    # Sending 'a', 'b', 'c', 'd' means M increases exactly by 1 each query.
    for m in ['a', 'b', 'c', 'd']:
        r.sendline(m.encode())
        line = r.recvline().decode().strip()
        print(f"    [+] {line}")
        
        match = re.search(r'=\s*([0-9a-f]+)', line)
        if match:
            h_vals.append(int(match.group(1), 16))
        else:
            print("[-] Failed to parse hash from output.")
            return

    h1, h2, h3, h4 = h_vals
    
    # Mathematical relations that eliminate `g` and form multiples of `p`
    V1 = abs(h2**2 - h1*h3)
    V2 = abs(h3**2 - h2*h4)
    V3 = abs(h2*h3 - h1*h4)

    print("[*] Computing GCD of relations to extract p...")
    P = gcd(V1, gcd(V2, V3))

    p = None
    # Strip away any small constants to extract the true 256-bit prime
    for k in range(1, 1000):
        if P % k == 0:
            cand = P // k
            if cand.bit_length() <= 256 and is_prime(cand):
                p = cand
                break

    if p is None:
        print("[-] Failed to recover p reliably.")
        return

    print(f"[+] Successfully extracted p = {p}")

    target_val = ZZ(int.from_bytes(b'SECUREHASH_pleasegivemetheflag', 'big'))
    prefix_val = ZZ(int.from_bytes(b'SECUREHASH_', 'big'))
    
    # We want to find a string `m` of length L such that it resolves to target_val mod (p-1)
    L = 75 
    
    A = prefix_val * (256**L)
    # We center our search around ASCII 110 ('n') so that variables easily fit in [-13, 12]
    C = sum(110 * (256**i) for i in range(L))
    S = (target_val - A - C) % (p - 1)
    
    W = 2**150
    M = matrix(ZZ, L + 2, L + 2)
    for i in range(L):
        M[i, i] = 1
        M[i, L + 1] = (256**i) * W
    
    M[L, L + 1] = (p - 1) * W
    M[L + 1, L] = 1
    M[L + 1, L + 1] = S * W
    
    print("[*] Running LLL reduction")
    M_red = M.LLL()
    
    m_bytes = None
    
    def extract_vector(M_basis):
        for row in M_basis:
            if row[L] == 1 or row[L] == -1:
                sign = -int(row[L])
                y = [sign * row[i] for i in range(L)]
                # Check if elements are tightly bound in our desired alphabet spread
                if all(-13 <= yi <= 12 for yi in y):
                    x = [yi + 110 for yi in y]
                    # x[0] corresponds to 256^0 (least significant), so we reverse it
                    return bytes(x[::-1])
        return None

    m_bytes = extract_vector(M_red)

    print(f"[+] Found collision string satisfying regex: {m_bytes}")
    
    r.sendline(m_bytes)
    
    res = r.recvall(timeout=5).decode().strip()
    print("\n[+] SUCCESS! SERVER RESPONSE:")
    print("=" * 40)
    print(res)
    print("=" * 40)

if __name__ == '__main__':
    solve()
```

### Execution Output:
```text
[+] Opening connection to archive.cryptohack.org on port 9391: Done
[*] Leaking hashes to recover the secret prime p...
    [+] h(b'a') = e0cf748e999dbb1d88a5c49406444b2c8145b8c3af5a92a9e0d1ae70b306f261
    [+] h(b'b') = 62ed8827e95675027f0b096ebb0e383146e8e28900c7931373d43e0efecc5ea3
    [+] h(b'c') = c94beb94a7696877bb791211cd0266ac3787bb68bd72b392c209596f53ad76a9
    [+] h(b'd') = 814d6b268f678990908c26fc84611aa27cb2b0f608e8e99b7aeccb59b59bd384
[*] Computing GCD of relations to extract p...
[+] Successfully extracted p = 112648334221690649379877593880520592851577828580514230682187160669641186558407
[*] Running LLL reduction
[+] Found collision string satisfying regex: b'onmnnkpqqsosumjophphmmimurclpgitomplqdokosggktuohtpqtcnavtmngyskqiimlvmtkqo'
[+] Receiving all data: Done (221B)
[*] Closed connection to archive.cryptohack.org port 9391

[+] SUCCESS! SERVER RESPONSE:
========================================
h(b'onmnnkpqqsosumjophphmmimurclpgitomplqdokosggktuohtpqtcnavtmngyskqiimlvmtkqo') = a5246e713029a2394491ccdb4260402bb443003e2f8d66dbbae791a121d46ad8
Congrats! firebird{wh3n_1n_d0ub7_u5e_latt111c3_r3duc71110n_4lg0r111thm}
========================================
```

**Flag:** `firebird{wh3n_1n_d0ub7_u5e_latt111c3_r3duc71110n_4lg0r111thm}`

## 6. What We Learned
1. **Hidden Parameters are not always secure:** If an attacker can query inputs that alter the internal math in a linear or highly predictable way (like +1 increments), they can construct algebraic relations to leak hidden moduli.
2. **Algebraic Hashes have severe weaknesses:** Unlike bit-shuffling algorithms (like SHA256), a hash built on modular exponentiation inherits all properties of finite fields. This means collisions aren't found by "brute force", but by solving linear congruences.
3. **Lattice Reduction is Magic:** Constructing text-based collisions is notoriously annoying. By framing it as a bounded shortest-vector problem and throwing LLL at it, we let the math instantly find a payload that perfectly satisfies both the ASCII regex constraints and the hash modulo!