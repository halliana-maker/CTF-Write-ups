# HKCERT CTF 2025 - Bivariate copper Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *那麼問題來了，什麼是copper？ So the question is, what is copper?*

---

## TL;DR
The modulus $N$ has a trivially small prime factor ($q \approx 25$ bits), allowing us to recover the large prime factor $p$. The challenge provides two leaked values ($t_1, t_2$) related to the message $m$, but with their lower 244 bits truncated. By algebraically eliminating $m$, we derive a bivariate polynomial $f(x, y) \equiv 0 \pmod p$. Since the unknown bits are small relative to $p$, we use a **Bivariate Coppersmith Attack** (via lattice reduction) to recover the missing bits and decrypt the flag.

---

## 1. Reconnaissance & Code Analysis

We are given a Python script and output parameters ($N, e, c, k, r_1, r_2, \text{leaks}$).

### Key Observations:
1.  **Parameter Generation:**
    ```python
    p = getPrime(1024)
    q = getPrime(25)  # <--- VULNERABILITY #1
    N = p * q
    ```
    The prime $q$ is extremely small (25 bits). This means $N$ can be factored instantly.

2.  **The Equations:**
    The challenge computes two values $t_1, t_2$ modulo $p$ (not $N$):
    ```python
    t1 = (k * inverse(m + r1, p)) % p
    t2 = (k * inverse(m + r2, p)) % p
    ```
    Rearranging these, we get:
    $$ t_1 (m + r_1) \equiv k \pmod p $$
    $$ t_2 (m + r_2) \equiv k \pmod p $$

3.  **The Leak:**
    ```python
    leak1 = t1 >> 244
    leak2 = t2 >> 244
    ```
    We are given the *high bits* of $t_1$ and $t_2$. The lower 244 bits are unknown.

---

## 2. Deriving the Attack

### Step 1: Factorization
Since $q$ is only 25 bits ($q < 2^{25} \approx 3.3 \times 10^7$), we can find it by simple trial division or using a tool like `factordb` (though it's generated fresh, it's small enough to brute-force locally in seconds).

Once we have $q$, we compute:
$$ p = N // q $$

### Step 2: Equation Manipulation
We have two equations with one unknown we care about ($m$) and two unknowns we want to find (the lower bits of $t_1, t_2$). Let's eliminate $m$.

From the provided code:
$$ m \equiv k \cdot t_1^{-1} - r_1 \pmod p $$
$$ m \equiv k \cdot t_2^{-1} - r_2 \pmod p $$

Equating the two expressions for $m$:
$$ k \cdot t_1^{-1} - r_1 \equiv k \cdot t_2^{-1} - r_2 \pmod p $$

Multiply by $t_1 t_2$ to clear the modular inverses:
$$ k \cdot t_2 - r_1 \cdot t_1 t_2 \equiv k \cdot t_1 - r_2 \cdot t_1 t_2 \pmod p $$

Group terms:
$$ k(t_2 - t_1) + t_1 t_2 (r_2 - r_1) \equiv 0 \pmod p $$

Let $\Delta r = r_1 - r_2$. The equation becomes:
$$ k(t_2 - t_1) - \Delta r \cdot t_1 t_2 \equiv 0 \pmod p $$

### Step 3: Polynomial Construction
We know the high bits of $t_1$ and $t_2$. Let:
*   $A_1 = \text{leak}_1 \ll 244$
*   $A_2 = \text{leak}_2 \ll 244$
*   $x, y$ be the unknown lower 244 bits.

Then:
$$ t_1 = A_1 + x $$
$$ t_2 = A_2 + y $$

Substitute these into our derived equation:
$$ k((A_2+y) - (A_1+x)) - \Delta r(A_1+x)(A_2+y) \equiv 0 \pmod p $$

This expands to a bivariate polynomial $f(x, y)$ of degree $(1,1)$:
$$ f(x, y) = -\Delta r \cdot xy + (\dots)x + (\dots)y + C \equiv 0 \pmod p $$

### Step 4: Coppersmith's Method
We need to find roots $(x, y)$ such that $|x|, |y| < 2^{244}$.
The modulus $p$ is $\approx 1024$ bits.
Coppersmith's heuristic generally works if the product of the unknowns is less than $p^{1/d}$ (roughly).
Here, $X \cdot Y \approx 2^{488}$, which is well below $p \approx 2^{1024}$.

We can use the `small_roots` function provided by standard CTF tools like **[defund/coppersmith](https://github.com/defund/coppersmith)**.

---

## 3. Solution Script

We used SageMath to implement the attack.

```python
#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.number import long_to_bytes, inverse

# Import/Paste small_roots from https://github.com/defund/coppersmith here
# (Omitted for brevity, see repo for implementation)

def solve():
    # --- 1. Load Data ---
    N = 333357... # (Full value in challenge)
    leak1 = 42662...
    leak2 = 11769...
    # ... (other constants k, r1, r2) ...

    # --- 2. Trivial Factorization ---
    # q is approx 25 bits. We found it easily:
    q = 23520857
    p = N // q
    
    # --- 3. Setup Polynomial ---
    P = PolynomialRing(Zmod(p), names=['x', 'y'])
    x, y = P.gens()

    A1 = leak1 << 244
    A2 = leak2 << 244
    dr = r1 - r2
    
    # Equation: k(t2 - t1) - dr*t1*t2 = 0
    # Substitute t1 = A1+x, t2 = A2+y
    f = k*((A2+y) - (A1+x)) - dr*(A1+x)*(A2+y)
    
    # --- 4. Run Coppersmith ---
    bounds = (2**244, 2**244)
    print("[*] Running small_roots...")
    
    # m=2, d=4 provides a good trade-off between speed and lattice dimension
    roots = small_roots(f, bounds, m=2, d=4)
    
    for delta1, delta2 in roots:
        # Recover full t1
        t1_recovered = int(A1 + delta1)
        
        # Recover message m
        # m = k * t1^-1 - r1 (mod p)
        m_val = (k * inverse(t1_recovered, int(p)) - r1) % p
        
        flag = long_to_bytes(int(m_val))
        if b"flag{" in flag:
            print(f"\n[+] FLAG: {flag.decode()}")

solve()
```

## 4. Result

Running the script recovers the roots almost instantly:
`[*] Roots found: [(26935...04, 35087...53)]`

Which decodes to the flag:
**`flag{H4hAHhhHh4_c0pP3r_N07_v1OI3n7_3n0uGh}`**

---

## References & Tools
*   **SageMath:** Essential for lattice reductions.
*   **defund/coppersmith:** A widely used Sage script for finding small roots of multivariate polynomials. [GitHub Link](https://github.com/defund/coppersmith).
*   **FactorDB:** Useful for checking if N is already factored (though unnecessary here due to small $q$).
