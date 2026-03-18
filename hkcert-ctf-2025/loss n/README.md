# HKCERT CTF 2025 - Loss N Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *Description: 沒有那個n，我照樣可以解出flag。 Even without that n, I can still solve the flag.*

## TL;DR
We are given the RSA decryption exponent $d$, encryption exponent $e$, and ciphertext $c$, but the modulus $N$ is missing.
1.  Exploit the RSA definition $e \cdot d = k \cdot \phi(N) + 1$ to brute-force the integer $k$ (where $1 \le k \le e$).
2.  Recover candidates for Euler's totient $\phi(N)$.
3.  Use the code's specific prime generation logic ($q = \text{next\_prime}(p)$) to deduce that $p \approx \sqrt{\phi(N)}$.
4.  Find $p$ by checking primes near $\sqrt{\phi(N)}$, reconstruct $N$, and decrypt the flag.

---

## Challenge Analysis

We are provided with a Python script and the output values for `c` and `d`.
**Source Code Analysis:**
```python
p = getPrime(512)
q = next_prime(p)     # <--- CRITICAL VULNERABILITY
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
```

**Key Observations:**
1.  **Missing Modulus:** We have $c, d, e$, but **no $N$**. Standard RSA tools (`rsactftool`) require $N$ or $p, q$.
2.  **Close Primes:** The code generates a 512-bit prime $p$, and immediately sets $q$ as the **next prime** after $p$. This means $p$ and $q$ are extremely close to each other ($|p - q|$ is very small).
3.  **Known $d$:** The private exponent is leaked.

---

## The Math (Step-by-Step)

### Step 1: Recovering $\phi(N)$
The fundamental definition of the RSA private key $d$ is the modular multiplicative inverse of $e$ modulo $\phi(N)$.
$$e \cdot d \equiv 1 \pmod{\phi(N)}$$
This can be rewritten as an equality over integers:
$$e \cdot d - 1 = k \cdot \phi(N)$$
Where $k$ is some integer.

Since $d < \phi(N)$ (by definition of modular inverse) and $e \cdot d \approx k \cdot \phi(N)$, we can estimate the size of $k$:
$$k = \frac{e \cdot d - 1}{\phi(N)} < e$$
Since $e = 65537$, the value of $k$ is relatively small ($1 \le k \le 65537$). We can easily **brute-force $k$**.

For every guess of $k$, we compute a candidate $\phi(N)$:
$$\phi_{cand} = \frac{e \cdot d - 1}{k}$$
(We only keep candidates where the division is exact).

### Step 2: Recovering $p$ and $q$ from $\phi(N)$
We know that:
$$\phi(N) = (p-1)(q-1) = pq - p - q + 1$$
Usually, factoring $\phi(N)$ is hard. However, the challenge constrains $q$ to be the `next_prime(p)`.
This implies $p \approx q$.
Therefore:
$$\phi(N) \approx p \cdot p \approx p^2$$
$$p \approx \sqrt{\phi(N)}$$

We can calculate the integer square root of our candidate $\phi(N)$. The real prime $p$ will be very close to this value.

### Step 3: Verification
For each candidate $p$ (found near $\sqrt{\phi_{cand}}$):
1.  Generate $q' = \text{next\_prime}(p)$.
2.  Check if $(p-1)(q'-1)$ equals our derived $\phi_{cand}$.
3.  If it matches, we have found the correct primes. We can now compute $N = p \cdot q'$ and decrypt $c$.

---

## The Solver Script

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

# Challenge Data
c = 30552929401084215063034197070424966877689134223841680278066312021587156531434892071537248907148790681466909308002649311844930826894649057192897551604881567331228562746768127186156752480882861591425570984214512121877203049350274961809052094232973854447555218322854092207716140975220436244578363062339274396240
d = 3888417341667647293339167810040888618410868462692524178646833996133379799018296328981354111017698785761492613305545720642074067943460789584401752506651064806409949068192314121154109956133705154002323898970515811126124590603285289442456305377146471883469053362010452897987327106754665010419125216504717347373
e = 0x10001

# Calculate the numerator for the phi equation
X = e * d - 1

print("[*] Brute-forcing k to recover phi(N)...")

# k must be roughly the size of e or smaller
for k in range(1, e + 1):
    if X % k == 0:
        phi_cand = X // k
        
        # Estimate p as sqrt(phi)
        p_approx = gmpy2.isqrt(phi_cand)
        
        # Search for p near the approximation.
        # Since q > p, (p-1)(q-1) > (p-1)^2, so sqrt(phi) > p-1.
        # This suggests p is slightly smaller than isqrt(phi).
        
        p_curr = p_approx
        
        # Check a few integers downwards
        for _ in range(10): 
            # Find the nearest prime <= p_curr
            while not gmpy2.is_prime(p_curr):
                p_curr -= 1
            
            p = int(p_curr)
            
            # Recreate the challenge logic
            q = int(gmpy2.next_prime(p))
            
            # Check if these primes match our candidate phi
            if (p - 1) * (q - 1) == phi_cand:
                print(f"[+] Found valid parameters at k={k}")
                print(f"    p: {p}")
                print(f"    q: {q}")
                
                # Reconstruct N
                n = p * q
                
                # Decrypt
                m = pow(c, d, n)
                try:
                    flag = long_to_bytes(m).decode()
                    print(f"\n[SUCCESS] FLAG: {flag}")
                    exit()
                except:
                    pass
            
            p_curr -= 1
```

## Execution Output

```text
[*] Brute-forcing k to recover phi(N)...
[+] Found valid parameters at k=3201
    p: 8922506587925927021529806484699222261112802496828489475122717712027885598469464326598661719636053156680705716899915060678486654755882620413015804223061611
    q: 8922506587925927021529806484699222261112802496828489475122717712027885598469464326598661719636053156680705716899915060678486654755882620413015804223061631

[SUCCESS] FLAG: flag{Y0u_kNow_h0w_7o_f4cTor1z3_phI}
```

**Flag:** `flag{Y0u_kNow_h0w_7o_f4cTor1z3_phI}`