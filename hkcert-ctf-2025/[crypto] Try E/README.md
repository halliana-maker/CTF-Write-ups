# HKCERT CTF 2025 - Try E Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *e這麼大...何意味？ E is so big... what does it mean?*

## TL;DR
The challenge implements RSA but explicitly generates a **small private exponent ($d$)** of only 256 bits, while the modulus ($N$) is 2048 bits. This vulnerability allows us to recover the private key using **Wiener's Attack**, which exploits the relationship between $e/N$ and $k/d$ using continued fractions.

---

## 1. Reconnaissance & Analysis

We are given the source code `chall.py` and the output parameters ($N, e, c$). Let's look at the key generation logic:

```python
def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    phi = (p - 1) * (q - 1)
    while True:
        d = getPrime(256)          # <--- VULNERABILITY HERE
        e = pow(d, -1, phi)
        if e.bit_length() == N.bit_length():
            break
    return N,e
```

### The Anomaly
Standard RSA requires $d$ to be roughly the same size as $N$ (2048 bits) to be secure. Here, the code explicitly forces $d$ to be a 256-bit prime.
*   **Modulus ($N$):** ~2048 bits
*   **Private Exponent ($d$):** 256 bits
*   **Public Exponent ($e$):** Very large (~2048 bits)

This massive $e$ is the hint ("E is so big... what does it mean?"). When $e$ is huge because $d$ is small, we should immediately think of **Wiener's Attack**.

---

## 2. Theory: Wiener's Attack

Michael Wiener proved that if the private exponent $d$ is sufficiently small, specifically:
$$ d < \frac{1}{3} N^{1/4} $$
then $d$ can be efficiently recovered from the public key $(N, e)$.

### The Math
We know the core RSA equation:
$$ ed \equiv 1 \pmod{\phi(N)} $$
$$ ed - k\phi(N) = 1 $$
where $k$ is some integer.

Dividing by $d\phi(N)$:
$$ \frac{e}{\phi(N)} - \frac{k}{d} = \frac{1}{d\phi(N)} $$

Since $N \approx \phi(N)$, we can approximate:
$$ \left| \frac{e}{N} - \frac{k}{d} \right| \approx \frac{1}{d N} $$

Because $d$ is small, this difference is tiny. A theorem in number theory states that if $|x - \frac{a}{b}| < \frac{1}{2b^2}$, then $\frac{a}{b}$ is a **convergent** of the continued fraction expansion of $x$.

**Strategy:**
1.  Compute the continued fraction expansion of $\frac{e}{N}$.
2.  Iterate through the convergents. Each convergent gives us a candidate fraction $\frac{k}{d}$.
3.  Test if the denominator $d$ is the correct private key (by checking if it factors $N$ or successfully decrypts the message).

### Checking Constraints
*   $N \approx 2^{2048}$
*   $N^{1/4} \approx 2^{512}$
*   Our $d$ is 256 bits.
Since $256 < 512$, the condition holds, and the attack is guaranteed to succeed.

---

## 3. Solution Script

We used SageMath because it handles continued fractions natively and efficiently.

**Solver:** `solve.sage`
```python
#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.number import long_to_bytes

# Challenge Parameters
N = 0x662854e5ee8b1aa73eea7c897f0f1bd7cace486dea68fb4e9b1affe86ddae225221e9941b7e90b7dd87d57988fc3428f51433a5c2a6e7ef9cbe85aace0925914347ca1d403ea58e2f36435b67648f8caf0abd29c9c24d3caeadab2c41522deda75c19584ec917fa683ff16c932f334db3145a8367c3dc6bc3b918ff3f69f8bfb16c45b4caab1e8ecef24e8e923e984e921115d9fb997a638c8e25d74d592f279359e7147745a7a8443603287120d1a186f30d5a41ce26545f85844721b788564e306791ae39c3be23aeeab010e79302afab4b3e9ab18cb2769382ff8fcbc0514f51861ec6db247f0a0343b7cc6d44299878f7006c118df10de6937c11e3aed7d
e = 0x58a2680eae331e41397475dd699a75f242897e4ed4048338137eb40100cc406b651c4518f4057ad8419cd6a82605113dd5801cd9f022f8bda424b02db5feb333d96636026c3ffc4cab74f7426aa14fb1139663a4f6248dd8e5c7075fcdf3e520c425697775cfb65d33ccca5ffe08d944753b1e9da2dbf96713ece5436deb6dbc843dcd5c497eda9919e055a32c76798770535c6a91ae00b971f35be1ab9e48dd4c701026e0744826001f6fb30e4f68d6e4981aa5a5bbcc995a9e46a4d9b1658348d0fb3b1314fa091251ea1b7379a854a3860fcba2ace323dca8157008d80d6035fd6c880404495f933bf4b4ae829b35823450a921f64b9cf63ae861b3fc4ef7
c = 0x47d2e297294af43a9a02d465f7f5272cab0af2445cbc6022def1098e075dcfb3a7830f09df6112a9fa55b34ed4d0baebad54ea2cbd32e4367cbe7a138409a0ef4c36d837ea7817ec3624fca3a19c1377eaf08e4a519de73cb2c5e99ec8f3998e04d4c3bc44a6f1eb389111bf7c72c68bf1dd743e656467d1ecdd314b37313963758634b83ea96724b1872367a922788f2c8a046c76ccc57e86686bedd7ac431f92b9e2f1fae79701fa0d14d2a0119860c8908336c6caec87b9733f626166373631e1e7e9ba6be92d712e84e821e0e4dc105d460c6640498aefaeb5146d0f57b8e57c3e24bc13f3e79082172c1690428eb49bc6035f1e60f6a579129a2da00c60

def wiener_attack(e, n):
    # 1. Expand e/N into continued fractions
    f = continued_fraction(Integer(e) / Integer(n))
    print(f"[*] Computed continued fraction with {len(f.convergents())} convergents.")
    
    # 2. Iterate over convergents k/d
    for c_frac in f.convergents():
        k = c_frac.numerator()
        d = c_frac.denominator()
        
        if k == 0: continue
        
        # 3. Check if d is valid
        # We check if (ed-1) is divisible by k to find phi
        if (e * d - 1) % k != 0:
            continue
            
        phi = (e * d - 1) // k
        
        # Verify roots of quadratic: x^2 - (N - phi + 1)x + N = 0
        s = N - phi + 1
        delta = s*s - 4*N
        
        if delta >= 0 and delta.is_square():
            print(f"[*] Status: Found d = {d}")
            return d
    return None

print(f"[*] Status: Analyzing N={hex(N)[:20]}...")
d = wiener_attack(e, N)

if d:
    m = pow(c, d, N)
    flag = long_to_bytes(int(m)).decode()
    print(f"[*] FLAG: {flag}")
```

---

## 4. Execution & Result

Running the script quickly identified the correct private exponent:

```text
[*] Status: Analyzing N=0x662854e5ee8b1aa73e...
[*] Computed continued fraction with 906 convergents.
[*] Status: Found d = 76516802127572529241860569119773645337201291188788443592272413818606050201799
[*] FLAG: flag{Y0u_kNoW_C0n7lNu3d_Fr4c71on!}
```

The flag confirms the use of continued fractions.

**Flag:** `flag{Y0u_kNoW_C0n7lNu3d_Fr4c71on!}`