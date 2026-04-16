# 1337crypt - DownUnderCTF 2020 Writeup
**Description:** "Can you solve my factorisation problem if I give you a hint?" 

## 1. TL;DR
The challenge leaks an approximation of $\sqrt{p} + \sqrt{q}$. By squaring this approximation, we can estimate the sum of the primes $p+q$ with enough precision to recover over half of the Most Significant Bits (MSBs) of $p$. We then use **Coppersmith's Method** via SageMath's `.small_roots()` to recover the exact prime $p$. Finally, the flag is decrypted bit-by-bit by evaluating the Legendre symbol of each ciphertext modulo $p$.

## 2. What data/file we have and what is special
We are provided with a SageMath script (`1337crypt.sage`) and its output text file (`output.txt`). 

**Special characteristics of the data:**
* **1337-bit Primes:** $p$ and $q$ are exactly 1337 bits long, making $n$ a 2674-bit RSA modulus.
* **The Hint:** We are given $D = 63^{14}$ and a truncated hint: `hint` $= \lfloor D(\sqrt{p} + \sqrt{q}) \rfloor$.
* **The Encryption:** The flag is encrypted bit-by-bit into an array $c$. 
  * A special base $x$ is chosen such that its Legendre symbol modulo $p$ and $q$ is strictly $-1$ (quadratic non-residue).
  * Each bit $b \in \{0, 1\}$ is encrypted as $c = x^{1337 + b} \cdot r^{2674} \pmod n$, where $r$ is a random padding integer.

## 3. Problem Analysis (in detail)

This challenge consists of two phases: **Factorizing $n$** and **Decrypting the ciphertexts**.

### Phase 1: Factorization via the Hint
We know that:
$$ \text{hint} = \lfloor D(\sqrt{p} + \sqrt{q}) \rfloor $$

We can remove the floor function by acknowledging a small truncation error $\epsilon \in[0, 1)$:
$$ \frac{\text{hint}}{D} = \sqrt{p} + \sqrt{q} - \frac{\epsilon}{D} $$

Squaring both sides gives us an approximation for the sum of the primes, $S = p + q$:
$$ \left(\frac{\text{hint}}{D}\right)^2 \approx (\sqrt{p} + \sqrt{q})^2 = p + q + 2\sqrt{n} $$
$$ \implies p + q \approx \left(\frac{\text{hint}}{D}\right)^2 - 2\sqrt{n} $$

Let our approximation be $S_{approx} = (\frac{\text{hint}}{D})^2 - 2\sqrt{n}$. The error here is roughly bounded by $\approx \frac{2 n^{1/4}}{D}$. Given that $n$ is 2674 bits, $n^{1/4} \approx 2^{668}$. Since $D \approx 2^{83}$, our error in $S_{approx}$ is around $2^{585}$. 
Since $p$ is a root of the polynomial $X^2 - SX + n = 0$, we can approximate $p$ using the quadratic formula:
$$ p_{approx} = \frac{S_{approx} + \sqrt{S_{approx}^2 - 4n}}{2} $$
Because the error is at most $2^{585}$, we know $p_{approx}$ shares at least $1337 - 585 = 752$ MSBs with the real $p$. Since $752 \ge \frac{1337}{2}$ (we know more than half of the bits), we can easily recover the rest using **Coppersmith's Method**.

### Phase 2: Bit-by-bit Decryption
The encryption is a variation of the Goldwasser-Micali cryptosystem. Let's look at the ciphertext modulo $p$:
$$ c \equiv x^{1337 + b} \cdot r^{2674} \pmod p $$

Notice that $2674$ is an even number. This means $r^{2674} = (r^{1337})^2$, making it a perfect square (Quadratic Residue) modulo $p$. Its Legendre symbol is always $1$.
Now we evaluate the Legendre symbol of $c$ modulo $p$:
$$ \left(\frac{c}{p}\right) = \left(\frac{x}{p}\right)^{1337 + b} \cdot \left(\frac{r^{2674}}{p}\right) = (-1)^{1337 + b} \cdot 1 $$
* If $b = 0$, then $1337 + 0 = 1337$ (odd). So, $\left(\frac{c}{p}\right) = (-1)^{\text{odd}} = -1$.
* If $b = 1$, then $1337 + 1 = 1338$ (even). So, $\left(\frac{c}{p}\right) = (-1)^{\text{even}} = 1$.

We can map the bits directly using the Legendre symbol!

## 4. Initial Guesses/First Try
An initial naive thought might be to treat $H = D(\sqrt{p} + \sqrt{q})$ as an exact equation, isolate $p$ and $q$, and solve algebraically. However, because the server uses `int()` (which truncates the decimal part, basically acting as a floor function), a direct algebraic solver will fail due to the missing fractional precision. 

Instead of treating it as an exact equation, we MUST treat it as a bounds/approximation problem. Realizing that the approximation guarantees over 50% of the bits of $p$ immediately signals that a lattice-based approach (Coppersmith) is the intended path.

## 5. Exploitation Walkthrough/Flag Recovery

Here is the SageMath script used to perform the Coppersmith attack and recover the flag. We use `RealField(4000)` to ensure floating-point truncation doesn't corrupt our $S_{approx}$ calculation.

```sage
from Crypto.Util.number import long_to_bytes
import ast

def solve():
    print("[*] Reading data from output.txt ...")
    with open('output.txt', 'r') as f:
        lines = f.read().strip().split('\n')
        
    hint = int(lines[0].split('=')[1].strip())
    D = int(lines[1].split('=')[1].strip())
    n = int(lines[2].split('=')[1].strip())
    c = ast.literal_eval(lines[3].split('=', 1)[1].strip())
    
    # 4000 bits of precision to maintain integrity over 2674-bit numbers
    R_prec = RealField(4000)
    hint_R = R_prec(hint)
    D_R = R_prec(D)
    n_R = R_prec(n)
    
    print("[*] Approximating the sum of primes (s0) and largest prime (p0)...")
    s_approx = (hint_R / D_R)^2 - 2 * n_R.sqrt()
    s0 = s_approx.round()
    
    p0_R = (R_prec(s0) + (R_prec(s0)^2 - 4*n_R).sqrt()) / 2
    p0 = p0_R.round()
    
    print(f"[*] p0 approximation calculated.")
    
    # Coppersmith's Method setup
    PR.<x> = PolynomialRing(Zmod(n))
    f = x + int(p0)
    
    print("[*] Running small_roots to recover p...")
    roots = f.small_roots(X=2^610, beta=0.5, epsilon=0.02)
        
    if not roots:
        print("[-] small_roots failed.")
        return
        
    x0 = roots[0]
    p = int(p0 + x0)
    
    if n % p != 0:
        print("[-] Recovered root does not cleanly divide n.")
        return
        
    print(f"[+] Successfully factored n!")
    
    print("[*] Decrypting GM-like ciphertexts leveraging the Legendre Symbol...")
    flag_bits = ''
    for ct in c:
        # Evaluate the Legendre Symbol using kronecker
        lp = kronecker(ct, p)
        if lp == -1:
            flag_bits += '0'
        elif lp == 1:
            flag_bits += '1'
            
    print(f"[*] Recovered flag bits: {flag_bits}")
    flag = long_to_bytes(int(flag_bits, 2))
    print(f"\n[+] 🎯 Flag: {flag.decode('utf-8', errors='ignore')}")

if __name__ == '__main__':
    solve()
```

### Execution Output:
```text
[*] Reading data from output.txt ...
[*] Approximating the sum of primes (s0) and largest prime (p0)...
[*] p0 approximation calculated.
[*] Running small_roots to recover p...
[+] Successfully factored n!
[*] Decrypting GM-like ciphertexts leveraging the Legendre Symbol...
[*] Recovered flag bits: 10001000101010101000011010101000...
[+] 🎯 Flag: DUCTF{wh0_N33ds_pr3cIsi0n_wh3n_y0u_h4v3_c0pp3rsmiths_M3thod}
```

## 6. What We Learned
* **Floating-Point Precision matters in Math CTFs:** When computing intermediate values (like square roots of 2674-bit numbers), standard Python floats drop precision. Leveraging SageMath's `RealField(4000)` ensures no bits are accidentally truncated before handing the equation to Coppersmith.
* **The Power of Coppersmith:** As long as we know $> 50\%$ of a prime factor's bits, Coppersmith's algorithm (`small_roots`) can reliably bridge the gap to full factorization.
* **Legendre Symbol as a Decryptor:** By deliberately pairing an exponent with odd/even offsets and applying square padding ($r^{\text{even}}$), the Legendre Symbol can easily leak isolated encrypted bits, similar to Goldwasser-Micali logic.