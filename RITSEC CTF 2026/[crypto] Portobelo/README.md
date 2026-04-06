# Portobelo - RITSEC CTF 2026 write up

## 1. TL;DR
The challenge presents a CSIDH/Isogeny-based key exchange protocol with a massive state leak. The server provides a custom `QUERY` command that accidentally acts as a polynomial evaluation oracle, computing $\sum sk_i \cdot A^i \pmod p$ while skipping one "poisoned" index. By querying the server 74 times (the size of the secret key), we used **Lagrange Interpolation** to perfectly reconstruct the partial key. Using another leaked variable (`ops_count`), we deduced the missing element's magnitude, brute-forced its sign and position, and successfully decrypted the AES-GCM encrypted flag. 

---

## 2. What Data/Files We Have & What is Special

We are provided with two core files: `server.py` and `params.json`.

*   **`params.json`**: Contains the cryptographic parameters. Most notably: a 518-bit prime `p`, an array of 74 `primes` (the basis for the isogeny group action), a custom polynomial/generator for the Key Derivation Function (KDF), and the AES-GCM encrypted flag (`flag_ct`, `flag_nonce`, `flag_tag`).
*   **`server.py`**: The interactive Python server handling the connections. It mimics an isogeny key exchange but implements some custom logic. 

**The Interactive TCP Server (The Player's View):**
When connecting to the server (`nc portobelo.ctf.ritsec.club 1337`), the server automatically sends the base64-encoded params and the encrypted flag. 
The player is then allowed to send up to **200** `QUERY <A>` commands, where `A` is an integer representing a Montgomery curve coefficient. 
The server replies with: `RESULT <j_invariant> <ops_count> <trace>`.

---

## 3. Problem Analysis (In Detail)

While the challenge code includes complex CSIDH mathematics (`xmul`, `velu`, `group_action`), the actual vulnerability bypasses the isogeny math entirely. 

Let's look at the `trace()` function defined in `server.py`:
```python
def trace(query_A, secret_key, primes, p, skip_index=-1):
    A_pow = 1
    trace = 0
    for i in range(len(primes)):
        if i != skip_index:
            trace = (trace + secret_key[i] * A_pow) % p
        A_pow = A_pow * query_A % p
    return trace
```
If we look at this algebraically, the `trace` function evaluates a polynomial $P(x)$ at $x = A$:
$$
P(A) = \sum_{\substack{0 \le i \le 73 \\ i \ne j}} sk_i A^i \bmod p
$$
where $j$ is the poisoned index.

**The Flaw:** 
We can query this polynomial for any $A$. The coefficients of this polynomial *are* the secret key elements $sk_i$. The degree of the polynomial is bounded by the number of primes (74 primes $\implies$ max degree 73). A polynomial of degree $N-1$ can be perfectly reconstructed using exactly $N$ points. Since the server allows 200 queries, we have more than enough attempts to grab 74 points and use **Lagrange Interpolation** over $GF(p)$ to recover the coefficients!

**The "Poisoned Index" & Ops Count:**
The server intentionally skips one index (`skip_index`). When we interpolate the polynomial, the coefficient at this index will evaluate to `0`. However, the server also leaks `ops_count` during every query.
```python
params["ops_count"] = sum(abs(e) for e in params["secret_key"])
```
This tells us the sum of the absolute values of *all* elements in the complete secret key. By computing the sum of the partial key we recovered, the difference will give us the exact magnitude (absolute value) of the missing skipped element!

---

## 4. Initial Guesses / First Try

**Distraction via Group Actions:** 
At first glance, one might think this requires calculating group actions, factoring isogenies, or analyzing the $j$-invariant. But once you notice the `trace` variable is doing a basic power sum $\pmod p$, it becomes obvious that it's a simple algebraic state-leak. 

**The SageMath Preparser Gotcha:**
My first attempt successfully interpolated the polynomial and generated the right secret keys. However, the script crashed at the very end when generating the AES key:
```python
ValueError: bytes must be in range(0, 256)
```
Why? In `server.py` (standard Python), the KDF uses `a ^ b` for bitwise XOR. But in a `.sage` script, the SageMath preparser converts the caret `^` into exponentiation (`**`). Thus, `bytes(a ^ b...)` was trying to exponentiate the bytes, resulting in massive numbers. 

**The Fix:** I replaced the `^` with `operator.xor(a, b)` (or Sage's native `^^`) to safely bypass the preparser.

---

## 5. Exploitation Walkthrough / Flag Recovery

Here is the exact step-by-step strategy used in the exploit script:

1.  **Gather the points:** Loop 74 times, sending `QUERY X` (using $X = 3 \dots 76$ to avoid singular curves like $A=2$). Record the returned `trace` and `ops_count`.
2.  **Lagrange Interpolation:** Use SageMath's `PolynomialRing(GF(p), 'x').lagrange_polynomial()` to reconstruct $P(x)$ using our 74 coordinate pairs.
3.  **Recover Partial Key:** Extract the polynomial coefficients. Because CSIDH keys use small signed integers ($\pm$), map any large coefficient $c > p/2$ back to negative via $c - p$.
4.  **Find the Missing Element:** 
    *   $S_{\mathrm{partial}} = \sum |sk_{\mathrm{partial}}|$
    *   $m_{\mathrm{missing}} = \mathrm{opsCount} - S_{\mathrm{partial}}$
5.  **Brute Force:** We know the magnitude, but we don't know *where* it goes (which index was skipped) or its sign (positive or negative). We simply loop through all indices where our interpolated coefficient was `0`, inject $\pm \text{Missing Magnitude}$, and try to decrypt the AES-GCM flag.

**Execution Result:**
```text
$ python3 solve.py
[*] Connecting to portobelo.ctf.ritsec.club:1337...
[*] Parameters extracted. p is 518 bits, 74 primes.
[*] Gathering 74 trace evaluations...
[*] Lagrange interpolating polynomial over GF(p)...
[*] Partial Ops Sum: 86 | Server Leak Total: 89
[*] Target magnitude for the poisoned index: 3
[*] Testing 62 Candidate Keys against AES-GCM Tag...

[+] 🎯 SUCCESS! Flag found: RS{504_1s_7smo0th_s0_th3_0rb1t_h4s_n1n3}
[+] Poisoned index was identified as: 73
```

---

## 6. What We Learned

1.  **Don't Fear the Math (Or Get Distracted by It):** The challenge was heavily wrapped in complex post-quantum isogeny logic (Velu's formulas, Montgomery arithmetic). However, the vulnerability was simply identifying an insecure side-channel/debugging logic (`trace`) and exploiting it via high-school algebra (polynomial interpolation). 
2.  **Lagrange Interpolation is Powerful:** Whenever a remote service evaluates a secret sequence against a dynamic, attacker-controlled base, it represents a polynomial evaluation. Lagrange over a Finite Field is incredibly fast and precise for breaking this.
3.  **SageMath vs. Python Syntax:** Always be cautious when porting standard Python cryptographic implementations into `.sage` environments. The preparser's interpretation of `^` as exponentiation instead of `XOR` is a classic CTF pitfall that causes silent logic bugs or crashes!