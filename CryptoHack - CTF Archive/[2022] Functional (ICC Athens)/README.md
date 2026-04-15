# Functional - ICC Athens 2022 Writeup

**Description:** "It only took me four heat deaths of the universe to encrypt this flag.

---

## 1. TL;DR
The challenge involves breaking three distinct stages of highly complex, mathematically layered linear recurrences to decrypt an AES-ECB encrypted flag.
1. **Stage 1 (`ITERS` Recovery):** Use the Berlekamp-Massey algorithm to find the minimal polynomial of sequence `f`. By exploiting a repeated root in the polynomial, we use an algebraic derivative trick to instantly compute the discrete logarithm and recover the massive `ITERS` value ($~7.9 \times 10^{40}$).
2. **Stage 2 (Coupled Recurrences):** Sequences `g, h, i` are mutually recursive with polynomial additions. We model this as a $17 \times 17$ transition matrix and use binary matrix exponentiation to jump directly to the `ITERS` state.
3. **Stage 3 (Massive Recurrence):** Sequence `j` is a linear recurrence of degree $10,000$. Instead of a $10000 \times 10000$ matrix, we compute $x^{ITERS} \pmod{P_j(x)}$ in a polynomial quotient ring to reconstruct the final AES key.

---

## 2. What Data/File We Have and What is Special
We are provided with a SageMath script (`functional.sage`) and its output (`output.txt`). 

**What is special:**
* **No interactive server:** It's an offline cryptography/math puzzle. 
* **Extreme Complexity:** The script simulates $13^{37} \approx 1.8 \times 10^{41}$ iterations. Naively running the script would take "four heat deaths of the universe".
* **Math Heavy:** Everything relies on Finite Fields $GF(2^{142}-111)$, linear algebra, and polynomial quotient rings.

---

## 3. Problem Analysis (In Details)

### Stage 1: `f(n)`
```python
def f(n):
    if n < len(COEFFS):
        return F(int(10000*np.sin(n)))
    return COEFFS.dot(list(map(f, n - 1 - np.arange(len(COEFFS)))))
```
This is a standard homogeneous linear recurrence. The script provides 500 consecutive values starting from an unknown index `ITERS`. Because `f(n)` is a linear recurrence, we can find its minimal polynomial $P(x)$ using Berlekamp-Massey.

### Stage 2: `g(n)`, `h(n)`, `i(n)`
These sequences are mutually recursive (they depend on each other's past values) and *inhomogeneous* (they add constants and polynomials like $2n^3 + 42$ and $n$). To find `S3` (which contains 1337 values of `i` starting at `ITERS`), we must calculate $10^{40}$ steps.

### Stage 3: `j(n)`
```python
def j(n):
    if n < 10^4: ...
    return np.array([...]).dot(list(map(j, n - 10^4 + 100 - np.arange(100))))
```
This is a recurrence of depth $10,000$, where the next value depends on $100$ specific values from up to $10,000$ steps ago. The output $j(ITERS)$ is used as the SHA256 seed for the AES decryption key.

---

## 4. Initial Guesses / First Try
Our first thought for Stage 1 is to use Berlekamp-Massey to find the recurrence polynomial $P(x)$. From the 500 terms, we can build a Hankel matrix, solve for $A(x) = x^{ITERS} \pmod{P(x)}$, and then use a standard Baby-Step Giant-Step (BSGS) or Discrete Log (Pohlig-Hellman) algorithm to find `ITERS`. 

However, standard discrete log on the polynomial quotient ring fails or hangs because the group order isn't entirely smooth. But, analyzing the roots of $P(x)$ reveals a **repeated root**, which leads to a massive algebraic shortcut.

---

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: The Derivative Trick for `ITERS`
We find $P(x)$ has degree 20. When factoring $P(x)$, we find a root $r$ with a multiplicity $> 1$.
If a polynomial has a repeated root $r$, it means $P(r) = 0$ and $P'(r) = 0$.
Since $A(x) \equiv x^{ITERS} \pmod{P(x)}$, we can write:
$x^{ITERS} = Q(x)P(x) + A(x)$

Taking the derivative of both sides:
$ITERS \cdot x^{ITERS-1} = Q'(x)P(x) + Q(x)P'(x) + A'(x)$

Evaluating at the root $x = r$:
$ITERS \cdot r^{ITERS-1} = 0 + 0 + A'(r)$

We also know $A(r) = r^{ITERS}$. Dividing the derivative by the original gives:
$\frac{A'(r)}{A(r)} = \frac{ITERS \cdot r^{ITERS-1}}{r^{ITERS}} = \frac{ITERS}{r}$

Thus, $ITERS = r \cdot \frac{A'(r)}{A(r)}$. This allows us to extract `ITERS` instantly, avoiding the discrete logarithm entirely!

### Step 2: Transition Matrix for `S3`
To jump $ITERS$ steps for `g`, `h`, and `i`, we combine them into a single $17 \times 17$ state vector:
$V_n =[g_n..g_{n-5}, h_n..h_{n-3}, i_n..i_{n-2}, n^3, n^2, n, 1]^T$
We manually map out the dependencies to create a transformation matrix $M$ such that $V_{n+1} = M \times V_n$.
By calculating $M^{ITERS-5} \pmod{F}$, we fast-forward to the exact state.

### Step 3: Polynomial Quotient Ring for `j`
A $10000 \times 10000$ matrix exponentiation is too slow. Instead, the sequence can be expressed natively as a polynomial modulo $P_j(x) = x^{10000} - \sum C_k x^{100-k}$.
We compute $x^{ITERS} \pmod{P_j(x)}$ using Python's native fast binary exponentiation. The resulting polynomial coefficients perfectly map to the linear combination of the first 10,000 base cases of `j`. 

### The Solver Script
```python
import ast
import numpy as np
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.matrix.berlekamp_massey import berlekamp_massey

def solve():
    print("[*] Progress: Reading inputs from file...")
    with open("output.txt", "r") as f:
        lines = f.read().splitlines()
    S1_raw = ast.literal_eval(lines[2])
    enc_hex = lines[-1].strip()

    F = GF(2**142 - 111)
    S1 =[F(x) for x in S1_raw]

    # STAGE 1: Berlekamp-Massey & Derivative Trick
    print("[*] Progress: Finding minimal polynomial via Berlekamp-Massey...")
    poly = berlekamp_massey(S1)
    L = poly.degree()
    
    f_base =[F(int(10000 * np.sin(n))) for n in range(L)]
    coeffs = poly.list()
    c = [-x / coeffs[-1] for x in coeffs[:-1]]
    for n in range(L, 2*L):
        f_base.append(sum(c[k] * f_base[n - L + k] for k in range(L)))

    W = matrix(F, L, L)
    for i in range(L):
        for j in range(L): W[i, j] = f_base[i + j]

    a_vec = W.solve_right(vector(F, S1[:L]))
    R_poly = PolynomialRing(F, 'x')
    x = R_poly.gen()
    A_poly = sum(a_vec[k] * x**k for k in range(L))

    print("[*] Finding ITERS using repeated root derivative trick...")
    ITERS = None
    for fac, mult in poly.factor():
        if mult > 1:
            K = R_poly.quotient(fac)
            iters_K = (K.gen() * K(A_poly.derivative())) / K(A_poly)
            ITERS = Integer(iters_K.lift().constant_coefficient())
            print(f"[+] Found ITERS = {ITERS}")
            break

    # STAGE 2: 17x17 Matrix Exponentiation
    print("[*] Progress: Exponentiating Matrix to ITERS to map S3...")
    C_g =[F(int(10000*np.log10(2 + i))) for i in range(6)]
    C_h =[F(int(10000*np.log10(1337 + i))) for i in range(4)]
    C_i =[F(int(10000*np.log10(31337 + i))) for i in range(5)]
    C_j =[F(int(10000*np.log(31337 + i))) for i in range(100)]

    M = matrix(F, 17, 17)
    M[10, 11] = C_i[0]; M[10, 2] = C_i[1]; M[10, 8] = C_i[2]; M[10, 6] = C_i[3]; M[10, 10] = C_i[4]; M[10, 16] = 1
    M[6, 8] = C_h[0]; M[6, 10] = C_h[1]; M[6, 1] = C_h[2]; M[6, 6] = C_h[3]; M[6, 15] = 1; M[6, 16] = 1
    M[0, 5] = C_g[0]; M[0, 7] = C_g[1]; M[0, 12] = C_g[2]; M[0, 2] = C_g[3]; M[0, 9] = C_g[4]
    for j in range(17): M[0, j] += C_g[5] * M[10, j]
    M[0, 13] += 2; M[0, 14] += 6; M[0, 15] += 6; M[0, 16] += 44

    for i, j in[(1,0), (2,1), (3,2), (4,3), (5,4), (7,6), (8,7), (9,8), (11,10), (12,11)]: M[i, j] = 1
    M[13, 13] = 1; M[13, 14] = 3; M[13, 15] = 3; M[13, 16] = 1
    M[14, 14] = 1; M[14, 15] = 2; M[14, 16] = 1
    M[15, 15] = 1; M[15, 16] = 1; M[16, 16] = 1

    # Define Base States
    g_val, h_val, i_val = [F(0)]*6, [F(0)]*6, [F(0)]*6
    for n in range(6):
        g_val[n] = F(int(10000*np.sin(L + n)))
        if n < 3:
            h_val[n] = F(int(10000*np.sin(L + 6 + n))); i_val[n] = F(int(10000*np.sin(L + 9 + n)))
        else:
            i_val[n] = C_i[0]*i_val[n-2] + C_i[1]*g_val[n-3] + C_i[2]*h_val[n-3] + C_i[3]*h_val[n-1] + C_i[4]*i_val[n-1] + 1
            h_val[n] = C_h[0]*h_val[n-3] + C_h[1]*i_val[n-1] + C_h[2]*g_val[n-2] + C_h[3]*h_val[n-1] + n

    V5 = vector(F, [g_val[5], g_val[4], g_val[3], g_val[2], g_val[1], g_val[0], h_val[5], h_val[4], h_val[3], h_val[2], i_val[5], i_val[4], i_val[3], F(5**3), F(5**2), F(5), F(1)])
    V_curr = (M**(ITERS - 5)) * V5
    S3 =[]
    for k in range(1337):
        S3.append(V_curr[10]) # tracks i_n
        V_curr = M * V_curr

    # STAGE 3: Evaluate j(ITERS)
    print("[*] Progress: Computing j(ITERS) over Polynomial Quotient Ring...")
    P_j = x**10000 - sum(C_j[k] * x**(100 - k) for k in range(100))
    Q_poly_j = R_poly.quotient(P_j)
    a_poly_j = (Q_poly_j.gen()**ITERS).lift()

    j_ITERS = F(0)
    for k, coeff in enumerate(a_poly_j.list()):
        if coeff != 0:
            j_ITERS += coeff * F(sum(S3[d] for d in ZZ(k).digits(1337)))

    print(f"[+] j(ITERS) = {j_ITERS}")

    print("[*] Progress: Decrypting AES...")
    key = hashlib.sha256(str(j_ITERS).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = unpad(cipher.decrypt(bytes.fromhex(enc_hex)), 16)
    print("\n[🎉] FLAG RECOVERED:")
    print(flag.decode('utf-8'))

if __name__ == "__main__":
    solve()
```

**Output:**
```text
[*] Progress: Reading inputs from file...
[*] Progress: Finding minimal polynomial via Berlekamp-Massey...
[*] Finding ITERS using repeated root derivative trick...
[+] Found ITERS = 79120327624133200239720213852419346424887
[*] Progress: Exponentiating Matrix to ITERS to map S3...
[*] Progress: Computing j(ITERS) over Polynomial Quotient Ring...
[+] j(ITERS) = 4884838814356754393675352922066305300889643
[*] Progress: Decrypting AES...

[🎉] FLAG RECOVERED: ICC{N0w_y0u_4re_a_mast3r_0f_t3h_l1n34r_r3curr3nc3s!}
```

---

## 6. What We Learned
* **The Derivative Trick for DLP:** If the minimal polynomial of a recurrence has a repeated root (i.e. $(x-r)^2 | P(x)$), computing the discrete log in the extension field can be bypassed entirely using the algebraic relationship $n = r \frac{A'(r)}{A(r)}$. This completely shattered the security of the $10^{40}$ index hiding.
* **Mutually Recursive Matrices:** Complex sequences that depend on one another and on polynomials (like $n^3$) can be flattened into a single, unified state vector. Binary matrix exponentiation reduces $O(N)$ operations to $O(\log N)$.
* **Polynomial Quotient Rings:** When a recurrence degree is massive (e.g., 10,000), building a $10000 \times 10000$ transition matrix is horribly inefficient. Treating the recurrence mathematically as $x^n \pmod{P(x)}$ in a polynomial quotient ring executes almost instantly.