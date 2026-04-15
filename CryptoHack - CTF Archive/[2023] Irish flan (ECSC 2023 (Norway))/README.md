# Irish flan - ECSC 2023 (Norway) Writeup
**Description:** "Yum, time for dessert." 

## 1. TL;DR
The challenge implements a custom public-key cryptosystem based on Quaternion algebra over a modulo ring $\mathbb{Z}_n$. By analyzing the algebraic properties of the key generation, we observe that the secret quaternion $\chi$ commutes with its power $\gamma$. This allows us to express $\chi$ as a linear combination of $1$ and $\gamma$. By solving a simple linear equation, we can recover a scalar multiple of $\chi$ (an "equivalent key"), which is sufficient to fully decrypt the AES ciphertext.

## 2. What Data/Files We Have
We are provided with two files:
*   `irish_flan.py`: The source code detailing the custom `Dessert` encryption class.
*   `output.txt`: The resulting output of the script containing:
    *   **Public Key:** $(n, \alpha, \beta, \gamma)$
    *   **Encryption Variables:** $(c, \mu, \varepsilon)$

**Note:** There is no server/interactive netcat component for this challenge. It is purely an offline cryptanalysis task.

## 3. Problem Analysis (In-Depth)
Let's break down the cryptosystem defined in the `Dessert` class. All arithmetic happens in a Quaternion ring over $\mathbb{Z}_n$, where $n = p \cdot q$ is a 2048-bit RSA-style modulus.

**Key Generation:**
1.  $\chi, \alpha$ are random quaternions.
2.  $\beta = \chi^{-1} \alpha^{-1} \chi$
3.  $\gamma = \chi^r$ (where $r$ is a massive random integer).
4.  **Public Key:** $(n, \alpha, \beta, \gamma)$

**Encryption Process:**
1.  $k$ is a newly generated random quaternion.
2.  The AES key $K$ is the SHA256 hash of the string representation of $k$.
3.  $c = \text{AES-CBC}(K, m)$ (The ciphertext of our flag).
4.  $\delta = \gamma^s$ (where $s$ is another massive random integer).
5.  $\varepsilon = \delta^{-1} \alpha \delta$
6.  $\kappa = \delta^{-1} \beta \delta$
7.  $\mu = \kappa k \kappa$
8.  **Ciphertext Output:** $(c, \mu, \varepsilon)$

Our ultimate goal is to recover $k$ from $\mu$ so we can generate the AES key and decrypt $c$. From step 7, if we can find $\kappa$, we can compute $k = \kappa^{-1} \mu \kappa^{-1}$.

## 4. Initial Guesses & Dead Ends
*   **Factoring $n$:** $n$ is formed by two 1024-bit primes. Without any provided hints, prime leakage, or small factors, standard integer factorization (like Pollard's $p-1$ or Fermat's) will fail.
*   **Discrete Logarithm Problem (DLP):** Since $\gamma = \chi^r$, one might try to find $r$. However, the ring is massive and finding the discrete log over a non-smooth group of this size is computationally infeasible.

## 5. Exploitation Walkthrough / Flag Recovery

The vulnerability lies in the algebraic relationship between the public parameters. 

### Step 1: The Linear Dependence of $\chi$
We know that $\gamma = \chi^r$. Because powers of a single element in any algebra commute with that element, $\chi$ and $\gamma$ commute. Furthermore, they are linearly dependent in the span of $1$ and $\gamma$. We can represent $\chi$ as a linear combination:
$$ \chi = c_0 + c_1 \gamma $$

From the key generation, we have:
$$ \beta = \chi^{-1} \alpha^{-1} \chi \implies \chi \beta = \alpha^{-1} \chi $$

Substitute our linear combination into this equation:
$$ (c_0 + c_1 \gamma) \beta = \alpha^{-1} (c_0 + c_1 \gamma) $$
$$ c_0 \beta + c_1 \gamma \beta = c_0 \alpha^{-1} + c_1 \alpha^{-1} \gamma $$
$$ c_0 (\beta - \alpha^{-1}) + c_1 (\gamma \beta - \alpha^{-1} \gamma) = 0 $$

Since scaling a quaternion by a constant doesn't change its conjugating properties, we don't need the exact $\chi$. We just need an equivalent proportional quaternion $\chi'$. We can safely assume $c_0 = 1$ and solve for $c_1$:
$$ c_1 = -(\beta - \alpha^{-1}) \cdot (\gamma \beta - \alpha^{-1} \gamma)^{-1} $$
With $c_1$ found, we establish our equivalent key: $\chi' = 1 + c_1 \gamma$.

### Step 2: Recovering $\kappa$
Now, let's look at how the encryption variables relate.
$$ \kappa = \delta^{-1} \beta \delta $$
Substitute $\beta$ with its definition ($\chi^{-1} \alpha^{-1} \chi$):
$$ \kappa = \delta^{-1} (\chi^{-1} \alpha^{-1} \chi) \delta $$

Because $\delta = \gamma^s = (\chi^r)^s = \chi^{rs}$, we know $\delta$ is just a power of $\chi$. Therefore, $\delta$ and $\chi$ commute.
$$ \kappa = \chi^{-1} (\delta^{-1} \alpha^{-1} \delta) \chi $$

Notice the inner part is exactly the inverse of $\varepsilon$! ($\varepsilon = \delta^{-1} \alpha \delta \implies \varepsilon^{-1} = \delta^{-1} \alpha^{-1} \delta$)
$$ \kappa = \chi^{-1} \varepsilon^{-1} \chi $$

Because $\chi'$ is just a scalar multiple of $\chi$, the scalar cancels out perfectly during this inversion/multiplication:
$$ \kappa = (\chi')^{-1} \varepsilon^{-1} \chi' $$

### Step 3: Decrypting the Flag
Now that we have exactly recovered $\kappa$, we can easily unmask $k$:
$$ k = \kappa^{-1} \mu \kappa^{-1} $$
Hash $k$ using SHA-256 to derive the AES key, and decrypt the payload.

### The Exploit Script
```python
import ast
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def solve():
    try:
        with open("output.txt", "r") as f:
            data = f.read()
    except Exception as e:
        print("[-] Failed to read the file:", e)
        return

    print("[*] Parsing data...")
    # Extract n
    n_match = re.search(r'Public key: (\d+)', data)
    if not n_match:
        print("[-] Could not find n.")
        return
    n = int(n_match.group(1))
    
    # Split data into pub and enc blocks
    pub_part = re.search(r'Public key:.*?(?=Encryption:)', data, re.DOTALL).group(0)
    enc_part = re.search(r'Encryption:.*', data, re.DOTALL).group(0)
    
    pub_comps = list(map(int, re.findall(r'(\d+) \(mod', pub_part)))
    enc_comps = list(map(int, re.findall(r'(\d+) \(mod', enc_part)))
    
    alpha_comps = pub_comps[0:4]
    beta_comps = pub_comps[4:8]
    gamma_comps = pub_comps[8:12]
    
    mu_comps = enc_comps[0:4]
    eps_comps = enc_comps[4:8]
    
    c_bytes = ast.literal_eval(re.search(r'(b".*?")', enc_part).group(1))

    # Define modulo arithmetic classes matching the original implementations
    class R:
        def __init__(self, r):
            self.r = r % n

        def __add__(self, other):
            return R(self.r + other.r)

        def __sub__(self, other):
            return R(self.r - other.r)

        def __neg__(self):
            return R(-self.r)

        def __mul__(self, other):
            if isinstance(other, int):
                return R(self.r * other)
            return R(self.r * other.r)

        def __pow__(self, other):
            return R(pow(self.r, other, n))

        def __truediv__(self, other):
            return self * other**-1

        def __repr__(self):
            return f"Z({repr(n)})({repr(self.r)})"

        def __str__(self):
            return f"{self.r} (mod {n})"

    class Q:
        def __init__(self, a, b, c, d):
            self.a = a
            self.b = b
            self.c = c
            self.d = d

        def __add__(self, other):
            return Q(self.a + other.a, self.b + other.b,
                     self.c + other.c, self.d + other.d)

        def __sub__(self, other):
            return Q(self.a - other.a, self.b - other.b,
                     self.c - other.c, self.d - other.d)

        def __mul__(self, o):
            if isinstance(o, (int, type(self.a))):
                return Q(self.a * o, self.b * o,
                         self.c * o, self.d * o)
            return Q(self.a * o.a - self.b * o.b - self.c * o.c - self.d * o.d,
                     self.a * o.b + self.b * o.a + self.c * o.d - self.d * o.c,
                     self.a * o.c - self.b * o.d + self.c * o.a + self.d * o.b,
                     self.a * o.d + self.b * o.c - self.c * o.b + self.d * o.a)

        def invert(self):
            d = (self.a**2 + self.b**2 + self.c**2 + self.d**2)
            return Q(self.a/d, -self.b/d, -self.c/d, -self.d/d)

        def __repr__(self):
            return "Q({},{},{},{})".format(*map(repr, [self.a, self.b, self.c, self.d]))

        def __str__(self):
            return "({})".format(",".join(map(str,[self.a, self.b, self.c, self.d])))

    alpha = Q(*[R(x) for x in alpha_comps])
    beta = Q(*[R(x) for x in beta_comps])
    gamma = Q(*[R(x) for x in gamma_comps])
    
    mu = Q(*[R(x) for x in mu_comps])
    eps = Q(*[R(x) for x in eps_comps])
    
    alpha_inv = alpha.invert()
    V1 = beta - alpha_inv
    V2 = gamma * beta - alpha_inv * gamma
    
    # We want to find c_val such that V1 + c_val * V2 = 0
    if V2.a.r != 0:
        c_val = -V1.a / V2.a
    elif V2.b.r != 0:
        c_val = -V1.b / V2.b
    elif V2.c.r != 0:
        c_val = -V1.c / V2.c
    else:
        c_val = -V1.d / V2.d
            
    # Recreate the projective chi multiple
    chi_prime = Q(R(1), R(0), R(0), R(0)) + gamma * c_val
    
    # Because chi_prime is a multiple of chi, the multiple gets cancelled out here
    kappa_inv = chi_prime.invert() * eps * chi_prime
    
    k = kappa_inv * mu * kappa_inv
    
    K = hashlib.sha256(str(k).encode()).digest()
    cipher = AES.new(K, AES.MODE_CBC, iv=b"\0" * 16)
    
    try:
        plaintext = unpad(cipher.decrypt(c_bytes), 16)
        print("[+] Flag:", plaintext.decode())
    except Exception as e:
        print("[-] Decryption failed:", e)

if __name__ == "__main__":
    solve()

```

### Result:
```text
[*] Parsing data...
[+] Flag: ECSC{3qu1v4l3nt_k3y_rec0very_988b09742b}
```

## 6. What We Learned
* **Equivalent Keys over Commutative Properties:** In non-commutative algebras (like quaternions or matrices), if $A$ is a power of $B$, they commute. This simple commutativity can completely bypass the need for Discrete Logarithm calculations. 
* **Scalar Cancellation:** When reconstructing hidden values inside a conjugation operation ($x^{-1} y x$), you rarely need the exact value of $x$. Any proportional equivalent/scalar multiple $x'$ will cancel out perfectly ($(\lambda x)^{-1} y (\lambda x) = x^{-1} y x$), leading to devastating Equivalent Key Recovery attacks.