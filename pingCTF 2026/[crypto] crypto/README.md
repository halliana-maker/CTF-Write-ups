# crypto - pingCTF 2026 Writeup
**Description :** "nc 178.104.42.20 55137"

## 1. TL;DR
The custom ECDH implementation (`ECDH.py`) fails to validate whether a user-supplied public key point actually resides on the target NIST P-192 curve. This omission allows an **Invalid Curve Attack**. By sending carefully crafted points that belong to alternative curves with smooth subgroup orders, we can leak the server's private key modulo small primes and recover the entire key using the Chinese Remainder Theorem (CRT).

---

## 2. What Data/Files We Have and What is Special

We are provided with the source code of the environment:
- `server.py`: Handles the TCP interaction, generates the private key, encrypts the flag using AES-CTR, and accepts unlimited oracle queries for key exchange.
- `ECDH.py`: A custom, from-scratch implementation of Elliptic Curve Diffie-Hellman over the NIST P-192 curve.
- `DOCKERFILE` & `docker-compose.yml`: Standard deployment files.

### The Server-Player Interaction
When connecting to the server, the flow looks like this:
1. **Server Initialization**: The server generates a random private scalar `b_priv` and encrypts the flag using AES-CTR with `SHA256(b_priv)` as the key.
2. **Flag Delivery**: The server sends us the `nonce` and `ciphertext` immediately.
3. **The Oracle Loop**: The server enters an infinite loop:
   - **Player** sends a JSON array representing a point `[x, y]`.
   - **Server** computes the shared secret $S = b_{priv} \times [x, y]$.
   - **Server** returns a `MAC`, which is the `SHA256` of the `SHA256` of the shared point's X-coordinate.

---

## 3. Problem Analysis (In Details)

Let's look at how elliptic curve point addition and doubling are implemented in `ECDH.py`:

```python
# P + (-P) = O
if x1 == x2 and (y1 + y2) % p == 0:
    return None

if P == Q:
    # tangent slope for doubling
    m = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, p) % p
else:
    # chord slope for addition
    m = (y2 - y1) * pow(x2 - x1, -1, p) % p

x3 = (m * m - x1 - x2) % p
y3 = (m * (x1 - x3) - y1) % p
```

Notice something mathematically dangerous? **The curve's `b` parameter is never used.**
The Weierstrass curve equation is $y^2 = x^3 + ax + b \pmod p$. 
Because the mathematical formulas for point addition and doubling only rely on $a$ and the coordinates themselves, if we supply a point $P(x, y)$ that does *not* lie on the NIST P-192 curve, the server will blindly perform scalar multiplication on it anyway.

By supplying an arbitrary $(x, y)$, we are implicitly forcing the server to do math on a **different curve** defined by $b' = y^2 - x^3 - ax \pmod p$. 

If we intentionally select points that belong to curves with **smooth orders** (meaning their order is divisible by a small prime $q$), the resulting shared secret $S = b_{priv} \times P$ will fall into a tiny subgroup of size $q$. We can brute-force $b_{priv} \pmod q$ locally by checking which $k \times P$ matches the server's MAC!

---

## 4. Initial Guesses / First Try

1. **Weak RNG?** My first thought was to check how `b_priv` was generated. It uses `secrets.randbelow(curve.n - 1) + 1`. The `secrets` module is cryptographically secure, so predicting the RNG is impossible.
2. **AES Flaws?** The AES implementation uses `Crypto.Cipher.AES` in `CTR` mode. The nonce is properly handled, and `b_priv` is hashed before being used as the key. No standard AES vulnerabilities apply here.
3. **The "Aha!" Moment:** The fact that `server.py` wrapped the point input in a `while True:` loop strongly hinted at an **Oracle Attack**. Checking `ecdh_responder` confirmed that it takes our point and instantly multiplies it without verifying $y^2 \equiv x^3 + ax + b$.

---

## 5. Exploitation Walkthrough / Flag Recovery

To recover `b_priv` (which is ~192 bits long), we need to extract its value modulo several small primes $q_i$ such that $\prod q_i > n_{curve}$. 

### Step 1: Harvest Small Primes
We write a SageMath script to iteratively guess random $b'$ parameters, construct the curve $y^2 = x^3 - 3x + b'$, and check its group order. If the order is divisible by a small prime $q$, we find a point $P$ of exact order $q$ and save it.

### Step 2: Query the Server
For each point $P$ of order $q$, we send it to the server and receive the MAC.

### Step 3: Brute-Force the Remainder
Locally, we calculate $k \times P$ for $k \in [1, q]$. If the double-SHA256 of the X-coordinate matches the MAC, we know $b_{priv} \equiv k \pmod q$.
*Caveat:* Since elliptic curve points $P$ and $-P$ share the same X-coordinate, the MAC leaves a sign ambiguity. This means $b_{priv}$ could be $k$ OR $q - k$. We save both possibilities.

### Step 4: Resolve Ambiguity & Decrypt
We use the Chinese Remainder Theorem (CRT) to combine all our modular equations. Because of the $\pm$ ambiguity, we have a few thousand combinations (e.g., $2^{14} = 16384$). We iterate through them, derive the AES key, and attempt to decrypt the first block. If it starts with `ping{`, we found the exact private key!

### Execution Log
```text
[*] Finding Invalid Curves with smooth subgroup orders...
[*] Harvested prime factor 8123  | Target remaining bit-length: 180
[*] Harvested prime factor 6899  | Target remaining bit-length: 167
...
[+] Successfully harvested 14 primes. M = prod(q_i) > n_curve.
[*] Connecting to 178.104.42.20:55137
[*] Captured Nonce: 7c769e996938573f
[+] Recovered b_priv % 8123 in[1361, 6762]
[+] Recovered b_priv % 6899 in [821, 6078]
...
[*] Resolving X-coordinate ambiguity...
[*] Testing 16384 combinations using optimized CRT...

FLAG RECOVERED: ping{b_p4r4m3t3r_d03snt_m4tt3r_h3r3}
```

---

## 6. What We Learned
The challenge flag perfectly encapsulates the vulnerability: `b_p4r4m3t3r_d03snt_m4tt3r_h3r3` (b parameter doesn't matter here). 

When writing ECDH logic from scratch, it is not enough to just check if `x` and `y` are integers modulo `p`. You **must** verify that the point satisfies the curve equation before executing scalar multiplication. 

**How to patch it:**
```python
def is_valid_point(P: Point, curve: Curve) -> bool:
    if P is None: return True
    x, y = P
    # Must enforce y^2 == x^3 + ax + b mod p
    return (y * y) % curve.p == (x**3 + curve.a * x + curve.b) % curve.p
```
Always use well-audited cryptographic libraries (like `cryptography` or `ecdsa` in Python) instead of writing low-level point-arithmetic logic!