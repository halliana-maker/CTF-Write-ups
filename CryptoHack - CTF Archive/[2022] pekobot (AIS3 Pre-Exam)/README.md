# pekobot - AIS3 Pre-Exam 2022 Writeup
**Description:** "I am a bot imitating Pekora. You can talk with me through Elliptic-curve Diffie–Hellman protocol!  Connect at archive.cryptohack.org 45328"

## 1. TL;DR
The server implements a custom Elliptic Curve Diffie-Hellman (ECDH) key exchange but fails to validate if the user-supplied public key actually lies on the designated curve (NIST P-256). By providing points that reside on crafted, cryptographically weak curves (curves with "smooth" orders), we force the server to perform scalar multiplication on these weak curves. We then extract small parts of the server's private key using the Baby-Step Giant-Step (BSGS) algorithm and reconstruct the full private key using the Chinese Remainder Theorem (CRT) to decrypt the flag.

---

## 2. Data/Files & Server Interaction
We are given two files:
* `elliptic_curve.py`: A custom implementation of Elliptic Curve arithmetic (Point addition, doubling, and multiplication).
* `server.py`: The main script handling the ECDH key exchange and flag encryption.

### Server Interaction Breakdown
When connecting to the server, we receive the server's static public key $P = d \times G$, and we are presented with a menu:
1. **Start a Diffie-Hellman key exchange:** The server prompts us for an `x` and `y` coordinate. It maps this to a `Point`, multiplies it by its private key $d$, and uses the resulting $x$ and $y$ coordinates as a key to XOR-encrypt a **randomly chosen quote** (from a list of 8 predefined quotes).
2. **Get an encrypted flag:** The server generates a random nonce $r$, and gives us $C_1 = r \times G$ and $C_2 = \text{Encrypt}(r \times P, \text{flag})$. (Standard ElGamal-like encryption).
3. **Exit**

**What is special here?**
* The `Point` class in `elliptic_curve.py` **never checks** if $y^2 \equiv x^3 + ax + b \pmod p$.
* The encryption mechanism `key = c ^ quote` is reversible. Since we know all 8 possible quotes, if we have `c`, we can try all 8 quotes to recover the `key` (which is the resulting point $S$).

---

## 3. Problem Analysis (In Details)

### The Invalid Curve Attack
Elliptic curves are defined by the Weierstrass equation: $y^2 \equiv x^3 + ax + b \pmod p$.
However, if you look at the mathematical formulas for Point Addition and Point Doubling, **the parameter $b$ is never actually used!** It only relies on $x$, $y$, $a$, and $p$.

Because the server does not validate our input point, we can supply a point $(x, y)$ that does not belong to the server's curve, but instead belongs to a forged curve:
$E': y^2 \equiv x^3 + ax + b' \pmod p$

When the server calculates $S = d \times P_{fake}$, it is unknowingly performing valid elliptic curve scalar multiplication on our forged curve $E'$. 

### The Strategy
Standard NIST P-256 has a massive prime order, making the Discrete Logarithm Problem (DLP) impossible to solve. But if we pick specific values for $b'$, we can create curves $E'$ whose group orders have **many small prime factors (smooth numbers)**.
1. Send a point $P_{fake}$ belonging to a small subgroup of order $q$ (where $q$ is small).
2. The server computes $S = d \times P_{fake} \pmod{E'}$.
3. We recover $S$, and since $q$ is small, we easily solve $d \pmod q = \text{DLP}(S, P_{fake})$.
4. Repeat this for multiple different small primes $q_1, q_2, \dots$ until the product of these primes is greater than the order of the private key (256 bits).
5. Use the **Chinese Remainder Theorem (CRT)** to stitch the pieces together and recover the full private key $d$.

---

## 4. Initial Guesses & First Tries

1. **The Random Quote Hurdle:** Initially, the fact that the server XORs the DH shared secret with a *random* quote seemed annoying. How do we know which quote was used?
   * *Solution:* We just XOR the ciphertext with all 8 padded quotes. For each resulting coordinate pair $(x_s, y_s)$, we plug it into our forged curve equation $y^2 \equiv x_s^3 - 3x_s + b' \pmod p$. Only the correct quote will yield a point that perfectly satisfies the equation.

2. **The "Hanging" SageMath Script:** At first, I tried to pre-calculate 400 curves at once using SageMath's `.order()` function. Calculating the SEA (Schoof-Elkies-Atkin) order for 256-bit curves is heavy, and the script timed out.
   * *Solution:* Implemented a **Lazy Evaluation / Greedy Algorithm**. We evaluate curves on the fly, extract subgroup factors, and stop *exactly* when we accumulate 260 bits of entropy. This brought the offline computation time down from 5+ minutes to **under 3 seconds**.

3. **The SageMath Preparser Trap:** During the padding/XOR phase, `key = bytes([c_b ^ q_b ...])` threw a `ValueError: bytes must be in range(0, 256)`. 
   * *Why?* SageMath automatically converts the `^` character to a power operator (`**`)! 
   * *Solution:* Swapped `^` with Python's native `operator.xor()`.

---

## 5. Exploitation Walkthrough / Flag Recovery

Here is the exact attack path our exploit takes:

1. **Curve Generation:** The script iterates $b'$ from 1 upwards, finding the order of $E'$ and factoring it with small primes (up to $2^{18}$). It stops when the unique prime factors collected total over 260 bits.
2. **Data Extraction:** We connect to the server and request `Option 2` to get $C_1$ and $C_2$.
3. **Active Exploitation:** We query `Option 1` with our generated subgroup generators $G_{fake}$. The server replies with a ciphertext. We decrypt this locally by brute-forcing the 8 quotes to find the shared point $S$.
4. **Discrete Logarithms:** Using a custom Baby-Step Giant-Step (BSGS) algorithm, we solve the DLP for each small subgroup, yielding $d \pmod{q_i}$.
5. **Reconstruction:** We pass our arrays of remainders and moduli into SageMath's `crt()` function.
6. **Flag Decryption:** With the full $d$ recovered, we compute the shared key from $C_1$: $S = d \times C_1$. We then XOR $S$ with $C_2$ to reveal the flag.

### Output Log
```text
$ sage solve.sage
[*] Generating prime list (up to 2^18)...
[*] Finding smooth curves on the fly (Takes ~2-3 seconds)...
[+] Accepted b=1   | Gained 56 bits | Total CRT target: 56/260
[+] Accepted b=3   | Gained 31 bits | Total CRT target: 87/260
[+] Accepted b=4   | Gained 27 bits | Total CRT target: 114/260
[+] Accepted b=5   | Gained 12 bits | Total CRT target: 126/260
[+] Accepted b=6   | Gained 46 bits | Total CRT target: 172/260
[+] Accepted b=7   | Gained 24 bits | Total CRT target: 196/260
[+] Accepted b=8   | Gained 19 bits | Total CRT target: 215/260
[+] Accepted b=9   | Gained 44 bits | Total CRT target: 259/260
[+] Accepted b=10  | Gained 13 bits | Total CRT target: 272/260

[*] Active server exploitation (9 queries)...

[*] Solving Subgroup Discrete Logarithms...
[+] Reconstructed Private Key (d): 35845945013502659769254137592561387320854637399668618960754701347592569398865

[🚀] FLAG: AIS3{a_very_bad_ecc_implementation}
```

---

## 6. What We Learned
* **Always Validate Curve Points:** If an ECC library doesn't explicitly verify that a public key satisfies the curve equation $y^2 = x^3 + ax + b$, it is fatally vulnerable to Invalid Curve Attacks. Modern libraries (like `cryptography` or `libsodium`) handle this automatically.
* **Math Optimization is Crucial:** Naively searching for curve orders will hang a CTF script. Targeting small primes dynamically and halting early saves immense amounts of time.
* **SageMath Quirks:** When writing Python scripts natively inside `.sage` files, be extremely careful with bitwise operators. `^` means exponentiation in SageMath. For bitwise XOR, you must use `import operator; operator.xor(a, b)` or `__import__('operator').xor(a, b)` to bypass the preparser.