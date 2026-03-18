# Write-up: Noisy Lucky Number (Crypto)

### Description 
We intercepted a batch of 50 ECDSA signatures from an experimental transaction server, along with an encrypted flag.
The server generates nonces using a custom EntropyMixer class. The developers claim that mixing a lucky number into the entropy buffer makes the system more secure.However, recent datacenter logs indicate unstable voltage caused the module to occasionally glitch. During these glitches, a small fraction of the signatures were generated incorrectly.

## 1. TL;DR
The challenge implements ECDSA signing where the nonce ($k$) is constructed by appending a fixed 16-bit `HW_ID` to 30 bytes of entropy. This constant 16-bit suffix across multiple signatures makes the system vulnerable to the **Hidden Number Problem (HNP)** using Lattice reduction (LLL). Because a fraction of the signatures were "noisy" (generated with pure random entropy due to a simulated hardware glitch), a standard lattice attack fails. We bypassed this by combining LLL with a **RANSAC (Random Sample Consensus)** algorithm to repeatedly test random subsets of signatures until a clean, noise-free subset successfully yielded the private key.

## 2. Problem Analysis (Details)
We are given 50 ECDSA signatures over the `secp256k1` curve, along with the encrypted flag. The core vulnerability lies in the `EntropyMixer` class:

```python
# Intended behavior: 30 bytes of random + 2 bytes of fixed HW_ID
mixed_buffer = struct.pack(">30sH", raw_entropy, self.hw_id)
k = int.from_bytes(mixed_buffer, "big")
```

In ECDSA, the signature $(r, s)$ is generated as:
$$ s \equiv k^{-1} (h + d \cdot r) \pmod n $$
Which rearranges to:
$$ k \equiv s^{-1}h + s^{-1}r \cdot d \pmod n $$

Let $u_i = s_i^{-1} h_i \pmod n$ and $t_i = s_i^{-1} r_i \pmod n$. 
Thus, $k_i \equiv u_i + t_i \cdot d \pmod n$.

Because the lower 16 bits of the nonces are fixed to `HW_ID` (let's call it $c$), we can write the nonce as:
$$ k_i = x_i \cdot 2^{16} + c $$
Where $x_i$ is the unknown 30-byte entropy. If we subtract the first equation ($k_0$) from the rest ($k_i$), the unknown constant $c$ is completely eliminated:
$$ k_i - k_0 = (x_i - x_0) \cdot 2^{16} $$
Substitute $k$:
$$ (u_i - u_0) + (t_i - t_0) \cdot d \equiv (x_i - x_0) \cdot 2^{16} \pmod n $$

Multiplying by the modular inverse of $2^{16}$:
$$ (u_i - u_0)2^{-16} + (t_i - t_0)2^{-16} \cdot d \equiv x_i - x_0 \pmod n $$

This leaves us with a system of linear congruences where the unknowns are relatively small ($x_i - x_0$ is 30 bytes, compared to the 32-byte modulo $n$). This is the textbook definition of the **Hidden Number Problem (HNP)**, solvable via LLL lattice reduction.

## 3. Initial Guesses / First Try
At first glance, this looks like a straightforward script-kiddie lattice attack. Normally, you would parse all 50 signatures, construct a single $52 \times 52$ basis matrix, run LLL, and read the private key $d$ from the shortest vector.

**The Catch:** The challenge description hints at "unstable voltage... causing the module to occasionally glitch." Looking at the source code, there is a probability check:
```python
self.mixer_stable = (os.urandom(1)[0] > 35) # Fails ~14% of the time
```
When it fails, $k$ is 32 bytes of pure, pattern-less entropy. 
If we put all 50 signatures into a single lattice, the 14% "noisy" signatures act as poisoned data. They do not share the 16-bit suffix, meaning their equations don't hold true. LLL is highly sensitive to outliers—even a single invalid equation in the matrix will break the reduction, yielding garbage output instead of the private key.

## 4. Exploitation Walkthrough / Flag Recovery
To defeat the poisoned data, we borrow a technique from computer vision: **RANSAC**. 

Instead of using all 50 signatures, we only need about $m=22$ signatures for the lattice to mathematically converge on a unique solution. 
1. We randomly sample a subset of 23 signatures.
2. We assume *all* of them are "stable" (noise-free).
3. We build the matrix and run LLL.
4. We extract the candidate private key ($d$) and attempt to decrypt the AES-XOR flag.
5. If it decrypts to a string containing `"PUCTF"`, we win. If not, we discard the subset and try another random sample.

The probability of picking 23 clean signatures from a pool that is 86% clean is roughly $(0.86)^{23} \approx 3.1\%$. This means we should only need around 30 to 100 attempts to find a perfect subset—a process that takes just seconds in SageMath.

**The Lattice Construction:**
We build an $(m+2) \times (m+2)$ matrix $M$.
Let $A_i = (u_i - u_0)2^{-16} \pmod n$ and $B_i = (t_i - t_0)2^{-16} \pmod n$.

$$
M = \begin{bmatrix}
n \cdot K & 0 & \dots & 0 & 0 & 0 \\
0 & n \cdot K & \dots & 0 & 0 & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & n \cdot K & 0 & 0 \\
B_1 \cdot K & B_2 \cdot K & \dots & B_m \cdot K & 1 & 0 \\
A_1 \cdot K & A_2 \cdot K & \dots & A_m \cdot K & 0 & X 
\end{bmatrix}
$$
*(Where $K = 2^{16}$ balances the weights, and $X = 2^{255}$ is the target scalar for the known constant).*

**Execution Output:**
Running the SageMath script yielded the following:
```text
[*] Loading task_data.json...
[*] Starting RANSAC Lattice Attack (m=22)...
[*] Attempt 10... continuing to search for an all-stable subset.
[*] Attempt 20... continuing to search for an all-stable subset.
...
[*] Attempt 150... continuing to search for an all-stable subset.

[+] SUCCESS! Valid subset found after 157 attempts.
[+] Private Key (d): 0xcfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2
[+] Flag: PUCTF26{y0u_4r3_1uck7_4nd_9O0d_47_5ub54mp1ing_d4102652fb095f2fDC40D346B7E02440}
```

## 5. What We Learned
1. **Never dilute cryptographic entropy:** Appending a "lucky number" or static hardware ID to an ECDSA nonce drastically reduces its security. ECDSA requires $k$ to be completely uniformly distributed and secret. Even a 16-bit known or shared suffix is fatal.
2. **Lattices are fragile, but RANSAC is robust:** Lattice reduction algorithms (like LLL) require mathematically perfect relations. When dealing with real-world traces or fault-injected CTF data that contains noise, pairing LLL with Random Sample Consensus (RANSAC) is an incredibly powerful way to isolate clean constraints and solve the Hidden Number Problem.
3. **Difference mapping eliminates unknown constants:** We didn't even need to brute-force the 2-byte `HW_ID`. By simply subtracting the equations ($k_i - k_0$), the constant naturally fell out of the math, turning a partially-known nonce attack into a pure shared-suffix attack.