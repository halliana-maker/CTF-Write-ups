# U-Turn - Breizh CTF 2025 Writeup

**Description:** "HaSh functIonS are one-way, right?"

### 1. TL;DR
The "hash function" in this challenge is a linear transformation $A\vec{x} \equiv \vec{h} \pmod{256}$. The vector $\vec{x}$ is derived from the flag using a balanced quinary (base-5) representation, making it a very short vector (all entries $\in \{-2, \dots, 2\}$). By constructing a lattice and using the **LLL (Lenstra-Lenstra-Lovász)** algorithm, we solve the **Short Integer Solution (SIS)** problem to recover $\vec{x}$, reconstruct the flag integer, and reverse the XOR padding.

### 2. Files and Data
The following files were provided:
*   `A.txt`: A $48 \times 50$ matrix $A$ with entries in $\mathbb{Z}_{256}$.
*   `chal.sage`: The hashing script using SageMath.
*   `utils.py`: Implementation of `btq` (bytes-to-quinary) and `sanitize` (XOR/Padding).
*   `output.txt`: The target hash value: `fdac962720ab6e0c60ddbdf06d05112e315b86294e6bef26a695d851bb898b025dd3f6a65620cb4b509292cb64d0aa88`.

**Special Observation:**
The `btq` function maps bytes to a vector of length 50 where each element is from the set $\{-2, -1, 0, 1, 2\}$. In lattice cryptography, this is a "small secret" or "short vector," which makes the theoretically one-way SIS problem solvable in practice.

### 3. Problem Analysis
#### The Hashing Pipeline:
1.  **Padding:** The 16-character hex flag (16 bytes) is padded using PKCS#7 to 32 bytes. Since the length is exactly 16, a full block of `\x10` (sixteen 16s) is added.
2.  **Sanitize:** The two 16-byte blocks are XORed together. This means:
    $a = \text{FLAG} \oplus (\text{16 bytes of } 0x10)$
3.  **Quinary Conversion (`btq`):** The resulting integer $a$ is converted to base 5. The digits are shifted by $-2$ to create a "balanced" representation: $charset = \{-2, -1, 0, 1, 2\}$.
4.  **Matrix Multiplication:** The first 50 quinary digits form a vector $\vec{x}$. The hash $\vec{h}$ is computed as:
    $$A \vec{x} \equiv \vec{h} \pmod{256}$$

#### The Mathematical Weakness:
The system has 48 equations and 50 unknowns. However, because we know $\|x\|_{\infty} \le 2$, the solution space is extremely constrained. This is a classic **Bounded Distance Decoding (BDD)** problem.

### 4. Initial Guesses
*   **Brute Force:** 16 hex characters ($16^{16} = 2^{64}$) is too large for a direct search.
*   **Linear Algebra:** Standard Gaussian elimination over $\mathbb{Z}_{256}$ would give many possible solutions for $\vec{x}$, most of which would not result in valid quinary digits or hex characters. We specifically need the **shortest** solution.

### 5. Exploitation Walkthrough

#### Step 1: Lattice Construction
We construct a lattice $\mathcal{L}$ such that a short vector in the lattice reveals $\vec{x}$. We use Kannan's Embedding:

$$
M = \begin{pmatrix} 
I_{50} & A^T \cdot W & 0 \\
0 & 256 \cdot I_{48} \cdot W & 0 \\
0 & -\vec{h} \cdot W & 1 
\end{pmatrix}
$$

Where $W$ is a large weight (e.g., 1000) used to penalize any vector that doesn't satisfy the equation $A\vec{x} \equiv \vec{h} \pmod{256}$.

#### Step 2: LLL Reduction
Running LLL on this matrix finds a row where the first 50 entries correspond to our small $\vec{x}$ and the last entry is $\pm 1$.

#### Step 3: Reconstructing the Integer
The integer $a$ is recovered by reversing the digit shift:
$$R = \sum_{i=0}^{49} (x_i + 2) \cdot 5^i$$

#### Step 4: Handling Truncation
The `btq` function truncates the quinary representation to 50 digits. $5^{50}$ is approximately $8.8 \times 10^{34}$, while a 16-byte integer can be as large as $256^{16} \approx 3.4 \times 10^{38}$. 
We brute-force the "missing" high-order digits:
$$a = R + k \cdot 5^{50}$$
For each candidate $a$, we XOR the resulting bytes with `0x10` and check if the result is a 16-byte hex string.

#### Solving Script (SageMath):
```python
from ast import literal_eval

# Load matrix and hash
with open("A.txt", "r") as f: A_data = literal_eval(f.read())
h_hex = "fdac962720ab6e0c60ddbdf06d05112e315b86294e6bef26a695d851bb898b025dd3f6a65620cb4b509292cb64d0aa88"
h = vector(ZZ, list(bytes.fromhex(h_hex)))

k, l, n = 48, 50, 256
W = 1000

# Build Lattice
M = Matrix(ZZ, l + k + 1, l + k + 1)
M[:l, :l] = identity_matrix(l)
M[:l, l:-1] = Matrix(ZZ, A_data).transpose() * W
M[l:-1, l:-1] = identity_matrix(k) * n * W
M[-1, l:-1] = -h * W
M[-1, -1] = 1

# Reduce
L = M.LLL()
target_x = [row[:l] for row in L if abs(row[-1]) == 1 and all(abs(v) <= 2 for v in row[:l])][0]

# Search for flag
R = sum((int(target_x[i]) + 2) * (5**i) for i in range(l))
for k_val in range(4000):
    a_int = R + k_val * (5**50)
    a_bytes = int(a_int).to_bytes(16, 'little')
    flag_cand = bytes([int(b) ^^ 0x10 for b in a_bytes])
    if all(c in b"0123456789abcdef" for c in flag_cand):
        print(f"BZHCTF{{{flag_cand.decode()}}}")
        break
```
Program output:
```
BZHCTF{7ffbeebcd72be3dc}
```

### 6. What We Learned
1.  **Linearity is Dangerous:** Any hash function that relies purely on linear operations over small moduli is susceptible to lattice reduction attacks.
2.  **Short Secrets:** Using balanced digits (like $\{-2, \dots, 2\}$) significantly reduces the security of a system because it allows attackers to use LLL to distinguish the secret from the noise.
3.  **Reverse Engineering Padding:** Always account for how padding (like PKCS#7) interacts with XOR operations in a custom "sanitize" function.

**Flag:** `BZHCTF{7ffbeebcd72be3dc}`