# HKCERT CTF 2025 - Triple Key Cipher Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *我實現了一個使用三個密鑰的分組密碼算法。 I implemented a block cipher algorithm that uses three keys.*

## TL;DR
The challenge implements a custom block cipher where the encryption logic depends on three keys. A critical implementation bug in the `twist` function fails to bit-shift the high nibble, restricting the keystream ($K3$) and the modulus generator ($K1$) to the range `[0, 15]`.
This leaks the high nibbles of the ciphertext, transforming the challenge into a **Hidden Number Problem (HNP)**. We solve it by:
1.  Recovering $K1$ using Z3 (trivial due to the small range).
2.  Linearizing the polynomial multiplication logic.
3.  Recovering the static $K2$ using **Lattice Reduction (LLL)** on the linear constraints derived from the ciphertext high nibbles.

***

## 1. Reconnaissance & Analysis

We are provided with a C source file `triKeyEnc.c` and a remote service. The service offers three options:
1.  **Encrypt**: Takes a message, returns a `leak` and the `ciphertext`.
2.  **Get Flag**: Requires submitting the correct `Key2`.
3.  **Quit**.

### The Cipher Logic
The encryption routine `triple_key_cipher` is complex:
*   **Key 1**: Used to generate a $16 \times 16$ expansion matrix (`key_expand`).
*   **Key 2**: A static key used as a vector in a custom matrix multiplication with the message.
*   **Key 3**: A dynamic keystream XORed with the result.

Mathematically, the encryption for a block $i$ looks like this:
$$ C_i = (M_i \otimes K2) \oplus K3_i $$
Where $\otimes$ is a custom matrix-vector multiplication over $\mathbb{Z}_{256}$ defined by the `key_expand` table.

Crucially, the keys are "twisted" before use. Let's look at that function.

## 2. The Vulnerability: The "Missing Shift"

The `twist` function is supposed to mix the bits of the key using 64-bit arithmetic and then pack them back into bytes.

```c
void twist(unsigned char *msg) {
    // ... complex 64-bit math calculating out1 and out2 ...
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        msg[i] = out1 & 0xf;
        msg[i] |= out2 & 0xf; // <--- CRITICAL BUG HERE
        out1 >>= 4;
        out2 >>= 4;
    }
}
```

**The Bug:** The line `msg[i] |= out2 & 0xf;` is missing a left shift `<< 4`.
Intended behavior: Pack two 4-bit nibbles into one 8-bit byte.
Actual behavior: Both nibbles are OR'd into the **lower 4 bits**.

**Consequence:**
1.  `msg[i]` will always be in the range $[0, 15]$.
2.  The high nibble (bits 4-7) is **always 0**.

This applies to:
*   **Key 1**: Twisted at the start. So every byte of $K1 \in [0, 15]$.
*   **Key 3**: Twisted before every block encryption. So every byte of the keystream $K3 \in [0, 15]$.

## 3. Exploit Strategy

### Phase 1: Recovering Key 1
The service outputs a `leak`, which is the last row of the `key_expand` matrix.
The expansion logic is deterministic:
$$ \text{Row}_{i+1} = f(\text{Row}_i, K1) $$
Since we know $\text{Row}_{15}$ (the leak) and we know $K1$ is "twisted" (bytes $\le 15$), we can use a constraint solver (Z3) to reverse the expansion and find $K1$.
Because the search space for $K1$ is tiny ($16^{16}$ vs $256^{16}$), Z3 finds the solution instantly.

### Phase 2: Linearization (Hidden Number Problem)
The encryption equation is:
$$ C = (M \cdot K2) \oplus K3 $$
Where $M$ is the transformation matrix derived from the message and `key_expand`.

Since $K3$ has zeroed high nibbles ($K3 < 16$), the XOR operation doesn't affect the high nibbles of the result much. Specifically:
$$ C \& 0xF0 \approx (M \cdot K2) \& 0xF0 $$
(Strictly speaking, since $K3 \in [0, 15]$, no carries propagate into the high nibble during addition if we treat XOR as addition-with-no-carry, but in $\mathbb{Z}_{256}$, the constraint is simply that the top 4 bits must match).

We can rewrite this as a linear inequality for each byte $j$:
$$ (M \cdot K2)_j \pmod{256} \in [C_j \& 0xF0, (C_j \& 0xF0) + 15] $$

This is a classic **Hidden Number Problem (HNP)**. We have a linear system with "noise" (the lower 4 bits), and we need to recover the secret vector $K2$.

### Phase 3: Lattice Attack
We can solve this using Lattice Reduction (LLL). We construct a lattice basis $B$ such that a short vector in the lattice corresponds to our key $K2$.

**Lattice Construction:**
We want to solve $M \cdot K2 - 256 \cdot q = C + \epsilon$, where $\epsilon$ is small.
Rearranging: $M \cdot K2 - 256 \cdot q - C \approx 0$.

We build a matrix of dimension $(16 + N + 1)$, where $N$ is the number of constraints (bytes of ciphertext).
*   **Rows 0..15**: Identity matrix for $K2$ (since we want to find $K2$).
*   **Rows 16..(16+N)**: The coefficients of $M$, scaled by a large weight $W$. Also include the modulus $256 \times W$.
*   **Last Row**: The target vector $-Target \times W$. We set the target to the center of the possible range: $(C \& 0xF0) + 7$.

By running LLL (Lenstra-Lenstra-Lovász) reduction, we find a basis where the vectors are as short as possible. The shortest vector will correspond to the solution where the "error" (difference between our guess and the ciphertext) is minimal—i.e., the correct $K2$.

**Data Requirements:**
*   Key length: 16 bytes (128 bits).
*   Information per byte: 4 bits.
*   Required bytes: $128 / 4 = 32$ bytes.
*   We use **2 traces** (64 bytes) to guarantee a unique solution and account for lattice overhead.

## 4. The Solution Script

Here is the full SageMath/Python script used to secure the Gold.

```python
#!/usr/bin/env python3
from pwn import *
from z3 import *
import hashlib
import binascii
import subprocess
import os

# Configuration
BLOCK_SIZE = 16
HOST = "pwn-3836fac34b.challenge.xctf.org.cn"
PORT = 9999

def solve():
    # 1. Establish Connection (Keep alive for session state)
    r = remote(HOST, PORT, ssl=True)

    def get_trace():
        r.recvuntil(b"Your choice:")
        r.sendline(b"1")
        # Send 32 bytes to get 2 blocks of ciphertext
        payload = b"A" * 32
        r.recvuntil(b"Message:")
        r.send(payload)
        r.recvuntil(b"leak: ")
        leak = binascii.unhexlify(r.recvline().strip().decode())
        r.recvuntil(b"enc: ")
        enc = binascii.unhexlify(r.recvline().strip().decode())
        # Calculate real plaintext (SHA256 of input)
        msg = hashlib.sha256(payload).digest()
        return msg, leak, enc

    # 2. Collect Data
    print("[*] Phase 1: Collecting traces...")
    traces = [get_trace() for _ in range(2)]

    # 3. Recover Key1 & Build Matrices
    print("[*] Phase 2: Recovering Key1 and building Linear System...")
    all_matrices = []
    all_targets = []

    for msg, leak, enc in traces:
        # Z3 Solver for Key1
        s = Solver()
        k1 = [BitVec(f"k1_{i}", 8) for i in range(BLOCK_SIZE)]
        
        # Simulate Key Expansion
        row = k1
        for _ in range(BLOCK_SIZE - 1):
            nxt = [BitVecVal(0, 8)] * BLOCK_SIZE
            f = row[BLOCK_SIZE-1]
            nxt[0] = f * k1[0]
            for j in range(BLOCK_SIZE - 1):
                nxt[j+1] = row[j] + f * k1[j+1]
            row = nxt
        
        # Constraints: Leak matches & Key1 is twisted (<= 15)
        for i in range(BLOCK_SIZE):
            s.add(row[i] == leak[i])
            s.add(ULE(k1[i], 15)) 
            
        if s.check() != sat:
            log.failure("Key1 recovery failed.")
            return
        
        m = s.model()
        k1_val = [m[k1[i]].as_long() for i in range(BLOCK_SIZE)]
        
        # Generate Concrete Key Expansion Table
        key_expand = []
        curr_row = list(k1_val)
        key_expand.append(curr_row)
        for _ in range(BLOCK_SIZE - 1):
            nr = [0]*BLOCK_SIZE
            f = curr_row[BLOCK_SIZE-1]
            nr[0] = (f * k1_val[0]) & 0xFF
            for j in range(BLOCK_SIZE - 1):
                nr[j+1] = (curr_row[j] + f * k1_val[j+1]) & 0xFF
            key_expand.append(nr)
            curr_row = nr

        # Linearize Encryption Blocks
        for b in range(2):
            msg_blk = msg[b*BLOCK_SIZE : (b+1)*BLOCK_SIZE]
            enc_blk = enc[b*BLOCK_SIZE : (b+1)*BLOCK_SIZE]
            
            # Matrix M construction (Enc = M * K2 + K3)
            M = [[0]*BLOCK_SIZE for _ in range(BLOCK_SIZE)]
            for col in range(BLOCK_SIZE):
                e = [0]*BLOCK_SIZE
                if col == 0: e = list(msg_blk)
                else:
                    i = col
                    for j in range(BLOCK_SIZE - i):
                        e[i+j] = (e[i+j] + msg_blk[j]) & 0xFF
                    for j in range(BLOCK_SIZE - i, BLOCK_SIZE):
                        row_red = key_expand[i + j - BLOCK_SIZE]
                        coeff = msg_blk[j]
                        for k in range(BLOCK_SIZE):
                            e[k] = (e[k] + coeff * row_red[k]) & 0xFF
                for r in range(BLOCK_SIZE): M[r][col] = e[r]
            
            all_matrices.extend(M)
            # Target is the center of the nibble range: (C & 0xF0) + 7
            for val in enc_blk:
                all_targets.append((val & 0xF0) + 7)

    # 4. Lattice Attack via SageMath
    print("[*] Phase 3: Lattice Reduction (LLL)...")
    
    sage_code = f"""
from sage.all import *

M = {all_matrices}
T = {all_targets}
n = 16
m = len(M)
mod = 256
W = 100 # Weight factor

# Lattice Basis Construction
dim = n + m + 1
B = Matrix(ZZ, dim, dim)

# Identity for K2
for i in range(n): B[i,i] = 1

# Equations: M*K2 - mod*q = T + err
for j in range(m):
    for i in range(n):
        B[i, n+j] = M[j][i] * W
    B[n+j, n+j] = mod * W     # Modulus vector
    B[dim-1, n+j] = -T[j] * W # Target vector

B[dim-1, dim-1] = 1 # Anchor

# LLL Reduction
res = B.LLL()

# Extract solution
for row in res:
    if abs(row[dim-1]) == 1:
        sign = 1 if row[dim-1] == 1 else -1
        k2 = [(row[i] * sign) % 256 for i in range(n)]
        print("KEY=" + bytes(k2).hex())
        break
"""
    with open("solve.sage", "w") as f:
        f.write(sage_code)
    
    # Run Sage
    try:
        out = subprocess.check_output(["sage", "solve.sage"]).decode()
        key_hex = out.split("KEY=")[1].strip()
        print(f"[+] FOUND KEY2: {key_hex}")
    except Exception as e:
        log.error(f"Solver failed: {e}")
        return

    # 5. Submit Flag
    r.recvuntil(b"Your choice:")
    r.sendline(b"2")
    r.recvuntil(b"Key: ")
    r.send(binascii.unhexlify(key_hex))
    
    print("\n" + "="*40)
    print(r.recvall(timeout=3).decode().strip())
    print("="*40)

if __name__ == "__main__":
    solve()
```

## 5. Result

Running the solver collects the traces, linearizes the system, and instantly finds the key using LLL.

```text
[*] Phase 1: Collecting traces...
[*] Phase 2: Recovering Key1 and building Linear System...
[*] Phase 3: Lattice Reduction (LLL)...
[+] FOUND KEY2: d5281b84ce8dcbf69280b64560dcef99
========================================
flag: flag{aTvQe9GVh5KSQxYx3p63VkZi5G018jPt}
========================================
```

**Flag:** `flag{aTvQe9GVh5KSQxYx3p63VkZi5G018jPt}`