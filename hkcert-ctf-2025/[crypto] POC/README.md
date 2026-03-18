# HKCERT CTF 2025 - POC Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *Easy AES Challenge*

## 1. TL;DR
The challenge implements AES-GCM with a critical flaw: **Nonce Reuse**. The server allows the `register` function to be called twice using the same `nonce`. In AES-GCM, reusing a nonce (the "Forbidden Attack") allows an attacker to recover the authentication hash key $H$ by solving a polynomial equation in $GF(2^{128})$. Once $H$ is known, we can forge a valid authentication tag for any ciphertext. We use this to forge a token for the `admin` user and retrieve the flag.

---

## 2. Vulnerability Analysis

### The Source Code
Looking at the provided `min.py`, we see the following logic in `PaddingOracleClass`:

```python
def update(self, nonce: bytes):
    self.nonce = nonce
    self.cnt = 2 # Each nonce can be used twice!

def register(self, username: bytes) -> tuple[bytes, bytes]:
    assert self.cnt, "Out of Services"
    self.cnt -= 1
    aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
    # ... encrypts username ...
```

### The Flaw
The `cnt` variable is initialized to `2` every time a nonce is set. This means we can call `register` twice for the **exact same nonce**. 

AES-GCM is composed of two parts:
1.  **Counter Mode (CTR) Encryption**: $C = P \oplus E_K(N || i)$. Reusing the nonce reveals the XOR sum of two plaintexts ($C_1 \oplus C_2 = P_1 \oplus P_2$).
2.  **GMAC Authentication**: A polynomial-based MAC using a hash key $H = E_K(0^{128})$. The tag $T$ is computed as:
    $$T = (A \cdot H^m \oplus \dots \oplus C_n \cdot H^2 \oplus L \cdot H) \oplus E_K(N || 1)$$
    Where $A$ is Associated Data, $C$ is Ciphertext, and $L$ is a length block.

If we have two messages $(C_1, T_1)$ and $(C_2, T_2)$ encrypted with the same nonce $N$ and same Associated Data $A$, the "mask" $E_K(N || 1)$ is identical for both.

---

## 3. Mathematical Theory: Recovering $H$

By XORing the two tags together:
$$T_1 \oplus T_2 = (C_1 \cdot H^2 \oplus \text{Terms}) \oplus (C_2 \cdot H^2 \oplus \text{Terms})$$

In this specific challenge, the Associated Data $A$ and the Length block $L$ are constant for a fixed-length username. Thus, they cancel out:
$$T_1 \oplus T_2 = (C_1 \oplus C_2) \cdot H^2$$

To find $H$, we solve:
$$H^2 = \frac{T_1 \oplus T_2}{C_1 \oplus C_2}$$
$$H = \sqrt{\frac{T_1 \oplus T_2}{C_1 \oplus C_2}}$$

Since this math happens in the finite field $GF(2^{128})$, we use **SageMath** to handle the polynomial arithmetic.

---

## 4. Exploitation Steps

### Step 1: Recover the Hash Key $H$
1. Connect to the server.
2. Call `Register` twice.
3. Receive `(Token1, User1)` and `(Token2, User2)`.
4. Extract $C_1, T_1$ and $C_2, T_2$.
5. Compute $H$ in SageMath.

### Step 2: Bypass the `cnt` Limit
After two registers, `cnt` becomes `0`. We cannot call `Login` or `Register` anymore for that nonce. We must call `Update` with a **new nonce** to reset `cnt` to `2`.

### Step 3: Recover the Mask for the New Nonce
Even though we know $H$, the authentication tag still requires the secret "Mask" ($E_K(N || 1)$) which is unique to every nonce. 
1. Call `Update` with a new nonce $N'$.
2. Call `Register` once to get a valid `(Token3, User3)`.
3. Calculate the "Combined Mask" (which includes the AD and Length terms):
   $$\text{CombinedMask} = T_3 \oplus (C_3 \cdot H^2)$$

### Step 4: Forgery
1. Since GCM is a stream cipher, we can recover the keystream for the current nonce:
   $$\text{Keystream} = C_3 \oplus \text{pad}(\text{User3})$$
2. Encrypt the username `admin`:
   $$C_{admin} = \text{pad}(\text{"admin"}) \oplus \text{Keystream}$$
3. Compute the forged tag:
   $$T_{admin} = (C_{admin} \cdot H^2) \oplus \text{CombinedMask}$$
4. Send the forged token to `Login` to get the flag.

---

## 5. Solver Script (SageMath)

```python
from sage.all import *
from Crypto.Util.Padding import pad
from pwn import *

# GCM Finite Field Setup
F128 = GF(2)['x']
modulus = F128([1, 1, 1, 0, 0, 0, 0, 1] + [0]*120 + [1])
F = GF(2**128, name='a', modulus=modulus)

def to_gf(b):
    res = F(0)
    for i in range(16):
        for j in range(8):
            if (b[i] >> (7 - j)) & 1:
                res += F.gen()**(i * 8 + j)
    return res

def from_gf(element):
    res = bytearray(16)
    coeffs = element.list()
    coeffs += [0] * (128 - len(coeffs))
    for i in range(128):
        if coeffs[i]:
            res[i // 8] |= (1 << (7 - (i % 8)))
    return bytes(res)

r = remote("pwn-6fa9f714d5.challenge.xctf.org.cn", 9999, ssl=True)

# Phase 1: Recover H
r.sendlineafter(b">", b"R")
tok1 = bytes.fromhex(r.recvline().strip().decode())
user1 = bytes.fromhex(r.recvline().strip().decode())

r.sendlineafter(b">", b"R")
tok2 = bytes.fromhex(r.recvline().strip().decode())
user2 = bytes.fromhex(r.recvline().strip().decode())

C1, T1 = to_gf(tok1[:16]), to_gf(tok1[16:])
C2, T2 = to_gf(tok2[:16]), to_gf(tok2[16:])
H = ((T1 + T2) / (C1 + C2)).sqrt()

# Phase 2: Reset cnt and get new mask
new_nonce = os.urandom(12)
r.sendlineafter(b">", b"U")
r.sendlineafter(b"hex)>", new_nonce.hex().encode())

r.sendlineafter(b">", b"R")
tok3 = bytes.fromhex(r.recvline().strip().decode())
user3 = bytes.fromhex(r.recvline().strip().decode())

# Phase 3: Forgery
C3, T3 = to_gf(tok3[:16]), to_gf(tok3[16:])
mask = T3 + (C3 * H^2)
ks = xor(tok3[:16], pad(user3, 16))
C_admin = xor(pad(b"admin", 16), ks)
T_admin = to_gf(C_admin) * H^2 + mask

forgery = C_admin + from_gf(T_admin)
r.sendlineafter(b">", b"L")
r.sendlineafter(b"hex)>", forgery.hex().encode())
r.interactive()
```

---

## 6. Conclusion
The challenge demonstrates that even a modern, "secure" cipher like AES-GCM is completely broken if nonces are reused. By exploiting the mathematical structure of the GMAC polynomial, we turned a restricted registration system into a full authentication bypass.

**Flag:** `flag{SBokYYXMJ4kLTdPnkvlosn53X8wJa8lN}`