# RNG GAME revenge - NCTF 2026 write up

## 1. TL;DR
The "revenge" version of RNG GAME patches the trivial absolute value (`-seed`) bypass from the first iteration. To solve this, we exploit the underlying CPython implementation of `random.seed()` for large integers. By reverse-engineering how Python slices big integers into 32-bit arrays to initialize the Mersenne Twister (MT19937) state, we can forge a strictly larger integer (twice the bit-length) that algebraically cancels out the internal loop index `j`. This forces Python to generate the exact same PRNG sequence using a completely different, mathematically colliding seed.

---

## 2. What data/file we have and what is special
We are only provided with a remote socket (`nc 114.66.24.221 35636`). 

**Interactive Details:**
Upon connecting, the server provides a large randomly generated integer seed and challenges us to provide a *different* seed that yields the same PRNG output.
```text
Welcome RNG GAME!!

In this game, I'll give you a seed that I used to generate a random number, and you need to give me a different seed that can generate the same random number. If you can do it, you will get the flag!!

Here is my seed: 255544675997988579645942543950794519197
Give me your seed: 
```
If we input the exact same seed, the server responds with: `Don't use the same seed!!` and exits.

---

## 3. Problem Analysis (in details)
In Python, the `random` module uses the Mersenne Twister (MT19937). When you seed it with an integer (`random.seed(x)`), CPython executes the `init_by_array` function found in `Modules/_randommodule.c`.

Here is how Python processes the integer:
1. It takes the absolute value of the integer.
2. It slices the integer into an array of 32-bit unsigned integers, denoted as `key`. Let the length of this array be $L$.
3. It initializes the MT state array (`mt`) using a loop that runs $k = \max(624, L)$ times.

The core state mutation in that loop looks like this in C:
```c
mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL))
         + key[j] + j;  /* Non linear */
mt[i] &= 0xffffffffUL;

i++; j++;
if (i >= N) { mt[0] = mt[N-1]; i=1; }
if (j >= key_length) j=0;
```

Notice the term **`+ key[j] + j`**. The variable `j` acts as an index for the `key` array and resets to `0` when `j >= L` (where `L` is `key_length`). 

If we create a new integer that produces an array $K_2$ of length **$2L$**, the index $j$ will *not* wrap around at $L$; it will continue to $2L$. To make the MT state identical at every single step, the added term `(key[j] + j)` must be identical for both seeds.

This gives us a system of equations for our new array $K_2$:
*   **First half ($0 \le i < L$):** 
    $K_2[i] + i \equiv K_1[i] + i \pmod{2^{32}}$
    $\implies K_2[i] = K_1[i]$
*   **Second half ($L \le i < 2L$):**
    For the original seed, $j$ wraps around, so it uses $K_1[i - L] + (i - L)$.
    For our new seed, $j$ continues, so it uses $K_2[i] + i$.
    $K_2[i] + i \equiv K_1[i - L] + (i - L) \pmod{2^{32}}$
    $\implies K_2[i] \equiv K_1[i - L] - L \pmod{2^{32}}$

By concatenating these two halves back into a massive integer, we mathematically guarantee a PRNG state collision.

---

## 4. Initial Guesses/First try
1.  **The Negative Seed:** Naturally, the first attempt was to send `-seed` just like in the non-revenge version of the challenge. The server immediately rejected this, indicating the author either applied `abs()` before checking `seed1 == seed2`, or strictly enforced positive integers.
2.  **String/Type Confusion:** We might try passing string representations, floats, or objects with colliding `hash()` values. However, the server specifically attempts to parse our input using `int(input())` base 10, killing off type-confusion avenues.
3.  **State Recovery:** Attempting to use a tool like `randcrack` to predict outputs. This is unnecessary and impossible here, as we aren't given 624 outputs; we are forced to supply a colliding seed before any generation happens.

---

## 5. Exploitation Walkthrough / Flag Recovery

To weaponize the math from our problem analysis, we wrote a script that dynamically reconstructs a colliding seed from the server's seed. 

### The Exploit Script:
```python
from pwn import *

def solve():
    HOST = '114.66.24.221'
    PORT = 35636
    
    try:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        io = remote(HOST, PORT)
        
        # Read the game banner and extract the seed
        io.recvuntil(b"Here is my seed: ")
        seed_str = io.recvline().strip().decode()
        original_seed = int(seed_str)
        
        print(f"[+] Received original seed: {original_seed}")
        
        # Step 1: Slice the original seed into 32-bit chunks
        K1 =[]
        temp = abs(original_seed)
        while temp > 0:
            K1.append(temp & 0xFFFFFFFF)
            temp >>= 32
            
        L = len(K1)
        print(f"[*] Original seed key_length: {L}")
        
        # Step 2: Construct the colliding key array K2 of length 2L
        K2 = [0] * (2 * L)
        for i in range(L):
            # First half remains identical
            K2[i] = K1[i]
            # Second half accounts for the wrapped loop index 'j'
            K2[i + L] = (K1[i] - L) & 0xFFFFFFFF
            
        # Step 3: Reconstruct the new large integer from chunks
        collision_seed = 0
        for i in range(2 * L):
            collision_seed |= (K2[i] << (32 * i))
            
        print(f"[*] Synthesized collision seed: {collision_seed}")
        
        # Step 4: Submit the mathematically colliding seed
        io.sendlineafter(b"Give me your seed: ", str(collision_seed).encode())
        
        # Check validation
        print("[*] Waiting for server validation...")
        response = io.recvall(timeout=3).decode()
        
        print("\n[+] Server Response:")
        print(response.strip())
        
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    solve()
```

### Execution Output:
Running the exploit successfully bypasses the patched validation:
```bash
$ python3 solve.py
[*] Connecting to 114.66.24.221:35636...
[+] Opening connection to 114.66.24.221 on port 35636: Done
[+] Received original seed: 255544675997988579645942543950794519197
[*] Original seed key_length: 4
[*] Synthesized collision seed: 86957347094800099689023312582108325817372721723251481850992652536185559773853
[*] Waiting for server validation...
[+] Receiving all data: Done (161B)
[*] Closed connection to 114.66.24.221 port 35636

[+] Server Response:
86957347094800099689023312582108325817372721723251481850992652536185559773853
Congratulations!! Here is your flag:
flag{53e2d595-9d61-4720-8916-29d01ec4d459}
```

**Flag:** `flag{53e2d595-9d61-4720-8916-29d01ec4d459}`

---

## 6. What We Learned
*   **Length-Extension in PRNG Seeding:** We successfully performed a form of length-extension collision on Python's MT19937 seeder. If an initialization algorithm relies on loop indices (`j`) that wrap around, extending the input array to manipulate that wrap-around allows an attacker to construct highly controlled collisions.
*   **CPython Integer Storage:** This challenge required a solid understanding of how Python maps arbitrarily large integers into chunked arrays in C memory. 
*   **Security Takeaway:** Validating randomness is hard. Even when patching a known vulnerability (like the `abs()` bypass), the complexity of PRNG seed arrays leaves room for deep algebraic collisions. If uniqueness of state is cryptographically required, developers should use `os.urandom()` or cryptographically secure hashing (like SHA-256) on the input before feeding it into the generator, rather than relying on CPython's native MT seed routine.