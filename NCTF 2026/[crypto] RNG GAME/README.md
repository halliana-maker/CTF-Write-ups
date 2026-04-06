# RNG GAME - NCTF 2026 write up

## 1. TL;DR
The challenge asks us to find a different random seed that produces the exact same sequence of random numbers as a given seed. By exploiting the fact that Python's `random.seed(x)` internally takes the absolute value of integer inputs, we can simply provide the **negative version of the given seed** (`-seed`). This bypasses the "different seed" check but perfectly replicates the PRNG state.

---

## 2. What data/file we have and what is special
We were not provided with any source code or binaries, only a remote server address (`nc 114.66.24.221 46037`). 

**Interactive Details:**
When connecting to the server, the interaction looks like this:
```text
Welcome RNG GAME!!

In this game, I'll give you a seed that I used to generate a random number, and you need to give me a different seed that can generate the same random number. If you can do it, you will get the flag!!

Here is my seed: 103030500517678282732414474375943537424
Give me your seed: 
```
The server checks two things:
1. `player_seed != server_seed`
2. `random.seed(player_seed)` yields the exact same PRNG internal state as `random.seed(server_seed)`.

---

## 3. Problem Analysis (in details)
Since the challenge specifically involves a "Random Number Generator" and is likely running on Python (given the massive integer size and standard CTF infrastructure), we must look at how Python implements its `random` module.

Python uses the **Mersenne Twister (MT19937)** as its core generator. When you call `random.seed(x)`, Python takes the input `x` and converts it into an array of 32-bit unsigned integers to initialize the MT state. 

However, if `x` is an integer, the underlying CPython implementation (`Modules/_randommodule.c`) does something very specific before creating this array: **it takes the absolute value of the integer**. 

Because `abs(x) == abs(-x)`, passing `12345` and `-12345` will result in the exact same initialization array, and thus, the exact same sequence of random numbers. Since `-12345` is mathematically not equal to `12345`, this perfectly satisfies the server's requirement for a "different" seed.

---

## 4. Initial Guesses/First try
Without knowing the absolute value trick, a player might initially try:
*   **Type confusion:** Sending a string or float that evaluates to the same value (e.g., sending `"103030..."` instead of the raw integer, or `103030...0.0`). However, standard CTF inputs read from `stdin` use `int(input())`, which strictly requires a base-10 integer string and would crash on floats or fail equality checks.
*   **Hash Collisions:** Python 3 uses `hash()` for non-integer objects (like strings) to generate a seed. One might try to find two strings with the same hash. However, since the server gives us an *integer*, we must supply an *integer*.
*   **State brute-forcing:** Attempting to recover the 624-integer MT19937 state. This is over-complicating it, as we only need to bypass the seed validation, not predict unknown outputs.

The simplest, intended, and mathematically sound approach is the **integer negation (absolute value collision)**.

---

## 5. Exploitation Walkthrough / Flag Recovery
We wrote a short `pwntools` script to automate the interaction. The script connects to the server, extracts the large integer, multiplies it by `-1`, and sends it back.

### The Exploit Script:
```python
from pwn import *

def solve():
    HOST = '114.66.24.221'
    PORT = 46037

    try:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        io = remote(HOST, PORT)
        
        # Read the game banner and extract the seed
        io.recvuntil(b"Here is my seed: ")
        seed_str = io.recvline().strip().decode()
        original_seed = int(seed_str)
        
        print(f"[+] Received original seed: {original_seed}")
        
        # Calculate the collision seed by negating the integer
        # Python's random.seed() takes the absolute value of integers
        collision_seed = -original_seed
        print(f"[*] Sending collision seed: {collision_seed}")
        
        # Submit the seed
        io.sendlineafter(b"Give me your seed: ", str(collision_seed).encode())
        
        # Receive flag and print output
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
Running the script yields the following result:
```bash
$ python3 solve.py
[*] Connecting to 114.66.24.221:46037...
[+] Opening connection to 114.66.24.221 on port 46037: Done
[+] Received original seed: 103030500517678282732414474375943537424
[*] Sending collision seed: -103030500517678282732414474375943537424
[*] Waiting for server validation...
[+] Receiving all data: Done (124B)
[*] Closed connection to 114.66.24.221 port 46037

[+] Server Response:
-103030500517678282732414474375943537424
Congratulations!! Here is your flag:
flag{e38da06f-2afd-43cd-870a-5cd692a0014a}
```

**Flag:** `flag{e38da06f-2afd-43cd-870a-5cd692a0014a}`

---

## 6. What We Learned
*   **Python internals matter:** Functions in standard libraries often have undocumented or poorly understood edge cases. In CPython, `random.seed(int)` quietly takes the absolute value of an integer before processing it.
*   **Seed collisions are trivial for integers:** Because of this absolute value conversion, PRNG initialization in Python is not a strictly bijective (one-to-one) mapping. Every positive integer seed has a colliding negative counterpart.
*   **Security takeaway:** Never use `random.seed()` checks as a form of authentication or assume that different seed values guarantee different random sequences in standard libraries.