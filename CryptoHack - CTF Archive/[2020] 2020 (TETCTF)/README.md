# 2020 - TETCTF 2020 Writeup

**Description:**  "Pick two indices to reveal, then guess the 2020th number!"

We are given a connection to `archive.cryptohack.org 63222` and two files:
* `2020.py` - The challenge source code.
* `Dockerfile` - Shows the environment (Python 3.9).

## 1. TL;DR
The challenge generates 2020 random 32-bit integers using Python's default Mersenne Twister (MT19937) PRNG. We are only allowed to reveal **two** numbers from the sequence and must predict the 2020th number. By requesting indices `1396` and `1792`, untempering them to get their internal states, and taking a 50/50 guess on a single bit (the MSB of index `1395`), we can bypass the usual 624-number requirement to crack MT19937 and directly calculate the 2020th state using the generator's recurrence relation.

---

## 2. What Data/File We Have & What is Special
We are provided with `2020.py`, which contains the following core logic:
```python
nIndices = 2
indices =[int(input()) for _ in range(nIndices)]

for i in range(2019):
    r = random.getrandbits(32)
    print(r if i in indices else 'Nope!')

if int(input()) == random.getrandbits(32):
    print(os.environ["FLAG"])
```

### Interactive Flow:
1. **Server:** Prompts us to enter two indices (from `0` to `2018`).
2. **Player:** Sends two integers (e.g., `4` and `5`).
3. **Server:** Loops 2019 times. It prints the generated random number if the loop index matches our chosen indices; otherwise, it prints `Nope!`.
4. **Player:** Submits a guess for the 2020th number.
5. **Server:** Checks if the guess matches the next `random.getrandbits(32)`. If it does, we get the flag.

**What is special:** We only get **2** numbers out of a PRNG that usually requires **624** numbers to break. We cannot simply use standard tools like `randcrack`.

---

## 3. Problem Analysis (In Details)
Python's `random` module uses the **Mersenne Twister (MT19937)** algorithm. 

MT19937 maintains an internal state array of 624 32-bit integers. When a random number is requested, it takes the current internal state, applies a bitwise transformation called **tempering** (which is fully reversible), and outputs the result.

When the 624 internal states are exhausted, it generates the next 624 states using a **recurrence relation**. Let the internal states be $S_0, S_1, S_2, \dots$. The formula for any new state is:
$$S_{i+624} = S_{i+397} \oplus \text{Twist}(S_i, S_{i+1})$$

The `Twist` function works by concatenating the **Most Significant Bit (MSB)** of $S_i$ with the **lower 31 bits** of $S_{i+1}$, and then doing a bitwise shift and XOR. In Python-like pseudocode:
```python
y = (S[i] & 0x80000000) | (S[i+1] & 0x7FFFFFFF)
twist = (y >> 1) ^ (0x9908B0DF if (y & 1) else 0)
```

The challenge requires us to predict the **2020th number**, which is generated from state $S_{2019}$ (0-indexed).
If we map our target $S_{2019}$ to the recurrence formula ($i + 624 = 2019 \implies i = 1395$):
$$S_{2019} = S_{1792} \oplus \text{Twist}(S_{1395}, S_{1396})$$

Look closely at what the `Twist` function needs from $S_{1395}$ and $S_{1396}$:
* From **$S_{1396}$**: It needs the lower 31 bits.
* From **$S_{1395}$**: It ONLY needs the 1 Most Significant Bit (MSB).

---

## 4. Initial Guesses / First Try
* **First thought:** Use a known tool like `randcrack`.
* **Why it fails:** `randcrack` requires 624 consecutive outputs to completely reconstruct the 624-integer internal state. We only have 2 outputs.
* **Second thought:** Can we just ask for $S_{1395}$ and $S_{1396}$ to calculate the twist?
* **Why it fails:** If we ask for `1395` and `1396`, we still wouldn't know $S_{1792}$, which is required for the final XOR. We only have 2 choices, but the formula requires pieces of 3 different states.
* **The Breakthrough:** Since we only need **one single bit** (the MSB) from $S_{1395}$, it can only be `0` or `1`. We can simply **guess** this bit! This gives us a 50% chance of being correct. We can then use our 2 allowed queries to reveal $S_{1396}$ and $S_{1792}$.

---

## 5. Exploitation Walkthrough / Flag Recovery

Our attack plan:
1. Connect to the server and request indices `1396` and `1792`.
2. Parse the output to grab the values of $R_{1396}$ and $R_{1792}$.
3. **Untemper** these values to reveal the internal states $S_{1396}$ and $S_{1792}$.
4. **Guess** the MSB of $S_{1395}$ (we'll just assume it is $0$).
5. Calculate $S_{2019} = S_{1792} \oplus \text{Twist}(b_{1395}, S_{1396})$, where $b_{1395} \in \{0,1\}$ is the guessed MSB bit.
6. **Temper** $S_{2019}$ to get the final output $R_{2019}$.
7. Submit it. If we get "TetCTF{...}", we win. If not, rerun the script until our 50% guess is right.

### The Solve Script
```python
import socket

# Reverses the MT19937 right shift
def unshift_right(y, shift):
    x = 0
    for j in range(31, -1, -1):
        y_j = (y >> j) & 1
        x_j_plus_shift = (x >> (j + shift)) & 1 if (j + shift) <= 31 else 0
        x_j = y_j ^ x_j_plus_shift
        x |= (x_j << j)
    return x

# Reverses the MT19937 left shift
def unshift_left(y, shift, mask):
    x = 0
    for j in range(0, 32):
        y_j = (y >> j) & 1
        x_j_minus_shift = (x >> (j - shift)) & 1 if (j - shift) >= 0 else 0
        mask_j = (mask >> j) & 1
        x_j = y_j ^ (x_j_minus_shift & mask_j)
        x |= (x_j << j)
    return x

# Reverses the MT19937 tempering process to get the internal state
def untemper(y):
    y = unshift_right(y, 18)
    y = unshift_left(y, 15, 0xefc60000)
    y = unshift_left(y, 7, 0x9d2c5680)
    y = unshift_right(y, 11)
    return y

# Applies the MT19937 tempering process to get the final output
def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y

def solve():
    with socket.create_connection(("archive.cryptohack.org", 63222)) as sock:
        def read_until(delim):
            buf = b""
            while delim not in buf:
                buf += sock.recv(1)
            return buf

        read_until(b"number!\n")
        
        # 1. Request the two required indices
        sock.sendall(b"1396\n")
        sock.sendall(b"1792\n")
        
        r_1396 = r_1792 = 0
        for i in range(2019):
            line = read_until(b"\n").strip()
            if i == 1396:
                r_1396 = int(line)
            elif i == 1792:
                r_1792 = int(line)
                
        # 2. Untemper to reverse-engineer the inner states
        s_1396 = untemper(r_1396)
        s_1792 = untemper(r_1792)
        
        # 3. Guess MSB and execute the MT19937 Twist
        guessed_msb = 0  # 50% chance of being right
        
        y = guessed_msb | (s_1396 & 0x7FFFFFFF)
        a_val = (y >> 1) ^ (0x9908B0DF if (y & 1) else 0)
        s_2019 = s_1792 ^ a_val
        
        # 4. Temper back down to the target 2020th number
        r_2019 = temper(s_2019)
        
        # 5. Submit the guess
        sock.sendall(str(r_2019).encode() + b"\n")
        result = sock.recv(1024).strip()
        
        if b"TetCTF" in result:
            print("\n[+] SUCCESS! Flag found:")
            print(result.decode())
            return True
            
        print("[-] MSB was 1. Retrying...")
        return False

if __name__ == "__main__":
    for attempt in range(1, 10):
        print(f"Attempt {attempt}...")
        if solve():
            break
```

### Execution Output:
```text
$ python3 solve.py
Attempt 1...
[-] MSB was 1. Retrying...
Attempt 2...
[-] MSB was 1. Retrying...
Attempt 3...
[-] MSB was 1. Retrying...
Attempt 4...

[+] SUCCESS! Flag found:
TetCTF{2020_n0t_4_pr3d1ct4bl3_y34r}
```
*Note: Because our guess of the MSB being `0` has a 50% probability, it took 4 attempts for the script to hit the right permutation, exactly as mathematically expected.*

---

## 6. What We Learned
1. **MT19937 is heavily structured:** While tools like `randcrack` are great, understanding the underlying math of the Mersenne Twister recurrence relation allows you to exploit partial state leaks where automated tools fail.
2. **Minimal Data Leakage:** You don't always need the full 624 consecutive outputs to predict a future state. In this scenario, just **two outputs and a 1-bit guess** were enough to accurately predict numbers down the line. 
3. **Never use MT19937 for secrets:** Python's `random` module is strictly for statistical randomness, not cryptographic security. `secrets.randbits()` should always be used when security/unpredictability is required.