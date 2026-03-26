# TokenCrypt - BSidesSF CTF 2026

## 1. TL;DR
TokenCrypt is a custom 24-bit block cipher designed to encrypt LLM token IDs. The cipher alternates between a 16-round Feistel network and a linear affine layer. The vulnerability lies in an interactive REPL feature that allows players to downgrade the encryption from 1024 rounds to just 16 rounds (which equals exactly one Feistel chunk + one Affine layer). By performing a Chosen Plaintext Attack (CPA) on the 16-round mode, we canceled out the affine offset, found linear dependencies in the ciphertext space, and brute-forced the small 16-bit Feistel key. Once the non-linear Feistel key was known, we recovered the hidden affine matrix and offset using Gaussian elimination. Finally, we decrypted the 1024-round flag and decoded the resulting GPT-4o token IDs to get the plaintext flag.

## 2. What Data/Files We Have and What is Special
**Provided Materials:**
*   `tokencrypt.py`: The complete Python source code for the cryptosystem.
*   **A Remote TCP Endpoint (REPL):** A server providing an interactive shell (`tc.ai> `) to interact with the active cipher context.

**Special Features of TokenCrypt:**
*   **24-bit Block Size:** Extremely unusual for modern cryptography. It was designed specifically to map 1:1 with large LLM token dictionaries without packing overhead.
*   **96-bit Key Structure:** The key is parsed into three parts: a 16-bit Feistel key (`s`), a 56-bit matrix seed (`seed56`), and a 24-bit affine offset (`b24`).
*   **Token-Specific Constraints:** The REPL explicitly mentions it is built for LLMs. The `encrypt` command enforces a minimum token value of `100000` and a maximum budget of 1000 tokens per session.

## 3. The Server/Player Interaction
When connecting to the server via TCP/socat, we are greeted by the `TokenCrypt.AI` demo tool. The server generates a random 96-bit key for our session and drops us into a prompt:

```text
Welcome to the TokenCrypt.AI demo tool!

We're excited to share with you our state-of-the-art LLM token encryption.
While our revolutionary patented military-grade trade secret encryption technology
is optimized for GPT 5.x tokens, it will work on any LLM tokens.

<secure 96-bit key generated for this session>
Type 'help' to get started.

tc.ai> 
```

The `help` command reveals our available actions:
*   `getflag`: Returns the encrypted challenge flag.
*   `setsecurity`: Changes the round count. Options are `Fastest` (16), `Default` (256), or `Paranoid` (1024).
*   `encrypt`: Encrypts a provided JSON-like array of token IDs.

If we ask for the flag, the server uses the `Paranoid` 1024-round setting:
```text
tc.ai> getflag
tc.ai(1024,[9218349, 5163827, 3440583, 4312947, 1703605, 6651765, 2918541, 11024004, 4362039, 6900810, 8710139, 7973125, 7181461])
```
Because the key is randomized per session, we *must* exploit the system and recover the key within the same connection to decrypt these specific numbers.

## 4. Problem Analysis (In Details)
Let's analyze the mathematical structure of the cipher found in `tokencrypt.py`.

The cipher splits operations into "chunks". Every chunk consists of exactly **16 rounds**:
1.  **Feistel Core ($F_s$):** A 16-round Feistel network keyed by the 16-bit key `s`.
2.  **Affine Layer ($A$):** The 24-bit output is multiplied by a secret $24 \times 24$ invertible binary matrix $M$ (generated from `seed56`) and XORed with a 24-bit offset $b$ (`b24`), entirely over GF(2).

Mathematically, a single chunk operates as:
$$y = M \cdot F_s(x) \oplus b$$

If the security is set to `Paranoid` (1024 rounds), this chunk repeats $1024 / 16 = 64$ times. At 64 repeats, tracking the math is practically impossible due to extreme diffusion. 

## 5. Initial Guesses / First Try
*   *Attempt 1 (Full Key Brute Force):* The overall key is 96 bits. Trying $2^{96}$ combinations is impossible. The PRNG (`_xorshift64`) is only used for generating the matrix $M$, meaning there are no weak PRNG states to exploit during the encryption itself.
*   *Attempt 2 (Cryptanalysis of the 1024-round Feistel Network):* The S-box is only 4-bit, but performing differential or linear cryptanalysis across 1024 rounds of a constantly shifting affine layer is a dead end.
*   *The Breakthrough:* The `setsecurity` command allows us to change the number of rounds for the `encrypt` command. If we set it to `Fastest`, the round count becomes 16. **At 16 rounds, the cipher evaluates exactly ONE chunk!** This completely strips away the outer layers and exposes the core math: $y = M \cdot F_s(x) \oplus b$.

## 6. Exploitation Walkthrough / Flag Recovery

### Step 1: The Downgrade Attack
We interact with the REPL to fetch the Paranoid-level flag, and then immediately downgrade the security level to 16 rounds.

```text
tc.ai> setsecurity
Security level (Fastest, Default, Paranoid) [Default]: Fastest
tc.ai> 
```

### Step 2: Chosen Plaintext Attack (CPA)
We need to gather data to solve the single-chunk equation. We use the `encrypt` command to encrypt 35 sequential plaintexts (respecting the server's `100000` minimum value). 35 tokens easily fit under the 1000-token budget limit.

```text
tc.ai> encrypt
tokens>[100000, 100001, 100002, ..., 100034]
tc.ai(16,[1234567, 7654321, 2345678, ...])
```
We now have 35 known pairs of $(x_i, y_i)$.

### Step 3: Canceling the Offset and Finding Linear Dependencies
The affine offset $b$ prevents us from directly analyzing the matrix multiplication. To remove it, we XOR every ciphertext $y_i$ with the first ciphertext $y_0$:
$$Y_i = y_i \oplus y_0 = (M \cdot z_i \oplus b) \oplus (M \cdot z_0 \oplus b) = M \cdot (z_i \oplus z_0)$$

Let $Z_i = z_i \oplus z_0$ (where $z$ is the Feistel output before the matrix). We now have a strictly linear equation: $Y_i = M \cdot Z_i$.

We have 34 vectors ($Y_1$ through $Y_{34}$) in a 24-dimensional space (GF(2) is 24-bit). According to the Pigeonhole Principle, there *must* be linear dependencies. By applying Gaussian elimination on the $Y_i$ values, we find relationships where XORing a subset of $Y_i$ equals zero (e.g., $Y_1 \oplus Y_5 \oplus Y_9 = 0$).

### Step 4: Brute-Forcing the Feistel Key
Because $M$ is a linear matrix, if $Y_1 \oplus Y_5 \oplus Y_9 = 0$, then it **must** be true that $Z_1 \oplus Z_5 \oplus Z_9 = 0$.

The $Z$ values are just the differences of the Feistel network outputs, which *only depend on the 16-bit key `s`*. We don't need to know $M$ or $b$ to verify this!
We wrote a Python script to brute-force all 65,536 possible values of `s`. For each `s`, the script:
1. Computes the Feistel outputs for our chosen plaintexts.
2. Calculates $Z_i$.
3. Checks if the $Z_i$ values satisfy the exact same linear relations we found in $Y_i$.

This takes a fraction of a second and immediately reveals the correct `s` (e.g., `0x5573`).

### Step 5: Matrix and Offset Recovery
With the correct `s` in hand, we can easily calculate the true values of $Z_i$ for all 35 plaintexts. 
We now have 34 pairs of $(Z_i, Y_i)$ mapped by the equation $M \cdot Z_i = Y_i$. We map these into an augmented matrix and use Gaussian elimination over GF(2) to solve for the individual rows of $M$.
Once $M$ is recovered, calculating $b$ is trivial: $b = y_0 \oplus (M \cdot z_0)$.

### Step 6: Decryption and Token Decoding
We now possess the complete internal state of the cipher: `(s, M, b)`. We load this into our offline solver and decrypt the 1024-round flag array we grabbed at the start. 

The decryption outputs an array of integers:
`[1895, 37, 90, 13503, 70, 555, 26945, 315, 109569, 74208, 1565, 1782, 92]`

If converted to raw ASCII, this yields gibberish (`ݧ%Z㒿F...`). However, recalling the REPL prompt's flavor text ("*optimized for GPT 5.x tokens*"), we realize these are LLM token IDs. The presence of the large token ID `109569` indicates it exceeds GPT-4's older `cl100k_base` vocabulary limits. By importing OpenAI's `tiktoken` library and using the newer GPT-4o `o200k_base` encoding, the integers perfectly decode to readable text.

```python
import tiktoken
tokens =[1895, 37, 90, 13503, 70, 555, 26945, 315, 109569, 74208, 1565, 1782, 92]
enc = tiktoken.get_encoding("o200k_base")
print(enc.decode(tokens))
```

**Flag:** `CTF{chatgpt_slid_into_my_dms}`

## 7. What We Learned
1.  **Downgrade Attacks are Lethal:** Offering users a "fast mode" with fewer rounds completely nullified the security of the 1024-round "paranoid mode". Because both modes shared the exact same key state, breaking the weak mode broke the entire system.
2.  **Linear Algebra Defeats Obfuscation:** You don't need to know the initial 56-bit seed or the PRNG algorithm used to generate the matrix. Because the matrix operation is linear over GF(2), simply observing enough input/output pairs allows you to recreate the matrix mathematically.
3.  **Isolation of Non-Linear Components:** The design flawed itself by sandwiching a small, brute-forceable non-linear element (the 16-bit Feistel core) against a purely linear element (the matrix). By using differential cryptanalysis (XORing ciphertexts to drop the constant $b$), we bypassed the linear layer entirely to attack the non-linear layer in isolation.
4.  **CTFs in the AI Era:** Recognizing modern tokenizers (like distinguishing between `cl100k_base` and `o200k_base` via token ID size bounds) is a fun, modern twist required in contemporary cryptography challenges.