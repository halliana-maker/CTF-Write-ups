# XorVault - 0xV01D CTF 2026 writeup

## Description

> Something is locked away. It was locked more than once, by more than one hand. Find what was left behind.  
> Flag format: `0xV01D{...}`  
> Hint: Focus on the order of operations applied to each byte, especially anything using `i % 8` or `d[i] ^= i`.

---

## Concept Map

```mermaid
flowchart TD
    A[Given Artifact: easy.zip] --> B[Extract cipher.txt]
    B --> C[Hex Ciphertext: 24 bytes]
    C --> D[Use Hint Analysis]
    D --> E["Repeated 8-byte key via i % 8"]
    D --> F["Per-byte XOR with index via d[i] ^= i"]
    D --> G["Another byte transform in between"]

    E --> H[Assume flag prefix: 0xV01D{]
    F --> H
    G --> H

    H --> I[Model encryption order candidates]
    I --> J[Find consistent pipeline]
    J --> K["Key = DE AD BE EF CA FE BA BE"]
    J --> L["Rotate left by 3 bits"]
    J --> M["Final XOR with i"]

    K --> N[Decrypt ciphertext]
    L --> N
    M --> N

    N --> O[Recovered plaintext]
    O --> P["0xV01D{X0R_V4ULT_0P3N3D}"]
```

---

## 1. TL;DR

The challenge gives us a single encrypted file, `cipher.txt`, containing a hex string.  
The hint strongly suggests a byte-wise transformation involving:

- a repeating 8-byte pattern using `i % 8`
- an XOR with the byte index using `d[i] ^= i`

By combining the known flag format `0xV01D{...}` with brute-force reasoning about operation order, we recover the encryption pipeline:

1. XOR each plaintext byte with an 8-byte repeating key
2. Rotate the result left by 3 bits
3. XOR with the byte index `i`

The repeating key is:

```text
DE AD BE EF CA FE BA BE
```

Decrypting the ciphertext yields:

```text
0xV01D{X0R_V4ULT_0P3N3D}
```

---

## 2. What Data/File We Have and What Is Special

### Provided file

The archive contains only one file:

```text
easy.zip
└── cipher.txt
```

After extraction, `cipher.txt` contains:

```text
77af45fddbd008307ff605c6fb50b9581cfd65f5307be109
```

### What is special about it?

Several things stand out immediately:

1. It is a hex string.
2. The length is `48` hex characters, which means `24` raw bytes.
3. The flag format is known: `0xV01D{...}`.
4. The hint directly points to byte-index-based logic:
   - `i % 8` suggests an 8-byte repeating operation, most likely a key
   - `d[i] ^= i` suggests a final or intermediate XOR with the byte position

---

## 3. Problem Analysis

We start with the ciphertext:

```text
77af45fddbd008307ff605c6fb50b9581cfd65f5307be109
```

Convert that from hex into bytes:

- 48 hex characters
- 24 encrypted bytes total

That size is realistic for a short flag like:

```text
0xV01D{................}
```

### Step 1: Use the hint correctly

The hint is the most important part of the challenge:

- `i % 8`
- `d[i] ^= i`

This strongly implies that encryption is applied **per byte** and depends on the byte index.

#### Meaning of `i % 8`

This usually means one of these:

- repeating 8-byte XOR key
- repeating 8-byte lookup table
- repeating 8-byte additive mask

The most likely pattern in CTFs is a repeating 8-byte key.

#### Meaning of `d[i] ^= i`

This means every byte is also XORed with its position:

```c
d[i] = d[i] ^ i;
```

That is a common obfuscation layer because it is simple, reversible, and changes every byte differently.

### Step 2: Recognize that order matters

The challenge description says:

> It was locked more than once, by more than one hand.

That tells us there are multiple transformations, not just one XOR.

The hint also says:

> Focus on the order of operations applied to each byte

So it is not enough to know the ingredients. We must determine the exact sequence.

A likely structure is:

1. XOR with repeating key
2. bit rotation
3. XOR with index

or some permutation of those.

### Step 3: Use the known plaintext format

We know the flag starts with:

```text
0xV01D{
```

That gives us 7 known plaintext bytes immediately.

Known-prefix attacks are extremely useful here because we can test candidate pipelines and see whether they produce a consistent 8-byte key.

### Step 4: Identify the missing operation

If we only try:

- XOR with 8-byte key
- XOR with index

we do **not** get a clean printable flag.

That tells us one more reversible transformation is involved.

A classic byte-wise reversible operation is a **bit rotation**:

- rotate left (`ROL`)
- rotate right (`ROR`)

Since the hint mentions order and per-byte operations, rotate is a strong candidate.

### Step 5: Find the correct pipeline

The valid encryption order turns out to be:

```text
cipher[i] = rol(plaintext[i] ^ key[i % 8], 3) ^ i
```

Where:

- `key = DE AD BE EF CA FE BA BE`
- `rol(x, 3)` means rotate left by 3 bits

This matches the clue perfectly:

- `i % 8` -> repeating 8-byte key
- `d[i] ^= i` -> XOR with index
- "locked more than once" -> multiple transformations layered together

---

## 4. Exploitation Walkthrough / Flag Recovery

To decrypt, we reverse the operations in reverse order.

Encryption was:

```text
cipher[i] = rol(plaintext[i] ^ key[i % 8], 3) ^ i
```

So decryption is:

1. XOR ciphertext byte with `i`
2. rotate right by 3
3. XOR with the repeating 8-byte key

### Decryption formula

```text
plaintext[i] = ror(cipher[i] ^ i, 3) ^ key[i % 8]
```

### Key used

```text
DE AD BE EF CA FE BA BE
```

### Python solve script

```python
cipher_hex = "77af45fddbd008307ff605c6fb50b9581cfd65f5307be109"
cipher = bytes.fromhex(cipher_hex)
key = bytes.fromhex("deadbeefcafebabe")

def ror(x, r):
    return ((x >> r) | (x << (8 - r))) & 0xff

plain = bytearray()

for i, b in enumerate(cipher):
    x = b ^ i
    x = ror(x, 3)
    x ^= key[i % 8]
    plain.append(x)

print(plain.decode())
```

### Output

```text
0xV01D{X0R_V4ULT_0P3N3D}
```

---

## 5. What We Learned

This challenge is a good example of why small reversing hints matter.

### Key takeaways

- A known flag format can drastically reduce the search space.
- `i % 8` is a strong indicator of a repeating 8-byte structure.
- `d[i] ^= i` is simple obfuscation, but it becomes stronger when combined with another transform.
- The **order of operations** matters as much as the operations themselves.
- Bit rotation is a common reversible layer in CTF encryption tasks.
- Verifying by re-encryption is the cleanest way to confirm the recovered logic.

### Practical lesson

When a challenge hints at per-byte transforms, do not just ask:

- "What operations were used?"

Also ask:

- "In what exact order were they applied?"
- "Which parts depend on index?"
- "Can I exploit known plaintext like the flag prefix?"

That mindset turns a messy brute-force problem into a structured reverse-engineering task.

