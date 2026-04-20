# Storytime - BlueHens CTF 2026 Writeup

**Description :** "The day in the life of a UD student"

We are given a text file containing a story filled with puns and a ciphertext file. The objective is to decode the ciphertext by following the cryptographic clues hidden in the story.

---

## 1. TL;DR
The challenge involves a deeply nested ciphertext encrypted with 8 different layers of encoding and ciphers. The hints for each layer are hidden as puns within a short story. By extracting the ciphers (Hex, Base64, XOR, ROT13, Atbash, Rail Fence) and determining their exact order using a math riddle in the text, we built a Python script to peel back the layers and recover the final flag.

---

## 2. What Data/Files We Have and What is Special
We were provided with two files:
1. `storytime.txt`: A narrative text describing a "day in the life" of a University of Delaware (UD) student.
2. `ciphertext.txt`: A long string of hexadecimal characters starting with `4e545131...`

**Interactive/Server Details:** 
None. This is a purely offline cryptography/steganography challenge. No server interaction or web exploitation is required.

**What makes it special?**
Instead of guessing the cipher order blindly, the narrative explicitly dictates the required operations through wordplay and riddles. The challenge heavily tests your attention to detail and ability to parse instructions disguised as a story.

---

## 3. Problem Analysis (In Details)
Reading through `storytime.txt`, practically every sentence contains a cryptographic hint. Let's break down the translation of the narrative into crypto operations:

| Story Quote | Cryptographic Meaning |
|-------------|-----------------------|
| *"got cursed a few years back"* | **Hex Decode** (Cursed = "Hexed") |
| *"base was just 4 chunks away!"* | **Base64 Decode** (Minecraft chunk = 16 blocks; 16 x 4 = 64) |
| *"exorcise a lot more" / "UD's mascot"* | **XOR Cipher** ("eXORcise"). UD's mascot is the Blue Hen, giving us the key: `bluehens` |
| *"rotting my social battery" / "less than two weeks"* | **ROT13 Cipher** ("ROTting", 13 days) |
| *"bashing my head into a wall"* | **Atbash Cipher** ("at-BASH-ing") |
| *"two people... stabbed me in the back"* | **2-Rail Fence Cipher** (Backstabbing/Picket fence, 2 rails) |

**The Master Riddle (The tricky part!):**
> *"The position of my first plus one times the position of my second equals the position of my third!"*

This riddle dictates the placement of the **Hex Decodes** (the "hexes"/curses). 
* Let the **First Hex Decode** be at **Step 1**
* `(1 + 1) = 2`
* If the **Second Hex Decode** is at **Step 3**
* `2 * 3 = 6`
* Therefore, the **Third Hex Decode** must be at **Step 6**.

---

## 4. Initial Guesses / First Try
Our initial approach was to linearly map the ciphers to the story:
`Hex -> Base64 -> XOR -> ROT13 -> Atbash -> Rail Fence`.

However, after the Base64 decode, the output was *another* Hex string. When we tried to directly XOR that Hex string using the key `bluehens`, it produced a mangled output (`WX@\V[W...`). This later caused our script to crash with a `ValueError` because the characters weren't valid hex format.

**The Fix:** We had missed the master riddle! The output of the Base64 decode needed to be *Hex Decoded again* (Step 3) to turn it into raw bytes before applying the XOR operation. 

---

## 5. Exploitation Walkthrough / Flag Recovery

Here is the exact visual roadmap of how the ciphertext transforms layer by layer:

```mermaid
graph TD
    A[Ciphertext] -->|Step 1: Hex Decode| B[Base64 String]
    B -->|Step 2: Base64 Decode| C[Hex String]
    C -->|Step 3: Hex Decode| D[Raw Bytes]
    D -->|Step 4: XOR key='bluehens'| E[Shifted Hex String]
    E -->|Step 5: ROT13| F[Valid Hex String]
    F -->|Step 6: Hex Decode| G[ASCII String]
    G -->|Step 7: Atbash| H[Interleaved Flag]
    H -->|Step 8: 2-Rail Fence| I[Flag: udctf{c1ph3rs_ar3_Fun!}]
    
    style A fill:#2d2d2d,stroke:#fff,stroke-width:2px,color:#fff
    style I fill:#28a745,stroke:#fff,stroke-width:2px,color:#fff
```

### Execution Output
```text
Final Flag: udctf{c1ph3rs_ar3_Fun!}