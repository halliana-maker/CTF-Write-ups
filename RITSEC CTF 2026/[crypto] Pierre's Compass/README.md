# Pierre's Compass – RITSEC CTF 2026 write up

## 1. TL;DR
The challenge revolves around a custom PRNG combining three Linear Congruential Generators (LCGs). The name "Pierre" and "three hidden mechanisms" heavily hint at **Pierre L'Ecuyer's combined LCG algorithm**. By recognizing that L'Ecuyer’s formula operates modulo $m_1 - 1$ (which perfectly matched the provided 94-character alphabet) and assuming standard Lehmer properties ($c = 0$), we reduced the search space of multipliers ($a_1, a_2, a_3$) to just $\approx 60,000$ combinations. A simple offline brute-force attack looking for the known plaintext flag format (`RS{`) instantly yielded the flag.

## 2. What Data/Files We Have
This was a purely **offline cryptography challenge**. There was no interactive server or Netcat (`nc`) connection involved.

We were provided a single text file (`params.txt`) containing the following:
```text
characters:
    G!{Qq)EPU-M7yNAKnF%fS=\Z?;+.T2/8Lx65'@*VBw,#k:|~Dr`eOa9H"hb>3^<Jp}[&$iXogzl4vWu(tsc]1YmC_RI0jd
parameters:
    m1 = 95
    m2 = 37
    m3 = 19
    s1 = 11
    s2 = 29
    s3 = 7
```

**What is special here:**
1. **The Alphabet Length:** If you count the characters in the `characters` string, there are exactly **94** characters.
2. **The Moduli:** We are given 3 moduli ($m_1, m_2, m_3$) and 3 seeds ($s_1, s_2, s_3$), but the multipliers ($a$) and increments ($c$) are missing.
3. **The Target Modulus:** $m_1$ is $95$. Notice that $m_1 - 1 = 94$, which identically matches our alphabet length!

## 3. Problem Analysis (In Detail)
The description mentions:
> *"There once was a French pirate named Pierre... Each turn of its needle is driven by not one, but three hidden mechanisms (linear congruential generators) working together..."*

In cryptography and computer science, combining multiple PRNGs is a classic way to increase the period length and statistical randomness. The most famous mathematician associated with combining LCGs is **Pierre L'Ecuyer**, who published a highly influential paper on the subject in 1988.

A standard single LCG is defined as:
$X_{n+1} = (a \cdot X_n + c) \pmod m$

L'Ecuyer's combined generator usually relies on Lehmer RNGs (where the increment $c = 0$) and combines the outputs of $k$ generators using the following formula:
$Z_n = \left( \sum_{i=1}^{k} (-1)^{i-1} X_{i,n} \right) \pmod{m_1 - 1}$

For $k = 3$, the output sequence $Z_n$ is computed as:
**$Z_n = (X_{1,n} - X_{2,n} - X_{3,n}) \pmod{m_1 - 1}$**

The output $Z_n$ is an integer between $0$ and $m_1 - 2$. In our challenge, $m_1 = 95$, meaning $Z_n \pmod{94}$ gives an index from $0$ to $93$ — precisely the indices needed to map to our 94-character alphabet!

## 4. Initial Guesses / First Try
Initially, without immediately applying the $-1$ offset to the modulus, one might assume the combination simply adds the outputs modulo $m_1$:
$Z_n = (X_{1,n} + X_{2,n} + X_{3,n}) \pmod{95}$

If you attempt a Known Plaintext Attack (Meet-In-The-Middle) using this formula, you run into two issues:
1. **IndexError:** The generated $Z_n$ can be $94$, but the alphabet max index is $93$. If you try to pad the alphabet with a space to make it length 95, the output is gibberish.
2. **False Positives:** By trying to solve for $c \neq 0$ and $m = 95$, the math allows for *degenerate states* (e.g., $a_2 = 1, c_2 = 0$, meaning the second generator is stuck outputting a constant). This results in false matches that pass the `RS{` check but result in looping garbage text (e.g., `~RS{eVBL!>XW=RS{eVBL...`).

The crucial pivot was realizing that the author intended for $c_1 = c_2 = c_3 = 0$ (standard L'Ecuyer/Lehmer generator) and that the combination strictly utilizes modulo $94$, cleanly avoiding the `IndexError` entirely.

## 5. Exploitation Walkthrough / Flag Recovery
Because we know $c = 0$, we are missing only the multipliers ($a_1, a_2, a_3$). We can determine the maximum bounds for the search:
* $a_1 \in[1, 94]$
* $a_2 \in [1, 36]$
* $a_3 \in [1, 18]$

Total combinations to check: $94 \times 36 \times 18 = 60,912$.
This search space is incredibly small. We can write a simple Python script to iterate through all possible $a$ values, generate a sequence of indices, map them to the alphabet, and check if the resulting string contains our known flag prefix `"RS{"`.

### The Exploit Script:
```python
import sys
import re

chars = r"""G!{Qq)EPU-M7yNAKnF%fS=\Z?;+.T2/8Lx65'@*VBw,#k:|~Dr`eOa9H"hb>3^<Jp}[&$iXogzl4vWu(tsc]1YmC_RI0jd"""

m1, m2, m3 = 95, 37, 19
s1, s2, s3 = 11, 29, 7

# Alphabet size is exactly 94
L = len(chars)

def is_valid_flag(s):
    # Search for RS{ followed by reasonable flag characters and a closing brace
    match = re.search(r'RS\{[A-Za-z0-9_!@#\$\%\^&\*\-\+=]+\}', s)
    if match:
        return True, match.group(0)
    return False, ""

def solve_c0():
    print("[*] Brute-forcing all a-values with c=0 (Lehmer/L'Ecuyer standard)...")
    # L'Ecuyer typically uses c=0 for the constituent generators.
    # Total combinations: 94 * 36 * 18 = 60,912 (instant)
    for a1 in range(1, m1):
        for a2 in range(1, m2):
            for a3 in range(1, m3):
                # Generate 50 chars
                x1, x2, x3 = s1, s2, s3
                msg1, msg2, msg3, msg4 = [], [], [],[]
                
                for _ in range(60):
                    x1 = (a1 * x1) % m1
                    x2 = (a2 * x2) % m2
                    x3 = (a3 * x3) % m3
                    
                    # Try L'Ecuyer variants modulo 94
                    Z1 = (x1 - x2 - x3) % 94
                    Z2 = (x1 + x2 + x3) % 94
                    Z3 = (x1 - x2 + x3) % 94
                    Z4 = (x1 + x2 - x3) % 94
                    
                    msg1.append(chars[Z1])
                    msg2.append(chars[Z2])
                    msg3.append(chars[Z3])
                    msg4.append(chars[Z4])
                    
                for s_msg in["".join(msg1), "".join(msg2), "".join(msg3), "".join(msg4)]:
                    if "RS{" in s_msg:
                        valid, flag = is_valid_flag(s_msg)
                        if valid:
                            print(f"\n[+] VALID FLAG FOUND (c=0)!")
                            print(f"a = ({a1}, {a2}, {a3})")
                            print(f"Flag: {flag}")
                            print(f"Full text: {s_msg}")
                            return True
    return False

if solve_c0():
    sys.exit(0)

print("[-] Not found with c=0. Running generalized MITM with c != 0...")

# Use MITM for c != 0
target_R = chars.index('R')
target_S = chars.index('S')
target_brace = chars.index('{')
MAX_OFFSET = 30

valid_x1_by_offset = {off: {} for off in range(MAX_OFFSET)}
for a1 in range(1, m1):
    for c1 in range(m1):
        x = s1
        seq =[]
        for _ in range(MAX_OFFSET + 3):
            seq.append(x)
            x = (a1 * x + c1) % m1
        
        for off in range(MAX_OFFSET):
            key = (seq[off], seq[off+1], seq[off+2])
            valid_x1_by_offset[off][key] = (a1, c1)

for a2 in range(1, m2):
    for c2 in range(m2):
        x = s2
        seq2 =[]
        for _ in range(MAX_OFFSET + 3):
            seq2.append(x)
            x = (a2 * x + c2) % m2
            
        for a3 in range(1, m3):
            for c3 in range(m3):
                x = s3
                seq3 =[]
                for _ in range(MAX_OFFSET + 3):
                    seq3.append(x)
                    x = (a3 * x + c3) % m3
                    
                for sgn2 in [1, -1]:
                    for sgn3 in[1, -1]:
                        for offset in range(MAX_OFFSET):
                            v2_0, v2_1, v2_2 = seq2[offset], seq2[offset+1], seq2[offset+2]
                            v3_0, v3_1, v3_2 = seq3[offset], seq3[offset+1], seq3[offset+2]
                            
                            req0 = (target_R - sgn2*v2_0 - sgn3*v3_0) % 94
                            req1 = (target_S - sgn2*v2_1 - sgn3*v3_1) % 94
                            req2 = (target_brace - sgn2*v2_2 - sgn3*v3_2) % 94
                            
                            key = (req0, req1, req2)
                            if key in valid_x1_by_offset[offset]:
                                a1, c1 = valid_x1_by_offset[offset][key]
                                
                                msg =[]
                                curr1, curr2, curr3 = s1, s2, s3
                                for _ in range(70):
                                    Z = (curr1 + sgn2*curr2 + sgn3*curr3) % 94
                                    msg.append(chars[Z])
                                    curr1 = (a1 * curr1 + c1) % m1
                                    curr2 = (a2 * curr2 + c2) % m2
                                    curr3 = (a3 * curr3 + c3) % m3
                                    
                                s = "".join(msg)
                                valid, flag = is_valid_flag(s)
                                if valid:
                                    print(f"\n[+] VALID FLAG FOUND (c != 0)!")
                                    print(f"a = ({a1}, {a2}, {a3}) | c = ({c1}, {c2}, {c3}) | Signs = (+, {sgn2}, {sgn3})")
                                    print(f"Flag: {flag}")
                                    print(f"Full text: {s}")
                                    sys.exit(0)

print("[-] Search completed. Could not find a strictly formatted flag.")
```

### Execution Output:
```text
[*] Brute-forcing all a-values with c=0 (Lehmer/L'Ecuyer standard)...

[+] VALID FLAG FOUND (c=0)!
a = (69, 30, 2)
Flag: RS{trU1y_ch40TiC}
Full text: RS{trU1y_ch40TiC}]RS{trU1y_ch40TiC}]RS{trU1y_ch40TiC}]RS{trU
```
The PRNG falls into a clean, repeating loop, continuously printing the flag.

**Flag:** `RS{trU1y_ch40TiC}`

## 6. What We Learned
1. **OSINT in Crypto Descriptions:** In crypto CTF challenges, flavor text is rarely just flavor. "Pierre" and "combining three generators" was a deliberate, direct reference to **Pierre L'Ecuyer**, bridging the gap between an impossible math problem and a known standard algorithm.
2. **Mind the Constraints:** A 94-character alphabet paired with an $m_1 = 95$ modulus is a glaring mathematical hint towards $m-1$ arithmetic operations. 
3. **Lehmer Generator Assumptions:** When encountering unknown LCG constants, always check if $c = 0$ (a Lehmer RNG) first. It dramatically shrinks the brute-force search space from billions of possibilities to mere thousands, shifting the challenge from requiring complex Meet-In-The-Middle attacks to a simple instant brute-force.