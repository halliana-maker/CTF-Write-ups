# file-transfer - JerseyCTF VI Wripteup

## Description

Our network security solution has alerted us to some suspicious traffic from a user's workstation. Can you help us figure out what is going on?

This is the 3rd time this month something happened with this user, we really need to improve our password policies...

**Flag Format:** `jctf{...}`

---

# 1. TL;DR

* SMB authentication uses weak password: `password`
* SMB3 traffic is encrypted, requiring key derivation to decrypt
* Extracted uploaded malware: `DaVinci.exe`
* Malware communicates with a C2 server using XOR encoding
* XOR key recovered and applied per chunk
* Flag found in decoded C2 command

**Final Flag:**

```
jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}
```

---

# 2. Provided Data & What’s Special

## Given File

* `export.pcap`

## Observations

* Contains SMB traffic (port 445)
* Contains a secondary TCP stream (port 55544)
* SMB traffic is encrypted (SMB3)
* Challenge hint indicates password reuse

This strongly suggests credential-based compromise.

---

# 3. Problem Analysis

## Step 1 — Protocol Identification

```
tshark -r export.pcap -q -z io,phs
```

Findings:

* SMB is dominant
* Additional small TCP stream exists

---

## Step 2 — Extract NTLMv2 Authentication

From SMB traffic:

* Domain: `IT640`
* User: `operator1`
* Workstation: `W11-C1`

Captured:

* Server challenge
* NTLMv2 response

---

## Step 3 — Crack Password

Testing weak passwords:

```
password = "password"
```

Verification:

```
HMAC-MD5(server_challenge + blob) == NTProofStr
```

Password is confirmed.

---

## Step 4 — SMB Encryption Barrier

After authentication:

* SMB3 encrypts traffic
* No plaintext data visible

Need to derive session keys to decrypt.

---

# 4. Initial Attempts

## Attempt 1 — String search

```
strings export.pcap | grep jctf
```

No result.

## Attempt 2 — Use password as flag

```
jctf{password}
```

Incorrect.

## Attempt 3 — Decode side channel directly

Produced unreadable output.

Conclusion: deeper analysis required.

---

# 5. Exploitation Walkthrough

## Step 5.1 — Session Key Derivation

```
SessionBaseKey = HMAC(NTLMv2_hash, NTProofStr)
SessionKey = RC4(SessionBaseKey, EncryptedSessionKey)
```

---

## Step 5.2 — SMB3 Key Derivation

Using pre-auth hash:

```
SMBC2SCipherKey
SMBS2CCipherKey
```

Derived using KDF with session key and pre-auth hash.

---

## Step 5.3 — Decrypt SMB Traffic

* Identify SMB transform packets (`0xFD 'SMB'`)
* Decrypt using AES-GCM
* Recover plaintext SMB messages

---

## Step 5.4 — Recover Uploaded File

Reconstructed:

```
DaVinci.exe
```

Indicates malware upload via SMB.

---

## Step 5.5 — Analyze Side Channel

Traffic between:

```
10.1.2.210 → 10.1.2.211:55544
```

Commands sent:

```
CMD-SEQ-A
CMD-SEQ-B
CMD-SEQ-C
CMD-SEQ-D
```

---

## Step 5.6 — Reverse Encoding

Recovered XOR key from malware:

```
sorry_im_not_the_flag_:)
```

Important detail:

* XOR key resets for each response chunk

---

## Step 5.7 — Decode C2 Responses

Decoded output:

```
start "" "C:\Program Files\DaVinci\latmove.bat"-wk

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "DaVinci" /t REG_SZ /F /D "C:\Program Files\DaVinci\DaVinci.exe"[jk

echo Mess with the best, die like the rest >> C:\Users\Public\Desktop\pwnd.txt & echo jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce} >> C:\Users\Public\Desktop\pwnd.txt
```

---

## Step 5.8 — Extract Flag

From third command:

```
jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}
```

---

# 6. What We Learned

## Security Insights

* Weak passwords can fully compromise systems
* NTLMv2 is vulnerable to offline attacks
* SMB3 encryption is ineffective if keys are recoverable
* Malware often uses simple obfuscation (e.g., XOR)

---

## CTF Takeaways

* Always inspect authentication flows
* Look for secondary channels
* Encryption often adds steps, not impossibility
* Try XOR and chunk-based decoding for unknown encodings

---

## Key Insight

The challenge requires chaining multiple concepts:

```
SMB authentication → key derivation → decryption → malware extraction → XOR decoding
```

---

# Final Answer

```
jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}
```
