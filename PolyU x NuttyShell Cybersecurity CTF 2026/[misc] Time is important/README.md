# Write-up: Time is important (Misc/Crypto)
- Description: The key is ticking. Btw, i like Japan.

## 1. TL;DR
The challenge uses a stream cipher (XOR) where the key is the SHA-256 hash of a timestamp string (`YYYYMMDDHHMMSS`) plus the suffix `"salt"`. By XORing the known flag prefix (`PUCTF26{`) with the provided ciphertext, we recovered a fragment of the key. We then brute-forced the timestamp within a narrow window (using Japan Standard Time as hinted) to find the full 32-byte SHA-256 key and decrypt the flag.

## 2. Problem Analysis
We are provided with a partial Python script and two hex-encoded ciphertexts from a remote server.

### Key Findings from Source:
*   **Key Generation:** The key is generated via `hashlib.sha256(material.encode()).digest()`.
*   **The Material:** `material = time_str + "salt"`, where `time_str` follows the format `%Y%m%d%H%M%S`.
*   **Encryption:** A standard XOR function (`rox`) is used.
*   **Hints:** "Time is important" and "I like Japan" suggest the server's internal clock is set to **JST (UTC+9)**.

### Mathematical Primitive:
In XOR encryption:
$$C = P \oplus K$$
$$P = C \oplus K$$
$$K = C \oplus P$$
Where $C$ is Ciphertext, $P$ is Plaintext, and $K$ is the Key. Since the SHA-256 key is 32 bytes (256 bits) and the flag is longer, the XOR key repeats ($K_{i \pmod{32}}$).

## 3. Initial Guesses & First Try
Upon connecting to the service twice, we received two different hex strings:
1. `b3f6f6306adf4758...`
2. `47f5aa59b3621d54...`

The fact that the output changes every few seconds confirms the `time_str` is the variable factor. The "Japan" hint is crucial; if we used UTC or our local time for brute-forcing, we would never find the key unless we accounted for the +9 hour offset.

## 4. Exploitation Walkthrough

### Step 1: Recover Key Fragment
The flag format starts with `PUCTF26{`. We XOR the first 8 bytes of the ciphertext with this prefix to find the first 8 bytes of the SHA-256 hash:
```python
c1 = bytes.fromhex('b3f6f6306adf4758...')
prefix = b"PUCTF26{"
key_fragment = bytes([c1[i] ^ prefix[i] for i in range(8)])
# Result: e3a3b5642ced7123
```

### Step 2: Timestamp Brute-force
We iterate through possible timestamps (YYYYMMDDHHMMSS) around the current date. For each, we calculate `SHA256(timestamp + "salt")` and check if the first 8 bytes match our fragment.

```python
import hashlib
from datetime import datetime, timedelta

target = "e3a3b5642ced7123"
# Searching around the time of the challenge (March 2026) in JST
start = datetime(2026, 3, 7, 11, 20, 0) 

for i in range(3600): # Check 1 hour window
    test_time = (start + timedelta(seconds=i)).strftime("%Y%m%d%H%M%S")
    h = hashlib.sha256((test_time + "salt").encode()).digest()
    if h.hex().startswith(target):
        print(f"Found! Time: {test_time}")
        # Found: 20260307112318
```

### Step 3: Decryption
Using the discovered timestamp `20260307112318`, we regenerate the full 32-byte key and XOR it against the entire ciphertext.

```python
def rox(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

full_key = hashlib.sha256(b"20260307112318salt").digest()
flag = rox(c1, full_key)
print(flag.decode())
```

**Final Flag:**
`PUCTF26{Tim3lsk3Y_mqJhz4viP5G3zUbx4HhYEhnWrDRz50Dy}`

## 5. What We Learned
1.  **Time as Entropy:** Using system time as a source of randomness for cryptographic keys is insecure because the search space (seconds in a day) is small enough to brute-force easily.
2.  **Known Plaintext Attacks:** XOR encryption is vulnerable if any part of the original message (like a standard flag header) is known.
3.  **Timezone Context:** In "Misc" challenges, flavor text like "I like Japan" is often a technical hint regarding environment variables like `TZ` (Timezone).