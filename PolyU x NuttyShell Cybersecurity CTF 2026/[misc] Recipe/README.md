# Write-up: Recipe (Misc) - PolyU CTF 2026


## 1. TL;DR
The challenge provided a 5MB file named `dishes`. It was a "Russian Doll" (Matryoshka) style challenge containing **256 nested layers**. Each layer was protected by a combination of a **Substitution Cipher**, a **Base Encoding** (Base64, Base32, or Base85), and a **Compression Algorithm** (Zlib or Gzip). By writing a robust Python script to automate the "peeling" process, we recovered the flag at the final layer.

## 2. Problem Analysis
We were given a text file named `dishes`. 
- **File Metadata:** Running `file dishes` initially reported it as ASCII text with very long lines. However, a hex dump revealed the magic bytes `1f 8b 08 00`, indicating the file was actually a **Gzip-compressed** archive.
- **Layer Structure:** Once decompressed, the file followed a repeating pattern:
  - **Line 1 (The Key):** A string containing a 92-character shuffled alphabet (often prefixed with tags like `cipherA:`, `cipherB:`, etc.).
  - **The Rest (The Data):** A large block of scrambled text.
- **Decryption Logic:** When the data was decrypted using the substitution map from Line 1, it revealed the string: `PLAINTEXT:<encoded_blob>`. This blob was the next layer, encoded and compressed.

## 3. Initial Guesses & Trials
### First Try: Manual Analysis
We initially looked for common "Recipe" ciphers like **CyberChef** recipes or the **Chef** esoteric programming language. However, the presence of `PLAINTEXT:` and `cipherX:` tags suggested a custom recursive encryption.

### Second Try: Simple Scripting
An initial attempt to split the key line in half failed because the "Key Line" wasn't always a fixed length, and the tags (like `cipherxZ;`) varied in size. We realized the script needed to be "smarter" and search for the correct 92-character mapping window dynamically.

### Third Try: Encoding Conflicts
We discovered that different layers used different "flavors" of encoding. Layer 1 used **Base85**, but Layer 10 used **Base32**. Base32 is notoriously strict about padding (`=`), which caused standard decoders to fail. The script had to be updated to handle missing padding and detect the compression type (Zlib vs. Gzip) automatically.

## 4. Exploitation Walkthrough / Flag Recovery
To reach the flag, we developed a Python solver that performed the following loop for 256 iterations:

1.  **Decompression:** If the file started with `1f 8b`, decompress it using Gzip.
2.  **Substitution Map Discovery:** Slide a 92-character window across the first line to find a mapping that, when applied to the ciphertext, produced the header `PLAINTEXT:`.
3.  **Substitution Decryption:** Use `str.maketrans` to revert the character scrambling.
4.  **Base Decoding:** Attempt to decode the payload using **Base85, Base64, and Base32** (with manual padding correction).
5.  **Decompression:** Attempt to decompress the resulting bytes using **Zlib** or **Gzip**.
6.  **Recurse:** Use the output as the input for the next iteration.

### Automated Peeling (Summary of Layers):
- **Layer 1:** Base85 + Zlib
- **Layer 10:** Base32 + Gzip
- **Layer 20:** Base64 + Gzip
- ...
- **Layer 256:** Flag Found!

### Flag Recovery
After peeling 256 layers, the script successfully extracted the flag:
**`PUCTF26{y0u_4re_m4st3r_ln_r3v3r53_b453_me554g3_cb6a739ace061277c5ec70e7abfc7c36}`**

## 5. The Exploit
```python
import base64
import zlib
import bz2
import gzip
import lzma
import re
import os

# The standard 92-character set used as the reference for substitution
STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"

def force_base32_decode(data):
    """Base32 decoding with correct padding correction."""
    data = data.upper().rstrip('=')
    # Valid Base32 lengths are n % 8 in [0, 2, 4, 5, 7]
    missing_padding = len(data) % 8
    if missing_padding == 2: data += '======'
    elif missing_padding == 4: data += '===='
    elif missing_padding == 5: data += '==='
    elif missing_padding == 7: data += '='
    elif missing_padding == 0: pass
    else: return None # Invalid length
    try:
        return base64.b32decode(data)
    except:
        return None

def universal_decode(encoded_text):
    """Attempts to decode and decompress the payload using all common CTF formats."""
    encoded_text = "".join(encoded_text.split()) # Remove any whitespace
    
    # Define potential Base decoders
    base_attempts = [
        ('Base85', lambda x: base64.b85decode(x)),
        ('Ascii85', lambda x: base64.a85decode(x)),
        ('Base64', lambda x: base64.b64decode(x + "====")),
        ('Base32', lambda x: force_base32_decode(x)),
        ('Hex', lambda x: base64.b16decode(x, casefold=True)),
    ]
    
    # Define potential Compression decoders
    compression_attempts = [
        ('zlib', zlib.decompress),
        ('bz2', bz2.decompress),
        ('lzma', lzma.decompress),
        ('gzip', gzip.decompress),
        ('deflate', lambda d: zlib.decompress(d, -15)) # Raw deflate
    ]
    
    for b_name, b_func in base_attempts:
        try:
            raw_bytes = b_func(encoded_text)
            if not raw_bytes: continue
            
            for c_name, c_func in compression_attempts:
                try:
                    res = c_func(raw_bytes).decode('ascii', errors='ignore')
                    # Validation: The next layer must contain 'PLAINTEXT', 'cipher', or the Flag
                    if any(marker in res for marker in ["PLAINTEXT", "cipher", "PUCTF26{"]):
                        return res, f"{b_name} + {c_name}"
                except: continue
            
            # Check if it was encoded but NOT compressed
            res_raw = raw_bytes.decode('ascii', errors='ignore')
            if any(marker in res_raw for marker in ["PLAINTEXT", "cipher", "PUCTF26{"]):
                return res_raw, f"{b_name} (No Compression)"
        except: continue
        
    return None, None

def find_substitution_map(key_line, ciphertext_sample):
    """Finds the 92-char shuffled alphabet within the key line."""
    for i in range(len(key_line) - 91):
        shuffled_candidate = key_line[i:i+92]
        trans = str.maketrans(shuffled_candidate, STD_ALPHABET)
        # Check if this mapping correctly recovers the 'PLAINTEXT:' header
        if ciphertext_sample.translate(trans).startswith("PLAINTEXT:"):
            return trans
    return None

def solve():
    filename = 'dishes'
    if not os.path.exists(filename): filename = 'dishes.txt'
    
    print(f"[*] Opening {filename}...")
    
    with open(filename, 'rb') as f:
        file_data = f.read()
        if file_data.startswith(b'\x1f\x8b'):
            print("[+] Initial Gzip detected. Decompressing...")
            current_content = gzip.decompress(file_data).decode('ascii', errors='ignore')
        else:
            current_content = file_data.decode('ascii', errors='ignore')

    iteration = 0
    while True:
        iteration += 1
        lines = current_content.strip().splitlines()
        if len(lines) < 2:
            if "PUCTF26{" in current_content: break
            print("[-] No more layers found.")
            break
            
        key_line = lines[0]
        ciphertext = "".join(lines[1:])
        
        # Find mapping
        mapping = find_substitution_map(key_line, ciphertext[:30])
        
        if not mapping:
            print(f"[-] Critical Error at Layer {iteration}: Could not find substitution map.")
            print(f"Debug (Key Line): {key_line[:100]}...")
            print(f"Debug (Scrambled Ciphertext): {ciphertext[:50]}...")
            break
            
        decrypted = ciphertext.translate(mapping)
        
        if "PLAINTEXT:" in decrypted:
            payload = decrypted.split("PLAINTEXT:")[1]
            next_layer, recipe = universal_decode(payload)
            
            if not next_layer:
                print(f"[-] Error at Layer {iteration}: Decoding/Decompression failed.")
                print(f"Debug (Decrypted Payload Prefix): {payload[:100]}...")
                break
                
            current_content = next_layer
            if iteration % 10 == 0 or iteration == 1:
                print(f"[*] Layer {iteration} peeled using {recipe}...")
        
        if "PUCTF26{" in current_content:
            print(f"\n[+] SUCCESS! Flag found at Layer {iteration}.")
            print("==================================================")
            flag = re.search(r'PUCTF26\{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}\}', current_content)
            if flag:
                print(f"FLAG: {flag.group(0)}")
            else:
                print(f"Raw Result: {current_content}")
            print("==================================================")
            break

if __name__ == "__main__":
    solve()
```

### Output
```
└─$ python3 solve.py
[*] Opening dishes...
[+] Initial Gzip detected. Decompressing...
[*] Layer 1 peeled using Base85 + zlib...
[*] Layer 10 peeled using Base32 + gzip...
[*] Layer 20 peeled using Base64 + gzip...
[*] Layer 30 peeled using Base32 + gzip...
[*] Layer 40 peeled using Base85 + gzip...
[*] Layer 50 peeled using Base85 + gzip...
[*] Layer 60 peeled using Base85 + zlib...
[*] Layer 70 peeled using Base32 + gzip...
[*] Layer 80 peeled using Base64 + zlib...
[*] Layer 90 peeled using Base64 + gzip...
[*] Layer 100 peeled using Base64 + zlib...
[*] Layer 110 peeled using Base32 + gzip...
[*] Layer 120 peeled using Base85 + gzip...
[*] Layer 130 peeled using Base64 + zlib...
[*] Layer 140 peeled using Base64 + zlib...
[*] Layer 150 peeled using Base85 + zlib...
[*] Layer 160 peeled using Base85 + zlib...
[*] Layer 170 peeled using Base32 + zlib...
[*] Layer 180 peeled using Base32 + gzip...
[*] Layer 190 peeled using Base64 + zlib...
[*] Layer 200 peeled using Base32 + zlib...
[*] Layer 210 peeled using Base64 + gzip...
[*] Layer 220 peeled using Base85 + gzip...
[*] Layer 230 peeled using Base32 + zlib...
[*] Layer 240 peeled using Base64 + gzip...
[*] Layer 250 peeled using Base32 + zlib...

[+] SUCCESS! Flag found at Layer 256.
==================================================
FLAG: PUCTF26{y0u_4re_m4st3r_ln_r3v3r53_b453_me554g3_cb6a739ace061277c5ec70e7abfc7c36}
==================================================
```

## 6. What We Learned
1.  **Automation is Essential:** With 256 layers and over 5 million tokens, manual decryption was impossible. Scripting is the only viable path for "onion" challenges.
2.  **Robustness Matters:** CTF authors often introduce slight variations in layers (e.g., changing from Zlib to Gzip or shifting the key position) to break "dumb" scripts. A successful solver must be "blind" to these changes by trying all combinations.
3.  **Encoding Nuances:** Understanding the specific requirements of encodings (like Base32 padding or Gzip headers) is crucial when dealing with raw data streams.

