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