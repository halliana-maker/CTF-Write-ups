import hashlib
from datetime import datetime, timedelta

def solve():
    # The first ciphertext from the netcat output
    c1 = bytes.fromhex('b3f6f6306adf4758c2201647396a08ca7cf5d41fe55f6b086dd862114c4cecf881db812c44b4344bf81e0930076356c961d3c4')
    
    # We know the flag starts with this prefix
    known_prefix = b"PUCTF26{"
    
    # 1. Recover the first 8 bytes of the SHA-256 key
    target_key_prefix = bytes([c1[i] ^ known_prefix[i] for i in range(8)])
    print(f"[*] Recovered partial key: {target_key_prefix.hex()}")
    print("[*] Brute-forcing timestamp...")

    # 2. Set up our brute force timeframe in JST (UTC+9) 
    # Since the challenge was accessed around early March 2026, we check that timeframe.
    start_time = datetime(2026, 3, 7, 11, 20, 0)
    end_time = datetime(2026, 3, 7, 11, 30, 0)

    curr_time = start_time
    found_time_str = None

    # Brute-force loop
    while curr_time < end_time:
        time_str = curr_time.strftime("%Y%m%d%H%M%S")
        material = time_str + "salt"
        
        # Calculate SHA256
        key = hashlib.sha256(material.encode()).digest()
        
        # Check if the generated key matches our known recovered partial key
        if key[:8] == target_key_prefix:
            found_time_str = time_str
            print(f"[+] Found correct server time: {found_time_str} (JST)")
            break
            
        curr_time += timedelta(seconds=1)

    # 3. Decrypt the full payload
    if found_time_str:
        material = found_time_str + "salt"
        full_key = hashlib.sha256(material.encode()).digest()
        
        flag = bytes([c1[i] ^ full_key[i % len(full_key)] for i in range(len(c1))])
        print(f"[+] Decrypted Flag: {flag.decode()}")
    else:
        print("[-] Could not find the time string. Adjust the time range.")

if __name__ == "__main__":
    solve()

# Output:
# [*] Recovered partial key: e3a3b5642ced7123
# [*] Brute-forcing timestamp...
# [+] Found correct server time: 20260307112318 (JST)
# [+] Decrypted Flag: PUCTF26{Tim3lsk3Y_mqJhz4viP5G3zUbx4HhYEhnWrDRz50Dy}