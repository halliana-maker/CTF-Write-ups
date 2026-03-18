import json
import hashlib
import random as pyrand
import operator
from sage.all import *

def solve():
    print("[*] Loading task_data.json...")
    with open("task_data.json", "r") as f:
        task = json.load(f)

    n = int(task["n"], 16)
    encrypted_flag = task["encrypted_flag"]

    data = []
    for d in task["data"]:
        data.append((int(d["r"], 16), int(d["s"], 16), int(d["hash"], 16)))

    # Lattice Parameters
    m = 22             # Subset size
    K = 2**16          # Multiplier to balance the lattice vectors
    X = 2**255         # Expected length of the constant 1 component
    
    inv_216 = inverse_mod(2**16, n)
    
    print(f"[*] Starting RANSAC Lattice Attack (m={m})...")
    attempts = 0

    while True:
        attempts += 1
        
        # Randomly select a subset to bypass the noisy signatures
        subset = pyrand.sample(data, m + 1)
        r0, s0, h0 = subset[0]
        
        inv_s0 = inverse_mod(s0, n)
        t0 = (inv_s0 * r0) % n
        u0 = (inv_s0 * h0) % n
        
        A_prime = []
        B_prime =[]
        
        # Calculate A' and B' for the chosen subset
        for i in range(1, m + 1):
            ri, si, hi = subset[i]
            inv_si = inverse_mod(si, n)
            ti = (inv_si * ri) % n
            ui = (inv_si * hi) % n
            
            A = ((ui - u0) * inv_216) % n
            B = ((ti - t0) * inv_216) % n
            A_prime.append(A)
            B_prime.append(B)
            
        # Build the HNP Lattice
        M = Matrix(ZZ, m + 2, m + 2)
        for i in range(m):
            M[i, i] = n * K
            M[m, i] = B_prime[i] * K
            M[m + 1, i] = A_prime[i] * K
            
        M[m, m] = 1
        M[m + 1, m + 1] = X
        
        # Lattice Reduction (LLL)
        L = M.LLL()
        
        # Extract Private Key and Validate
        for row in L:
            # The correct short vector should have the shifted component strictly at X or -X
            if abs(row[-1]) == X:
                sign = 1 if row[-1] == X else -1
                d_cand = (row[-2] * sign) % n
                
                if d_cand <= 0:
                    continue
                
                try:
                    # Try to decrypt the flag using d_cand
                    key32 = hashlib.sha256(int(d_cand).to_bytes(32, "big")).digest()
                    enc = bytes.fromhex(encrypted_flag)
                    ks = (key32 * ((len(enc) // 32) + 1))[:len(enc)]
                    pt = bytes(operator.xor(a, b) for a, b in zip(enc, ks))
                    
                    if b"PUCTF" in pt:
                        print(f"\n[+] SUCCESS! Valid subset found after {attempts} attempts.")
                        print(f"[+] Private Key (d): {hex(d_cand)}")
                        print(f"[+] Flag: {pt.decode(errors='ignore')}")
                        return
                except Exception as e:
                    continue
        
        if attempts % 10 == 0:
            print(f"[*] Attempt {attempts}... continuing to search for an all-stable subset.")

if __name__ == "__main__":
    solve()