#!/usr/bin/env python3
from pwn import *
from z3 import *
import hashlib
import binascii
import subprocess
import os

# [USER ACTION] Ensure 'sage' is in PATH.
# Global settings
BLOCK_SIZE = 16

def solve():
    # 1. CONNECT
    r = remote("pwn-3836fac34b.challenge.xctf.org.cn", 9999, ssl=True)

    def get_trace():
        r.recvuntil(b"Your choice:")
        r.sendline(b"1")
        # Send 32 bytes to get 2 blocks of encrypted data
        payload = b"A" * 32
        r.recvuntil(b"Message:")
        r.send(payload)
        r.recvuntil(b"leak: ")
        leak = binascii.unhexlify(r.recvline().strip().decode())
        r.recvuntil(b"enc: ")
        enc = binascii.unhexlify(r.recvline().strip().decode())
        # The plaintext used is SHA256 of input
        msg = hashlib.sha256(payload).digest()
        return msg, leak, enc

    # 2. COLLECT DATA (2 traces = 64 bytes of info = 256 bits)
    print("[*] Phase 1: Collecting traces...")
    traces = [get_trace() for _ in range(2)]

    # 3. RECOVER KEY1 FOR EACH TRACE
    print("[*] Phase 2: Recovering Key1 for each trace...")
    all_matrices = []
    all_targets = []

    for msg, leak, enc in traces:
        # Local Z3 solve for Key1
        s = Solver()
        k1 = [BitVec(f"k1_{i}", 8) for i in range(BLOCK_SIZE)]
        # Row 0
        row = k1
        # Polynomial Expansion
        for _ in range(BLOCK_SIZE - 1):
            nxt = [BitVecVal(0, 8)] * BLOCK_SIZE
            f = row[BLOCK_SIZE-1]
            nxt[0] = f * k1[0]
            for j in range(BLOCK_SIZE - 1):
                nxt[j+1] = row[j] + f * k1[j+1]
            row = nxt
        
        # Constraints
        for i in range(BLOCK_SIZE):
            s.add(row[i] == leak[i])
            s.add(ULE(k1[i], 15)) # The Twist Bug: high nibbles are 0
            
        if s.check() != sat:
            print("[!] Error: Key1 recovery failed.")
            return
        
        m = s.model()
        k1_val = [m[k1[i]].as_long() for i in range(BLOCK_SIZE)]
        print(f"    [+] Key1: {bytes(k1_val).hex()}")

        # Build Concrete Key Expand table
        key_expand = []
        curr_row = list(k1_val)
        key_expand.append(curr_row)
        for _ in range(BLOCK_SIZE - 1):
            nr = [0]*BLOCK_SIZE
            f = curr_row[BLOCK_SIZE-1]
            nr[0] = (f * k1_val[0]) & 0xFF
            for j in range(BLOCK_SIZE - 1):
                nr[j+1] = (curr_row[j] + f * k1_val[j+1]) & 0xFF
            key_expand.append(nr)
            curr_row = nr

        # 4. LINEARIZE BLOCK ENCRYPTION (HNP)
        # Block 0 and Block 1
        for b in range(2):
            msg_blk = msg[b*BLOCK_SIZE : (b+1)*BLOCK_SIZE]
            enc_blk = enc[b*BLOCK_SIZE : (b+1)*BLOCK_SIZE]
            
            # Construct Matrix M for this block: Enc = M * K2 + K3
            M = [[0]*BLOCK_SIZE for _ in range(BLOCK_SIZE)]
            for col in range(BLOCK_SIZE):
                e = [0]*BLOCK_SIZE
                # Simulate contribution of K2[col]
                if col == 0:
                    e = list(msg_blk)
                else:
                    i = col
                    for j in range(BLOCK_SIZE - i):
                        e[i+j] = (e[i+j] + msg_blk[j]) & 0xFF
                    for j in range(BLOCK_SIZE - i, BLOCK_SIZE):
                        row_red = key_expand[i + j - BLOCK_SIZE]
                        coeff = msg_blk[j]
                        for k in range(BLOCK_SIZE):
                            e[k] = (e[k] + coeff * row_red[k]) & 0xFF
                for row_idx in range(BLOCK_SIZE):
                    M[row_idx][col] = e[row_idx]
            
            all_matrices.extend(M)
            # Target is Center of Range [C&F0, C&F0 + 15]
            for val in enc_blk:
                all_targets.append((val & 0xF0) + 7)

    # 5. LATTICE SOLVER (SAGE)
    print("[*] Phase 3: Solving for Key2 via Lattice (Sage)...")
    
    sage_script = f"""
from sage.all import *

M = {all_matrices}
T = {all_targets}
n = {BLOCK_SIZE}
m = len(M)
mod = 256

# Weights
W = 128

# B = [ I | 0 | 0 ]
#     [ M*W | mod*W | 0 ]
#     [ -T*W | 0 | 1 ]
dim = n + m + 1
L = Matrix(ZZ, dim, dim)
for i in range(n):
    L[i, i] = 1
for j in range(m):
    for i in range(n):
        L[i, n+j] = M[j][i] * W
    L[n+j, n+j] = mod * W
    L[dim-1, n+j] = -T[j] * W
L[dim-1, dim-1] = 1

L_red = L.LLL()

for row in L_red:
    if abs(row[dim-1]) == 1:
        sign = 1 if row[dim-1] == 1 else -1
        res = [(row[i]*sign) % 256 for i in range(n)]
        print("RESULT:" + bytes(res).hex())
        break
"""
    with open("solve.sage", "w") as f:
        f.write(sage_script)

    out = subprocess.check_output(["sage", "solve.sage"]).decode()
    if "RESULT:" not in out:
        print("[!] Lattice failed to find Key2.")
        return
    
    key2_hex = out.split("RESULT:")[1].strip()
    print(f"[+] Recovered Key2: {key2_hex}")

    # 6. SUBMIT
    r.recvuntil(b"Your choice:")
    r.sendline(b"2")
    r.recvuntil(b"Key: ")
    r.send(binascii.unhexlify(key2_hex))
    
    # Get flag
    print("\n" + "="*40)
    print(r.recvall(timeout=3).decode().strip())
    print("="*40)

if __name__ == "__main__":
    solve()
