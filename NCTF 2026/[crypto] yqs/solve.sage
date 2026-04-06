import os
import sys
import re
import math
import hashlib
import operator
from pwn import remote, context
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Disable debug spam, but guarantee print outputs
context.log_level = 'error'

def solve():
    print("[*] Script booted successfully. Initializing solver...")
    sys.stdout.flush()

    try:
        print("[*] Connecting to the remote server 114.66.24.221:46272...")
        sys.stdout.flush()
        io = remote('114.66.24.221', 46272, timeout=15)
    except Exception as e:
        print(f"[-] Connection failed! Server may be down. Error: {e}")
        return

    try:
        io.recvuntil(b"Master's Seal: ", timeout=10)
        master_pub_int = int(io.recvline().strip())
        print(f"[+] Master Seal retrieved: {master_pub_int}")
        sys.stdout.flush()
        
        io.recvuntil(b"Cipher: ", timeout=5)
        enc_flag = bytes.fromhex(io.recvline().strip().decode())
        print(f"[*] Heavenly Cipher: {enc_flag.hex()}")
        sys.stdout.flush()
    except Exception as e:
        print(f"[-] Failed to read initial server data. Error: {e}")
        return
        
    p = 2**255 - 19
    a_param = 486662
    bound = 2**245
    
    primes =[]
    points = []
    curves = []
    M = 1
    
    print("[*] Dynamically precomputing invalid curves... (Please wait ~40 seconds)")
    sys.stdout.flush()
    
    # Precomputes cyclic groups without multi-factor overlap to prevent BSGS timeouts
    while M < bound:
        c = randint(1, p-1)
        try:
            E = EllipticCurve(GF(p), [a_param, c])
            order = E.order()
        except Exception:
            continue
            
        for f, e_pow in factor(order, limit=100000):
            # Strict e_pow == 1 isolates prime order. Eliminates BSGS hangs completely.
            if e_pow == 1 and 10000 < f < 2000000 and f not in primes:
                cofactor = order // f
                P = cofactor * E.random_point()
                if P != E(0):
                    primes.append(int(f))
                    points.append(P)
                    curves.append(E)
                    M *= f
                    print(f"[+] Mapped prime m_i = {f}. Target bound: {M.nbits()}/245 bits.")
                    sys.stdout.flush()
                    break

    NUM_QUERIES = 99
    results = []
    
    print("\n[*] Precomputations complete. Beginning High-Speed Pipelined Exploitation...")
    sys.stdout.flush()
    
    # ⚡ PIPELINED BURST: Compresses all 99 inputs into one payload frame 
    payload = (b"m\n0\n" * NUM_QUERIES)
    
    for i in range(len(primes)):
        print(f"\n[*] Round {i+1} / {len(primes)} (Modulus {primes[i]})")
        sys.stdout.flush()
        
        try:
            io.recvuntil(b"modulus for today: ", timeout=10)
            q = int(io.recvline().strip().decode())
        except Exception as e:
            print(f"[-] Dropped connection at round {i+1}. Error: {e}")
            return
            
        # Fire all 99 queries simultaneously
        io.send(payload)
        
        A_mat = []
        b_vec =[]
        
        msg_hash = int(hashlib.sha512(b"0").hexdigest(), 16)
        m_encoded = (msg_hash & ((1<<128)-1) & ((1<<8)-1)) << 2
            
        try:
            for j in range(NUM_QUERIES):
                io.recvuntil(b"Resonance echoes: (", timeout=5)
                a_int = int(io.recvuntil(b",", drop=True))
                b_int = int(io.recvuntil(b")", drop=True))
                
                a_v =[]
                tmp = a_int
                for _ in range(77):
                    a_v.append(tmp % q)
                    tmp //= q
                A_mat.append(a_v)
                
                b_prime = (b_int - m_encoded) % q
                b_vec.append(b_prime)
        except Exception as e:
            print(f"[-] Desync during pipelined receive. Error: {e}")
            return
            
        print("    [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...")
        sys.stdout.flush()
        
        # ⚡ LATTICE OPTIMIZATION: Extract Row Space via GF(q) Image directly.
        # Condenses from a bloated 177x100 matrix down to an ideal 100x100 basis matrix natively.
        A_mod = Matrix(GF(q), A_mat)
        C_basis = A_mod.transpose().echelon_form()
        
        pivots = C_basis.pivots()
        rank = len(pivots)
        non_pivots =[j for j in range(NUM_QUERIES) if j not in pivots]
        
        Basis_L = matrix(ZZ, NUM_QUERIES, NUM_QUERIES)
        for r_idx in range(rank):
            for c_idx in range(NUM_QUERIES):
                Basis_L[r_idx, c_idx] = int(C_basis[r_idx, c_idx])
                
        for r_idx, col_idx in enumerate(non_pivots):
            Basis_L[rank + r_idx, col_idx] = q
            
        K_mat = matrix(ZZ, NUM_QUERIES + 1, NUM_QUERIES + 1)
        for r_idx in range(NUM_QUERIES):
            for c_idx in range(NUM_QUERIES):
                K_mat[r_idx, c_idx] = Basis_L[r_idx, c_idx]
                
        for c_idx in range(NUM_QUERIES):
            K_mat[NUM_QUERIES, c_idx] = b_vec[c_idx]
        K_mat[NUM_QUERIES, NUM_QUERIES] = 2
        
        L_red = K_mat.LLL()
        
        E_err = None
        for row in L_red:
            if row[-1] == 2:
                E_test = [int(x) for x in row[:NUM_QUERIES]]
                if all(0 <= e_val <= 3 for e_val in E_test):
                    E_err = E_test
                    break
            elif row[-1] == -2:
                E_test = [-int(x) for x in row[:NUM_QUERIES]]
                if all(0 <= e_val <= 3 for e_val in E_test):
                    E_err = E_test
                    break
                
        if E_err is None:
            print("[-] Lattice reduction failed to find the exact bounded error vector. Exiting.")
            return
            
        b_exact = [(b_vec[k] - E_err[k]) % q for k in range(NUM_QUERIES)]
        B_mod = vector(GF(q), b_exact)
        
        # Robust linear equation extraction
        try:
            s_vec = A_mod.solve_right(B_mod)
        except Exception:
            pivots = A_mod.pivots()
            A_sub = matrix(GF(q), [A_mod[i] for i in pivots])
            B_sub = vector(GF(q), [B_mod[i] for i in pivots])
            s_vec = A_sub.solve_right(B_sub)
            
        priv = 0
        for r_idx in range(77):
            priv += int(s_vec[r_idx]) * (q ** r_idx)
            
        E_i = curves[i]
        P_i = points[i]
        X_i, Y_i = int(P_i[0]), int(P_i[1])
        m_i = primes[i]
        
        # --- The Bitwise Truncation Subvert ---
        MASK = (1 << 256) - 1
        priv_low = int(priv) & MASK
        P_H = int(priv) - priv_low
        P_H_mod = P_H % p
        
        Dx = (X_i - P_H_mod) % p
        Dy = (Y_i - P_H_mod) % p
        
        x_send = operator.xor(int(Dx), int(priv_low))
        y_send = operator.xor(int(Dy), int(priv_low))
        
        point_int = (x_send << 256) | y_send
        
        try:
            io.recvuntil(b"exchange):", timeout=5)
            io.sendline(b"e")
            io.recvuntil(b"formation (int):", timeout=5)
            io.sendline(str(point_int).encode())
            
            line = io.recvline(timeout=5).decode()
            m_match = re.search(r"Domain resonance: (\d+)", line)
            if not m_match:
                print(f"[-] Invalid response formatting: {line}")
                return
            res_int = int(m_match.group(1))
        except Exception as e:
            print(f"[-] Exchange desync. Error: {e}")
            return
            
        if res_int == 0:
            ki = 0
            print(f"    [+] Mapped Resonance: ki = 0 mod {m_i}")
            sys.stdout.flush()
        else:
            R_x = res_int >> 256
            R_y = res_int & MASK
            R_i = E_i(R_x % p, R_y % p)
            try:
                ki = int(discrete_log(R_i, P_i, ord=m_i, operation='+'))
            except Exception:
                print("    [!] Native BSGS failed. Initiating fallback algebraic BSGS mapping...")
                sys.stdout.flush()
                m_step = int(math.isqrt(m_i)) + 1
                table = {}
                P_table = P_i * 0
                for step in range(m_step):
                    if step > 0:
                        table[P_table.xy()] = step
                    P_table += P_i
                
                Q = R_i
                inv_mG = -(m_step * P_i)
                found = False
                for j in range(m_step):
                    if Q == P_i * 0:
                        ki = j * m_step
                        found = True
                        break
                    if Q.xy() in table:
                        ki = j * m_step + table[Q.xy()]
                        found = True
                        break
                    Q += inv_mG
                if not found:
                    ki = 0
                    print("    [!] Both mappers failed. Assuming 0.")
                    
            print(f"    [+] Mapped Resonance: ki = {ki} mod {m_i}")
            sys.stdout.flush()
            
        results.append((ki, m_i))
        
    print("\n[*] Initializing Final CRT Reconstruction Phase...")
    sys.stdout.flush()
    rems = [x[0] for x in results]
    mods = [x[1] for x in results]
    master_sec = crt(rems, mods)
    print(f"[+] Unlocked Master Secret: {master_sec}")
    
    aes_key = hashlib.sha256(str(master_sec).encode()).digest()
    dec = AES.new(aes_key, AES.MODE_ECB).decrypt(enc_flag)
    try:
        flag = unpad(dec, 32).decode()
        print(f"\n[🚀] FLAG EXFILTRATED: {flag}")
    except Exception as e:
        print(f"[-] Decryption sequence fragmented: {e}")
        print(f"[-] Raw alignment: {dec}")
    sys.stdout.flush()

if __name__ == '__main__':
    solve()


# Output:
# [*] Script booted successfully. Initializing solver...
# [*] Connecting to the remote server 114.66.24.221:46272...
# [+] Master Seal retrieved: 4419891753779050396832962235400752558065661872621999997737757324055177595466489585900910709089106441038048594365228283361137118971495886686106348971792993
# [*] Heavenly Cipher: eafb0b3c6ef5ea35b9fc5284b833be4a91066f54a2a1edff6b2059faee336991acb72b28febb3b26ef0012a090fb54129502b4a23e44b6ff45a5f66eee88bcd6
# [*] Dynamically precomputing invalid curves... (Please wait ~40 seconds)
# [+] Mapped prime m_i = 33317. Target bound: 16/245 bits.
# [+] Mapped prime m_i = 13591. Target bound: 29/245 bits.
# [+] Mapped prime m_i = 17191. Target bound: 43/245 bits.
# [+] Mapped prime m_i = 16033. Target bound: 57/245 bits.
# [+] Mapped prime m_i = 87743. Target bound: 74/245 bits.
# [+] Mapped prime m_i = 18587. Target bound: 88/245 bits.
# [+] Mapped prime m_i = 10459. Target bound: 101/245 bits.
# [+] Mapped prime m_i = 12323. Target bound: 115/245 bits.
# [+] Mapped prime m_i = 41141. Target bound: 130/245 bits.
# [+] Mapped prime m_i = 23293. Target bound: 145/245 bits.
# [+] Mapped prime m_i = 63211. Target bound: 161/245 bits.
# [+] Mapped prime m_i = 31387. Target bound: 176/245 bits.
# [+] Mapped prime m_i = 21163. Target bound: 190/245 bits.
# [+] Mapped prime m_i = 91141. Target bound: 206/245 bits.
# [+] Mapped prime m_i = 18713. Target bound: 221/245 bits.
# [+] Mapped prime m_i = 80789. Target bound: 237/245 bits.
# [+] Mapped prime m_i = 34211. Target bound: 252/245 bits.

# [*] Precomputations complete. Beginning High-Speed Pipelined Exploitation...

# [*] Round 1 / 17 (Modulus 33317)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 2434 mod 33317

# [*] Round 2 / 17 (Modulus 13591)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 13204 mod 13591

# [*] Round 3 / 17 (Modulus 17191)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 2860 mod 17191

# [*] Round 4 / 17 (Modulus 16033)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 10250 mod 16033

# [*] Round 5 / 17 (Modulus 87743)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 25773 mod 87743

# [*] Round 6 / 17 (Modulus 18587)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 3251 mod 18587

# [*] Round 7 / 17 (Modulus 10459)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 4013 mod 10459

# [*] Round 8 / 17 (Modulus 12323)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 524 mod 12323

# [*] Round 9 / 17 (Modulus 41141)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 25864 mod 41141

# [*] Round 10 / 17 (Modulus 23293)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 4394 mod 23293

# [*] Round 11 / 17 (Modulus 63211)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 41931 mod 63211

# [*] Round 12 / 17 (Modulus 31387)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 23264 mod 31387

# [*] Round 13 / 17 (Modulus 21163)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 1687 mod 21163

# [*] Round 14 / 17 (Modulus 91141)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 66564 mod 91141

# [*] Round 15 / 17 (Modulus 18713)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 9014 mod 18713

# [*] Round 16 / 17 (Modulus 80789)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 59691 mod 80789

# [*] Round 17 / 17 (Modulus 34211)
#     [>] Solving LWE Lattice (Optimized 0.05s Matrix Form)...
#     [+] Mapped Resonance: ki = 15594 mod 34211

# [*] Initializing Final CRT Reconstruction Phase...
# [+] Unlocked Master Secret: 123937238958327828026019855095728554040549536414884710522220467529449974

# [🚀] FLAG EXFILTRATED: nctf{d60050e3-0481-441c-ab03-67cc6396961e}