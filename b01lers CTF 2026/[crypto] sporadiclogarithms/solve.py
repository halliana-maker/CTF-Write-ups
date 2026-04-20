#!/usr/bin/env python3
import re
import sys
from pwn import *

# Configuration
HOST = "sporadiclogarithms.opus4-7.b01le.rs"
PORT = 8443

def solve():
    print(f"[*] Connecting to {HOST}:{PORT} via SSL...")
    # context.log_level = 'debug' # Uncomment this if you want to see raw hex traffic
    
    try:
        p = remote(HOST, PORT, ssl=True)
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    def query_batch(cmds):
        if not cmds: return []
        payload = b"\n".join(c.encode() for c in cmds) + b"\n"
        p.send(payload)
        results = []
        for _ in cmds:
            res = p.recvuntil(b"bb> ", drop=True).strip()
            # Handle potential echo or extra text
            clean_res = res.split(b'\n')[-1].strip()
            results.append(int(clean_res))
        return results

    def query(cmd):
        return query_batch([cmd])[0]

    # --- VERBOSE RECEIVE ---
    print("[*] Waiting for server initialization...")
    # We read until the first prompt, printing everything we see
    initial_data = b""
    while b"bb>" not in initial_data:
        chunk = p.recv(1024)
        if not chunk:
            break
        initial_data += chunk
        # Print to screen so we can see if there is a PoW or Banner
        sys.stdout.write(chunk.decode(errors='ignore'))
        sys.stdout.flush()

    out = initial_data.decode(errors='ignore')

    # If the server is asking for a PoW, you will see it in the terminal now.
    # If the script continues, it means we found 'bb>'
    
    for round_idx in range(1, 6):
        print(f"\n\n[+] --- Round {round_idx}/5 ---")
        
        # Extract metadata
        m_c = re.search(r"c order=(\d+)", out)
        m_h = re.search(r"one=(\d+) g=(\d+) c=(\d+) h=(\d+)", out)
        
        if not m_c or not m_h:
            print("[-] Parsing failed. Check server output above.")
            break
            
        c_order = int(m_c.group(1))
        one, g, c_handle, h = map(int, m_h.groups())
        print(f"[*] Parsed: c_order={c_order}, one={one}, g={g}, h={h}")

        # Algorithm Logic (BSGS)
        g_phi = [g]
        for _ in range(1, c_order):
            g_phi.append(query(f"phi {g_phi[-1]}"))
            
        s = [one]
        for i in range(c_order):
            s.append(query(f"mul {s[-1]} {g_phi[i]}"))
            
        B = s[c_order] 
        S_step = 600 
        max_j = (262144 // c_order) // S_step + 1
        
        print(f"[*] Building Baby/Giant steps...")
        powers = {0: one, 1: B}
        cur = 1
        while cur < S_step:
            b_h = powers[cur]
            cmds = [f"mul {b_h} {powers[i]}" for i in range(1, min(cur + 1, S_step - cur + 1))]
            res = query_batch(cmds)
            for j, val in enumerate(res):
                powers[cur + j + 1] = val
            cur += len(cmds)
            
        baby_steps = {v: k for k, v in powers.items()}
        inv_B_S = query(f"inv {powers[S_step]}")
        
        # Giant steps for W = B^-S_step
        w_powers = {0: one, 1: inv_B_S}
        cur = 1
        while cur < max_j:
            b_h = w_powers[cur]
            cmds = [f"mul {b_h} {w_powers[i]}" for i in range(1, min(cur + 1, max_j - cur + 1))]
            res = query_batch(cmds)
            for j, val in enumerate(res):
                w_powers[cur + j + 1] = val
            cur += len(cmds)

        s_inv = query_batch([f"inv {s[r]}" for r in range(c_order)])
        T_handles = query_batch([f"mul {h} {si}" for si in s_inv])
        
        ans_x = None
        print("[*] Finding match...")
        for r in range(c_order):
            V_res = query_batch([f"mul {T_handles[r]} {w_powers[j]}" for j in range(max_j + 1)])
            for j, v_h in enumerate(V_res):
                if v_h in baby_steps:
                    ans_x = (j * S_step + baby_steps[v_h]) * c_order + r
                    break
            if ans_x: break

        if ans_x:
            print(f"[!] Submitting x={ans_x}")
            p.sendline(f"submit {ans_x}".encode())
            # Read until next round or flag
            out = b""
            while b"bb>" not in out and b"bctf{" not in out:
                c = p.recv(1024)
                if not c: break
                out += c
                sys.stdout.write(c.decode(errors='ignore'))
                sys.stdout.flush()
            out = out.decode(errors='ignore')
        else:
            print("[-] Search failed.")
            break

    print("\n[*] Done.")
    p.interactive()

if __name__ == "__main__":
    solve()

# output:
# [*] Connecting to sporadiclogarithms.opus4-7.b01le.rs:8443 via SSL...
# [+] Opening connection to sporadiclogarithms.opus4-7.b01le.rs on port 8443: Done
# [*] Waiting for server initialization...
# Pass 5 rounds to get the flag.

# === Round 1/5 setup ===
# [setup] choosing conjugator c with small order...
# [setup] c order=2
# [setup] sampled g with ord=281487861809152
# Find any x in [0, 262144] such that h = s_{g,phi}(x),
# where phi(a) = c*a*c^-1 and s_{g,phi}(x)
# group=GL(3,65537) one=1 g=2 c=4 h=3
# Commands:
#   help
#   handles               # print one,g,c,h handles
#   mul <a> <b>           # return handle of a*b
#   inv <a>               # return handle of a^-1
#   phi <a>               # return handle of c*a*c^-1
#   eq <a> <b>            # return 1 if equal else 0
#   submit <x>            # submit exponent x
#   quit
# bb> 

# [+] --- Round 1/5 ---
# [*] Parsed: c_order=2, one=1, g=2, h=3
# [*] Building Baby/Giant steps...
# [*] Finding match...
# [!] Submitting x=76097
# correct

# === Round 2/5 setup ===
# [setup] choosing conjugator c with small order...
# [setup] c order=8
# [setup] sampled g with ord=1431699456
# Find any x in [0, 262144] such that h = s_{g,phi}(x),
# where phi(a) = c*a*c^-1 and s_{g,phi}(x)
# group=GL(3,65537) one=1 g=2 c=4 h=3
# Commands:
#   help
#   handles               # print one,g,c,h handles
#   mul <a> <b>           # return handle of a*b
#   inv <a>               # return handle of a^-1
#   phi <a>               # return handle of c*a*c^-1
#   eq <a> <b>            # return 1 if equal else 0
#   submit <x>            # submit exponent x
#   quit
# bb> 

# [+] --- Round 2/5 ---
# [*] Parsed: c_order=8, one=1, g=2, h=3
# [*] Building Baby/Giant steps...
# [*] Finding match...
# [!] Submitting x=39319
# correct

# === Round 3/5 setup ===
# [setup] choosing conjugator c with small order...
# [setup] c order=4
# [setup] sampled g with ord=65536
# Find any x in [0, 262144] such that h = s_{g,phi}(x),
# where phi(a) = c*a*c^-1 and s_{g,phi}(x)
# group=GL(3,65537) one=1 g=2 c=4 h=3
# Commands:
#   help
#   handles               # print one,g,c,h handles
#   mul <a> <b>           # return handle of a*b
#   inv <a>               # return handle of a^-1
#   phi <a>               # return handle of c*a*c^-1
#   eq <a> <b>            # return 1 if equal else 0
#   submit <x>            # submit exponent x
#   quit
# bb> 

# [+] --- Round 3/5 ---
# [*] Parsed: c_order=4, one=1, g=2, h=3
# [*] Building Baby/Giant steps...
# [*] Finding match...
# [!] Submitting x=242005
# correct

# === Round 4/5 setup ===
# [setup] choosing conjugator c with small order...
# [setup] c order=2
# [setup] sampled g with ord=281487861809152
# Find any x in [0, 262144] such that h = s_{g,phi}(x),
# where phi(a) = c*a*c^-1 and s_{g,phi}(x)
# group=GL(3,65537) one=1 g=2 c=4 h=3
# Commands:
#   help
#   handles               # print one,g,c,h handles
#   mul <a> <b>           # return handle of a*b
#   inv <a>               # return handle of a^-1
#   phi <a>               # return handle of c*a*c^-1
#   eq <a> <b>            # return 1 if equal else 0
#   submit <x>            # submit exponent x
#   quit
# bb> 

# [+] --- Round 4/5 ---
# [*] Parsed: c_order=2, one=1, g=2, h=3
# [*] Building Baby/Giant steps...
# [*] Finding match...
# [!] Submitting x=166150
# correct

# === Round 5/5 setup ===
# [setup] choosing conjugator c with small order...
# [setup] c order=8
# [setup] sampled g with ord=2147549184
# Find any x in [0, 262144] such that h = s_{g,phi}(x),
# where phi(a) = c*a*c^-1 and s_{g,phi}(x)
# group=GL(3,65537) one=1 g=2 c=4 h=3
# Commands:
#   help
#   handles               # print one,g,c,h handles
#   mul <a> <b>           # return handle of a*b
#   inv <a>               # return handle of a^-1
#   phi <a>               # return handle of c*a*c^-1
#   eq <a> <b>            # return 1 if equal else 0
#   submit <x>            # submit exponent x
#   quit
# bb> 

# [+] --- Round 5/5 ---
# [*] Parsed: c_order=8, one=1, g=2, h=3
# [*] Building Baby/Giant steps...
# [*] Finding match...
# [!] Submitting x=95949
# correct
# bctf{th3_m0n5t3r_gr0up_w45_t0_1mpr4ct1c4l_:(}

# [*] Done.