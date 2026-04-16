import os
import sys
import operator
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Disable pwntools logging to keep output clean
context.log_level = 'error'

def solve_dlp_bsgs(S_sub, G_sub, pe):
    """Robust Baby-Step Giant-Step for small prime-power order subgroups"""
    if S_sub == S_sub.curve()(0):
        return 0
    m = int(pe**0.5) + 1
    table = {}
    P = S_sub.curve()(0)
    for i in range(m):
        key = "INF" if P == S_sub.curve()(0) else P.xy()
        table[key] = i
        P += G_sub

    giant_step = G_sub * m
    P = S_sub
    for j in range(m):
        key = "INF" if P == S_sub.curve()(0) else P.xy()
        if key in table:
            return (j * m + table[key]) % pe
        P -= giant_step

    raise ValueError("DLP not found in BSGS")

def exploit():
    p_prime = 2**256 - 2**224 + 2**192 + 2**96 - 1
    a = -3
    b_orig = 41058363725152142129326129780047268409114441015993725554835256314039467401291

    quotes =[
        b"Konpeko, konpeko, konpeko! Hololive san-kisei no Usada Pekora-peko! domo, domo!",
        b"Bun bun cha! Bun bun cha!",
        b"kitira!",
        b"usopeko deshou",
        b"HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x93HA\xe2\x86\x93HA\xe2\x86\x93",
        b"HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x91",
        b"it's me pekora!",
        b"ok peko",
    ]
    quotes_bytes =[q.ljust(64, b"\0")[:64] for q in quotes]

    print("[*] Generating prime list (up to 2^18)...")
    limit = 2**18
    prime_list = list(primes(2, limit))

    total_bits = 0
    b = 1
    selected_curves =[]
    best_powers = {}

    print("[*] Finding smooth curves on the fly (Takes ~2-3 seconds)...")
    
    while total_bits < 260:
        try:
            E = EllipticCurve(GF(p_prime), [a, b])
            order = E.order()
        except Exception:
            b += 1
            continue

        rem = order
        factors =[]
        for p_fac in prime_list:
            if rem % p_fac == 0:
                e = 0
                while rem % p_fac == 0:
                    e += 1
                    rem //= p_fac
                factors.append((p_fac, e))

        if not factors:
            b += 1
            continue

        P = E.random_point()
        G_prime = P * rem 
        
        Q_max = prod([p**e for p, e in factors])
        subgroup_info =[]
        Q_actual = 1
        
        for p_fac, e in factors:
            cofactor = Q_max // (p_fac**e)
            temp = G_prime * cofactor
            c = 0
            curr = temp
            while curr != E(0):
                curr = curr * p_fac
                c += 1
            if c > 0:
                subgroup_info.append((p_fac, c))
                Q_actual *= (p_fac**c)

        useful =[]
        new_bits = 0
        for p_fac, c in subgroup_info:
            curr_c = best_powers.get(p_fac, 0)
            if c > curr_c:
                gain = (p_fac**c).nbits() - (p_fac**curr_c).nbits() if curr_c else (p_fac**c).nbits()
                new_bits += gain
                useful.append((p_fac, c))

        if new_bits >= 8:
            selected_curves.append((b, Q_actual, G_prime, useful, E))
            for p_fac, c in useful:
                best_powers[p_fac] = c
            total_bits = sum((p**c).nbits() for p, c in best_powers.items())
            print(f"[+] Accepted b={b:<3} | Gained {new_bits:<2} bits | Total CRT target: {total_bits}/260")
            
        b += 1

    print(f"\n[*] Active server exploitation ({len(selected_curves)} queries)...")
    io = remote("archive.cryptohack.org", 45328)

    io.recvuntil(b"watashi no public key: (")
    pub_x = int(io.recvuntil(b",", drop=True))
    pub_y = int(io.recvuntil(b")", drop=True))
    
    io.recvuntil(b"> ")
    io.sendline(b"2")
    c1_hex = io.recvline().strip().decode()
    c2_hex = io.recvline().strip().decode()

    results =[]
    for b_prime, Q_actual, G_prime, useful_factors, E in selected_curves:
        io.recvuntil(b"> ")
        io.sendline(b"1")
        io.recvuntil(b"x: ")
        io.sendline(str(G_prime.xy()[0]).encode())
        io.recvuntil(b"y: ")
        io.sendline(str(G_prime.xy()[1]).encode())

        c_hex = io.recvline().strip().decode()
        c = bytes.fromhex(c_hex)

        S_found = None
        for pad_q in quotes_bytes:
            # FIX: By-pass Sage preparser using operator.xor instead of '^'
            key = bytes([operator.xor(c_b, q_b) for c_b, q_b in zip(c, pad_q)])
            x_S = int.from_bytes(key[:32], 'big')
            y_S = int.from_bytes(key[32:], 'big')

            if (y_S**2) % p_prime == (x_S**3 + a*x_S + b_prime) % p_prime:
                S_found = E(x_S, y_S)
                break

        if S_found is not None:
            results.append((b_prime, Q_actual, G_prime, useful_factors, E, S_found))

    io.recvuntil(b"> ")
    io.sendline(b"3")
    io.close()

    print("\n[*] Solving Subgroup Discrete Logarithms...")
    moduli = {}

    for b_prime, Q_actual, G_prime, useful_factors, E, S in results:
        for p_fac, c in useful_factors:
            pe = p_fac**c
            G_sub = G_prime * (Q_actual // pe)
            S_sub = S * (Q_actual // pe)

            try:
                d_sub = solve_dlp_bsgs(S_sub, G_sub, pe)
                if p_fac not in moduli or moduli[p_fac][1] < pe:
                    moduli[p_fac] = (d_sub, pe)
            except Exception:
                pass

    rems = [val[0] for val in moduli.values()]
    mods =[val[1] for val in moduli.values()]

    d = crt(rems, mods)
    print(f"[+] Reconstructed Private Key (d): {d}")

    c1_bytes = bytes.fromhex(c1_hex)
    c1_x = int.from_bytes(c1_bytes[:32], 'big')
    c1_y = int.from_bytes(c1_bytes[32:], 'big')

    E_orig = EllipticCurve(GF(p_prime), [a, b_orig])
    C1 = E_orig(c1_x, c1_y)
    shared = C1 * d

    key = int(shared.xy()[0]).to_bytes(32, 'big') + int(shared.xy()[1]).to_bytes(32, 'big')
    c2_bytes = bytes.fromhex(c2_hex)

    # FIX: By-pass Sage preparser using operator.xor instead of '^'
    flag_padded = bytes([operator.xor(c_b, k_b) for c_b, k_b in zip(c2_bytes, key)])
    flag = flag_padded.split(b'}')[0] + b'}'
    print(f"\n[🚀] FLAG: {flag.decode(errors='ignore')}\n")

if __name__ == '__main__':
    exploit()