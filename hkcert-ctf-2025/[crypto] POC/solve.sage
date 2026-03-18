#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.Padding import pad
from pwn import *
import os

# GCM Field Setup: x^128 + x^7 + x^2 + x + 1
# This is the standard GCM polynomial
F128 = GF(2)['x']
modulus = F128([1, 1, 1, 0, 0, 0, 0, 1] + [0]*120 + [1])
F = GF(2**128, name='a', modulus=modulus)

def to_gf(b):
    """Convert bytes to GF(2^128) element with GCM bit-reflection."""
    res = F(0)
    # GCM bit ordering: The first bit of the stream is the coefficient of x^0
    for i in range(16):
        byte = b[i]
        for j in range(8):
            if (byte >> (7 - j)) & 1:
                res += F.gen()**(i * 8 + j)
    return res

def from_gf(element):
    """Convert GF(2^128) element back to bytes using .list() for compatibility."""
    res = bytearray(16)
    coeffs = element.list()
    # Ensure list is 128 long
    coeffs += [0] * (128 - len(coeffs))
    for i in range(128):
        if coeffs[i]:
            res[i // 8] |= (1 << (7 - (i % 8)))
    return bytes(res)

def get_token_and_user(r):
    r.sendlineafter(b">", b"R")
    r.recvuntil(b"Register!\n")
    token_hex = r.recvline().strip().decode()
    user_hex = r.recvline().strip().decode()
    print(f"[*] Recv Token: {token_hex[:32]}...")
    return bytes.fromhex(token_hex), bytes.fromhex(user_hex)

def solve():
    # Setup connection
    r = remote("pwn-6fa9f714d5.challenge.xctf.org.cn", 9999, ssl=True)
    
    print("[*] Status: Phase 1 - Recovering H")
    # Get two tokens under the SAME nonce (default starting nonce)
    tok1, user1 = get_token_and_user(r)
    tok2, user2 = get_token_and_user(r)
    
    C1, T1 = to_gf(tok1[:16]), to_gf(tok1[16:])
    C2, T2 = to_gf(tok2[:16]), to_gf(tok2[16:])
    
    # T1 ^ T2 = (C1 ^ C2) * H^2
    H2 = (T1 + T2) / (C1 + C2)
    H = H2.sqrt()
    print(f"[*] Status: Found H = {from_gf(H).hex()}")

    print("[*] Status: Phase 2 - Recovering Mask for new nonce")
    # Nonce Reuse is spent (cnt=0). Must update nonce.
    new_nonce = os.urandom(12)
    r.sendlineafter(b">", b"U")
    r.sendlineafter(b"nonce(hex)>", new_nonce.hex().encode())
    
    # Get one legitimate message for this new nonce
    tok3, user3 = get_token_and_user(r)
    C3, T3 = to_gf(tok3[:16]), to_gf(tok3[16:])
    P3 = pad(user3, 16)
    
    # GHASH(H, A, C) for 1 block of A and 1 block of C:
    # (A*H^3 + C*H^2 + Len*H)
    # Since A and Len are constant but unknown, we treat (A*H^3 + Len*H) + Mask as CombinedMask
    # T = C*H^2 + CombinedMask => CombinedMask = T + C*H^2
    CombinedMask = T3 + (C3 * H2)
    
    print("[*] Status: Phase 3 - Forgery")
    # Keystream is constant for this nonce: C = P ^ K => K = C ^ P
    keystream = xor(tok3[:16], P3)
    
    P_admin = pad(b"admin", 16)
    C_admin_bytes = xor(P_admin, keystream)
    C_admin = to_gf(C_admin_bytes)
    
    # T_admin = C_admin * H^2 + CombinedMask
    T_admin_gf = (C_admin * H2) + CombinedMask
    T_admin_bytes = from_gf(T_admin_gf)
    
    forgery = C_admin_bytes + T_admin_bytes
    print(f"[*] Status: Sending Forgery: {forgery.hex()}")
    
    r.sendlineafter(b">", b"L")
    r.sendlineafter(b"token(hex)>", forgery.hex().encode())
    
    # Final response
    res = r.recvall(timeout=2).decode()
    print(res)

if __name__ == "__main__":
    solve()