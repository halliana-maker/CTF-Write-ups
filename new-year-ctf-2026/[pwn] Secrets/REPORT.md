# PWN Analysis Report: Secrets

**Generated:** 2026-01-11T19:27:23

**Binary:** /home/ctf/Downloads/Secrets/secrets

---

## Executive Summary

- **Total Vulnerabilities Found:** 4
- **Critical/High Severity:** 3
- **Exploitation Chains:** 3
- **Recommended Approach:** Stack Buffer Overflow -> ROP/ret2libc


## Binary Protections

- **Architecture:** amd64 (64-bit)
- **PIE:** ✗ Disabled
- **NX:** ✓ Enabled
- **Canary:** ✗ Disabled
- **RELRO:** Partial


## Detected Vulnerabilities

### 1. dangerous_function_printf [MEDIUM]

**Description:** Uses dangerous function: printf

**Evidence:** `Symbol found: printf`

**Exploitation Notes:**
- Potential format string if user input not sanitized


### 2. stack_buffer_overflow [HIGH]

**Description:** No stack canary - stack buffer overflow easier to exploit

**Evidence:** `checksec shows no canary`

**Exploitation Notes:**
- Can overwrite return address directly
- Use cyclic pattern to find offset
- Build ROP chain or ret2libc


### 3. format_string [HIGH]

**Description:** Uses printf - potential format string vulnerability

**Evidence:** `Symbol found: printf`

**Exploitation Notes:**
- If user input goes directly to printf: format string bug
- Can leak stack/memory with %p, %x, %s
- Can write with %n
- Overwrite GOT entries to hijack control flow


### 4. format_string [HIGH]

**Description:** Format string vulnerability detected

**Evidence:** `['printf', 'plt.printf', 'got.printf']`

**Exploitation Notes:**
- Leak canary: %p at stack offset N
- Leak PIE base: find code pointer on stack
- Leak libc: find libc pointer (environ, __libc_start_main)
- Use %s to dereference and read memory


## Recommended Exploitation Chains

### Chain 1: Stack Buffer Overflow -> ROP/ret2libc

**Success Probability:** HIGH

**Steps:**
1. Trigger buffer overflow with calculated offset
2. Build ROP chain to bypass NX
3. ret2libc or ret2syscall for code execution

**Notes:**
- Classic exploitation chain
- Most reliable if no canary

---

### Chain 2: Format String -> GOT Overwrite

**Success Probability:** HIGH

**Prerequisites:**
- Partial RELRO (GOT writable)

**Steps:**
1. Use format string to leak libc addresses
2. Calculate libc base and system() address
3. Use %n to overwrite GOT entry (e.g., puts@GOT)
4. Trigger overwritten function with '/bin/sh' argument

**Notes:**
- Very powerful if available
- No need for stack overflow

---

### Chain 4: ret2dlresolve (Advanced)

**Success Probability:** MEDIUM

**Prerequisites:**
- No PIE
- Partial RELRO
- Advanced ROP skills

**Steps:**
1. Overflow to control RIP
2. Build fake link_map structure on stack/bss
3. Craft ROP chain to call _dl_runtime_resolve
4. Force resolver to resolve arbitrary function (system)
5. Execute with controlled arguments

**Notes:**
- Complex but powerful
- Use pwntools Ret2dlresolvePayload

---

## Next Steps

1. Calculate exact buffer overflow offset (use cyclic pattern)
2. Build ROP chain or ret2libc payload
1. Calculate format string offset
2. Leak libc addresses to bypass ASLR


## Key Hints

- NX enabled (likely needs ROP/ret2libc).
- No stack canary (stack BOF easier).
- ret2dlresolve is feasible!
- Heap: use_after_free - Binary uses malloc/free - check for UAF via dynamic analysis
- Format string functions detected: printf, plt.printf, got.printf
- Found 4 one_gadget(s) in libc - check constraints!
- Ghidra pseudo-C embedded in JSON (step ghidra_decompile.stdout).
- Functions without canary: _init, getenv@plt-0x10, getenv@plt, free@plt, puts@plt
- 🎯 Quick Win: Classic BOF: No PIE, No Canary (10-15 minutes)

