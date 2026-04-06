# PWN Analysis Report: Bad mood

**Generated:** 2026-01-11T21:03:16

**Binary:** /home/ctf/Downloads/Bad mood/bad_mood

---

## Executive Summary

- **Total Vulnerabilities Found:** 3
- **Critical/High Severity:** 2
- **Exploitation Chains:** 1
- **Recommended Approach:** No obvious exploitation chain


## Binary Protections

- **Architecture:** amd64 (64-bit)
- **PIE:** ✓ Enabled
- **NX:** ✓ Enabled
- **Canary:** ✓ Enabled
- **RELRO:** Full


## Detected Vulnerabilities

### 1. dangerous_function_printf [MEDIUM]

**Description:** Uses dangerous function: printf

**Evidence:** `Symbol found: printf`

**Exploitation Notes:**
- Potential format string if user input not sanitized


### 2. format_string [HIGH]

**Description:** Uses printf - potential format string vulnerability

**Evidence:** `Symbol found: printf`

**Exploitation Notes:**
- If user input goes directly to printf: format string bug
- Can leak stack/memory with %p, %x, %s
- Can write with %n
- Overwrite GOT entries to hijack control flow


### 3. format_string [HIGH]

**Description:** Format string vulnerability detected

**Evidence:** `['printf', 'plt.printf', 'got.printf']`

**Exploitation Notes:**
- Leak canary: %p at stack offset N
- Leak PIE base: find code pointer on stack
- Leak libc: find libc pointer (environ, __libc_start_main)
- Use %s to dereference and read memory


## Recommended Exploitation Chains

### Chain 0: No obvious exploitation chain

**Success Probability:** UNKNOWN

**Steps:**
Manual analysis required

**Notes:**
- Vulnerabilities unclear from static analysis
- Try dynamic analysis with fuzzing

---

## Next Steps

1. Calculate format string offset
2. Leak libc addresses to bypass ASLR


## Key Hints

- Source downloaded: bad_mood
- NX enabled (likely needs ROP/ret2libc).
- PIE enabled (needs leak for code base).
- Heap: use_after_free - Binary uses malloc/free - check for UAF via dynamic analysis
- Format string functions detected: printf, plt.printf, got.printf
- Found 4 one_gadget(s) in libc - check constraints!
- Ghidra pseudo-C embedded in JSON (step ghidra_decompile.stdout).
- Functions without canary: _init, getenv@plt-0x10, getenv@plt, free@plt, puts@plt

