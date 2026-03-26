# SELFsigned (Web/Pwn) - BSidesSF CTF 2026 Writeup

## 1. TL;DR
The server implements a custom ELF signature verification system that hashes and validates the binary based solely on its **Sections** (used by linkers and debuggers) rather than its **Segments** (used by the Linux kernel for execution). By downloading a legitimately signed binary provided by the server, appending our own shellcode to the end of the file, and modifying the unhashed **Program Header Table** to point the executable segment to our shellcode, we successfully hijack the execution flow while keeping the digital signature 100% valid.

## 2. What Data/Files We Have & Interactivity
We are given a web portal with a few static endpoints and one interactive endpoint:
*   **`/spec`**: A Markdown document explaining the custom "SELF-Signed" specification. It dictates exactly how the binary is hashed and signed using Ed25519.
*   **`/pubkey`**: The server's Ed25519 public key.
*   **`/selfsigned-amd64` & `/selfsigned-arm64`**: Pre-compiled, legitimately signed ELF binaries.
*   **`/upload`**: An HTML form where the user uploads an ELF binary. 
    *   **Interactivity**: When a file is uploaded, the backend parses the ELF, checks the signature embedded in the `.selfsigned` section against its public key allowlist, and calculates the hash. If the signature is valid, the server executes the binary and returns the standard output. If invalid, it returns an HTTP 400 error like `Signature verification failed`.

## 3. Problem Analysis (In Detail)
The core of the challenge lies within the `spec` file. Let's look closely at the **Hashing** section of the specification:

> The hashable state of the binary is represented by the following:
> *   The ELF File Header
> *   A dictionary of section name to the contents of the section header unless the section does not have the ALLOC flag.
> *   A dictionary of section name to the hash of the contents of the section contents unless the section does not have the ALLOC flag or the section type is SHT_NOBITS.

**The Vulnerability:**
ELF binaries have two parallel structures:
1.  **Sections (Section Header Table):** Used by tools like `readelf`, `objdump`, and linkers.
2.  **Segments (Program Header Table):** Used by the Linux kernel to actually map the file into memory and execute it. 

The custom signing algorithm strictly hashes the **Sections**. It hashes the 64-byte ELF Header, the Section Headers, and the Section Contents. However, it completely ignores the **Program Header Table (PHT)** and any raw bytes in the file that aren't explicitly mapped to an `ALLOC` section.

Because the Linux kernel loader *only* cares about Segments (`PT_LOAD` directives in the Program Header Table) and completely ignores Sections during execution, we have a classic parser mismatch! We can modify the Program Headers to manipulate how the binary is loaded into memory without altering the hash of the Sections. 

## 4. Initial Guesses / First Try
Because the challenge was named "SELFsigned", the initial hypothesis was a literal "self-signed certificate" attack. The thought process was:
1. Generate our own Ed25519 keypair.
2. Write a malicious C program and compile it.
3. Sign our malicious binary with our generated private key.
4. Embed our *public key* and *signature* into the binary (mimicking the `.selfsigned` section structure).
5. Upload it, hoping the server naively trusts the embedded public key to verify the embedded signature.

**Why it failed:** 
Upon uploading this payload, the server threw an error. Checking the `/spec` again revealed this line under the *ELF Verification* section:
> *"The public key in the signature section is compared against the allowlist of public keys."*

The server wasn't naive. It checked the public key against a hardcoded allowlist (the one at `/pubkey`). We couldn't forge the signature; we had to bypass the hashing mechanism itself.

## 5. Exploitation Walkthrough / Flag Recovery

To exploit the Section vs. Segment parser mismatch, we need to take a pre-signed binary and carefully surgically alter it.

**Step 1: Obtain a Valid Binary**
We download the `selfsigned-amd64` tool directly from the server. Because the server signed it, its sections perfectly match the cryptographic signature.

**Step 2: Locate the Executable Segment**
We parse the original binary to find its **Entry Point** (from the hashed ELF Header). We cannot change the entry point address because the ELF Header is hashed. Instead, we scan the unhashed Program Header Table to find the `PT_LOAD` segment that contains the Entry Point.

**Step 3: Append Shellcode**
We generate AMD64 shellcode to read the flag (`cat /home/ctf/flag.txt`). We append this shellcode to the very end of the file. Because these appended bytes do not belong to any defined Section, the hashing algorithm ignores them.

**Step 4: Align the Payload**
Since we cannot change the `e_entry` address in the ELF header, we must ensure that when the kernel maps our shellcode into memory, the shellcode perfectly overlaps with the original entry point address. We calculate the offset (`e_entry - p_vaddr`) and pad our shellcode with NOPs (`\x90`) so the execution slides right into our payload.

**Step 5: Overwrite the Program Header**
We edit the original Program Header entry in the binary. We change the `p_offset` to point to our newly appended shellcode at the end of the file, and update `p_filesz` and `p_memsz` to accommodate our payload size. 

Then we can use the solve.py program to get the flag, here is the output of the program:
```
[*] Downloading signed binary from https://selfsigned-6c8c026e.challenges.bsidessf.net/selfsigned-amd64...
[*] Found executable segment at index 2
[*] Original Entry Point: 0x487520
[*] Modified PHT segment 2 to point to offset 0x5c8000
[*] Uploading hijacked signed binary...
[+] Success! Flag found:
CTF{sections_and_segments_r_same_right?}
```


**Result:**
The script successfully modifies the binary. The server verifies the sections, finds the signature valid, executes the file, and the OS loads our payload instead.

**Flag:** `CTF{sections_and_segments_r_same_right?}`

## 6. What We Learned
1. **Sections vs. Segments:** The flag says it all. Sections and Segments are fundamentally different. Sections are for static analysis, linking, and debugging. Segments are for execution.
2. **Security Tooling Pitfalls:** If you are building a security tool (like an antivirus, a binary signer, or a sandbox) that parses executables, **you must parse it exactly how the OS loader parses it**. Failing to include the Program Headers in the cryptographic hash meant the actual executing logic of the file was completely unprotected.