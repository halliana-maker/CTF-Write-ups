#!/bin/bash

# Auto-generated debugging commands

# Find offset to RIP/EIP
echo '[*] Finding offset...'
gdb secrets -ex 'pattern create 200' -ex 'r' -ex 'pattern offset $rip' -ex 'quit'

# Get function addresses
echo '[*] Function addresses:'
objdump -t secrets | grep -E 'win|flag|system'

# Find useful strings
echo '[*] Searching for useful strings:'
strings -a -t x secrets | grep -E 'flag|bin|sh'

# PLT/GOT entries
echo '[*] PLT/GOT:'
objdump -d secrets | grep '@plt'

# ROP gadgets (requires ROPgadget)
echo '[*] Finding ROP gadgets:'
ROPgadget --binary secrets | grep -E 'pop rdi|pop rsi|syscall'
