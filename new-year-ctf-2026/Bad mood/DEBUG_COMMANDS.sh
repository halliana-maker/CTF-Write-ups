#!/bin/bash

# Auto-generated debugging commands

# Find offset to RIP/EIP
echo '[*] Finding offset...'
gdb bad_mood -ex 'pattern create 200' -ex 'r' -ex 'pattern offset $rip' -ex 'quit'

# Get function addresses
echo '[*] Function addresses:'
objdump -t bad_mood | grep -E 'win|flag|system'

# Find useful strings
echo '[*] Searching for useful strings:'
strings -a -t x bad_mood | grep -E 'flag|bin|sh'

# PLT/GOT entries
echo '[*] PLT/GOT:'
objdump -d bad_mood | grep '@plt'

# ROP gadgets (requires ROPgadget)
echo '[*] Finding ROP gadgets:'
ROPgadget --binary bad_mood | grep -E 'pop rdi|pop rsi|syscall'
