#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import io
import re
import socket
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _F(x, y, z): return ((x & y) | (~x & z)) & 0xffffffff
def _G(x, y, z): return ((x & y) | (x & z) | (y & z)) & 0xffffffff
def _H(x, y, z): return (x ^ y ^ z) & 0xffffffff
def _lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff


class MD4:
    def __init__(self, data=b""):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        self.count = 0
        self.buf = b""
        if data:
            self.update(data)

    def update(self, data: bytes):
        self.count += len(data)
        data = self.buf + data
        block_len = (len(data) // 64) * 64
        for i in range(0, block_len, 64):
            self._process(data[i:i + 64])
        self.buf = data[block_len:]

    def _process(self, block: bytes):
        X = list(struct.unpack("<16I", block))
        A, B, C, D = self.A, self.B, self.C, self.D

        s = [3, 7, 11, 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                A = _lrot((A + _F(B, C, D) + X[k]) & 0xffffffff, s[i % 4])
            elif i % 4 == 1:
                D = _lrot((D + _F(A, B, C) + X[k]) & 0xffffffff, s[i % 4])
            elif i % 4 == 2:
                C = _lrot((C + _F(D, A, B) + X[k]) & 0xffffffff, s[i % 4])
            else:
                B = _lrot((B + _F(C, D, A) + X[k]) & 0xffffffff, s[i % 4])

        s = [3, 5, 9, 13]
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, k in enumerate(order):
            if i % 4 == 0:
                A = _lrot((A + _G(B, C, D) + X[k] + 0x5A827999) & 0xffffffff, s[i % 4])
            elif i % 4 == 1:
                D = _lrot((D + _G(A, B, C) + X[k] + 0x5A827999) & 0xffffffff, s[i % 4])
            elif i % 4 == 2:
                C = _lrot((C + _G(D, A, B) + X[k] + 0x5A827999) & 0xffffffff, s[i % 4])
            else:
                B = _lrot((B + _G(C, D, A) + X[k] + 0x5A827999) & 0xffffffff, s[i % 4])

        s = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, k in enumerate(order):
            if i % 4 == 0:
                A = _lrot((A + _H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xffffffff, s[i % 4])
            elif i % 4 == 1:
                D = _lrot((D + _H(A, B, C) + X[k] + 0x6ED9EBA1) & 0xffffffff, s[i % 4])
            elif i % 4 == 2:
                C = _lrot((C + _H(D, A, B) + X[k] + 0x6ED9EBA1) & 0xffffffff, s[i % 4])
            else:
                B = _lrot((B + _H(C, D, A) + X[k] + 0x6ED9EBA1) & 0xffffffff, s[i % 4])

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self) -> bytes:
        saved = (self.A, self.B, self.C, self.D, self.count, self.buf)
        msg_len = self.count
        self.update(b"\x80" + b"\x00" * ((55 - msg_len) % 64) + struct.pack("<Q", msg_len * 8))
        out = struct.pack("<4I", self.A, self.B, self.C, self.D)
        self.A, self.B, self.C, self.D, self.count, self.buf = saved
        return out


def md4(data: bytes) -> bytes:
    return MD4(data).digest()


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    key = list(key)
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def nt_hash(password: str) -> bytes:
    return md4(password.encode("utf-16le"))


def ntlm_v2_hash(password: str, user: str, domain: str) -> bytes:
    nth = nt_hash(password)
    ident = (user.upper() + domain).encode("utf-16le")
    return hmac.new(nth, ident, hashlib.md5).digest()


def parse_pcap(path: Path):
    raw = path.read_bytes()
    f = io.BytesIO(raw)
    gh = f.read(24)
    if len(gh) != 24:
        raise ValueError("Invalid PCAP")
    magic = gh[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP format")
    _magic, _maj, _min, _tz, _sig, _snap, network = struct.unpack(endian + "IHHIIII", gh)
    if network != 1:
        raise ValueError("Expected Ethernet PCAP")
    packets = []
    while True:
        hdr = f.read(16)
        if not hdr:
            break
        ts_sec, ts_usec, inc_len, orig_len = struct.unpack(endian + "IIII", hdr)
        pkt = f.read(inc_len)
        packets.append(pkt)
    return packets


def parse_pkt(pkt: bytes):
    if len(pkt) < 14:
        return None
    if struct.unpack("!H", pkt[12:14])[0] != 0x0800:
        return None
    ip = pkt[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:
        return None
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", tcp[:14])
    off = ((off_flags >> 12) & 0xF) * 4
    flags = off_flags & 0x1FF
    payload = tcp[off:]
    return src, sport, dst, dport, seq, ack, flags, payload


def secbuf(msg: bytes, off: int):
    l, alloc, ptr = struct.unpack("<HHI", msg[off:off + 8])
    return l, ptr, msg[ptr:ptr + l]


def smb2_hdr(msg: bytes):
    if msg[:4] != b"\xfeSMB":
        return None
    return {
        "cmd": struct.unpack("<H", msg[12:14])[0],
        "status": struct.unpack("<I", msg[8:12])[0],
        "flags": struct.unpack("<I", msg[16:20])[0],
        "mid": struct.unpack("<Q", msg[24:32])[0],
        "tree": struct.unpack("<I", msg[36:40])[0],
        "sid": struct.unpack("<Q", msg[40:48])[0],
    }


def parse_transform(msg: bytes):
    sig = msg[4:20]
    nonce = msg[20:36]
    orig = struct.unpack("<I", msg[36:40])[0]
    _reserved = struct.unpack("<H", msg[40:42])[0]
    _flags = struct.unpack("<H", msg[42:44])[0]
    sid = struct.unpack("<Q", msg[44:52])[0]
    ct = msg[52:]
    return sig, nonce, orig, sid, ct


def wireshark_kdf(key: bytes, label_with_nul: bytes, label_len: int, context: bytes, context_len: int, outlen: int):
    # Matches Wireshark / SMB2 key derivation behavior:
    # counter || Label(label_len bytes, including NUL) || 0x00 || Context || L
    msg = struct.pack(">I", 1) + label_with_nul[:label_len] + b"\x00" + context[:context_len] + struct.pack(">I", outlen * 8)
    return hmac.new(key, msg, hashlib.sha256).digest()[:outlen]


def xor_reset_each_chunk(chunks, key: bytes):
    out = []
    for chunk in chunks:
        out.append(bytes(b ^ key[i % len(key)] for i, b in enumerate(chunk)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    args = ap.parse_args()

    packets = parse_pcap(args.pcap)
    rows = [r for r in map(parse_pkt, packets) if r]

    smb = [r for r in rows if r[1] == 64628 or r[3] == 64628]
    side = [r for r in rows if r[1] == 64627 or r[3] == 64627]

    print(f"[+] total packets: {len(packets)}")
    print(f"[+] smb packets  : {len(smb)}")
    print(f"[+] side packets : {len(side)}")

    # Extract NTLM challenge/auth blobs
    chal_blob = None
    auth_blob = None
    for r in smb:
        payload = r[7]
        if len(payload) < 8:
            continue
        nb_len = int.from_bytes(payload[:4], "big")
        msg = payload[4:4 + nb_len]
        p2 = msg.find(b"NTLMSSP\x00\x02\x00\x00\x00")
        if p2 != -1:
            chal_blob = msg[p2:]
        p3 = msg.find(b"NTLMSSP\x00\x03\x00\x00\x00")
        if p3 != -1:
            auth_blob = msg[p3:]

    if not chal_blob or not auth_blob:
        raise RuntimeError("Could not find NTLMSSP blobs")

    server_challenge = chal_blob[24:32]
    _domain_len, _domain_off, domain_raw = secbuf(auth_blob, 28)
    _user_len, _user_off, user_raw = secbuf(auth_blob, 36)
    _workstation_len, _workstation_off, workstation_raw = secbuf(auth_blob, 44)
    _sesskey_len, _sesskey_off, enc_sessionkey = secbuf(auth_blob, 52)
    _nt_len, _nt_off, nt_resp = secbuf(auth_blob, 20)

    domain = domain_raw.decode("utf-16le")
    user = user_raw.decode("utf-16le")
    workstation = workstation_raw.decode("utf-16le")

    print(f"[+] domain      : {domain}")
    print(f"[+] user        : {user}")
    print(f"[+] workstation : {workstation}")
    print(f"[+] challenge   : {server_challenge.hex()}")

    password = "password"
    v2hash = ntlm_v2_hash(password, user, domain)
    ntproof = nt_resp[:16]
    blob = nt_resp[16:]
    calc = hmac.new(v2hash, server_challenge + blob, hashlib.md5).digest()
    if calc != ntproof:
        raise RuntimeError("Known password no longer verifies")
    session_base_key = hmac.new(v2hash, ntproof, hashlib.md5).digest()
    session_key = rc4(session_base_key, enc_sessionkey)

    print(f"[+] cracked NTLMv2 password: {password!r}")
    print(f"[+] session key          : {session_key.hex()}")

    # Reconstruct full SMB streams
    dirs = {"c2s": [], "s2c": []}
    for src, sport, dst, dport, seq, ack, flags, payload in smb:
        if payload:
            direction = "c2s" if src == "10.1.2.210" else "s2c"
            dirs[direction].append((seq, payload))

    stream_bytes = {}
    for direction, segs in dirs.items():
        segs = sorted(segs)
        base = segs[0][0]
        data = bytearray()
        for seq, payload in segs:
            off = seq - base
            if off > len(data):
                data.extend(b"\x00" * (off - len(data)))
            end = off + len(payload)
            if end > len(data):
                data.extend(b"\x00" * (end - len(data)))
            data[off:end] = payload
        stream_bytes[direction] = bytes(data)

    def split_nbss(data: bytes):
        out = []
        i = 0
        while i + 4 <= len(data):
            l = int.from_bytes(data[i:i + 4], "big")
            if i + 4 + l > len(data):
                break
            out.append(data[i + 4:i + 4 + l])
            i += 4 + l
        return out

    c2s_msgs = split_nbss(stream_bytes["c2s"])
    s2c_msgs = split_nbss(stream_bytes["s2c"])

    # SMB 3.1.1 preauth hash for session keys:
    # Negotiate req/resp + first session setup req/resp + final session setup req
    preauth = b"\x00" * 64
    for msg in [c2s_msgs[1], s2c_msgs[1], c2s_msgs[2], s2c_msgs[2], c2s_msgs[3]]:
        preauth = hashlib.sha512(preauth + msg).digest()

    c2s_key = wireshark_kdf(session_key, b"SMBC2SCipherKey\x00", 16, preauth, 64, 16)
    s2c_key = wireshark_kdf(session_key, b"SMBS2CCipherKey\x00", 16, preauth, 64, 16)

    print(f"[+] SMB C2S key          : {c2s_key.hex()}")
    print(f"[+] SMB S2C key          : {s2c_key.hex()}")

    # Decrypt SMB transform messages and recover uploaded file
    decrypted_c2s = []
    for msg in c2s_msgs:
        if msg[:4] == b"\xfdSMB":
            sig, nonce, orig, sid, ct = parse_transform(msg)
            pt = AESGCM(c2s_key).decrypt(nonce[:12], ct + sig, msg[20:52])
            decrypted_c2s.append(pt)
        else:
            decrypted_c2s.append(msg)

    uploads = []
    for msg in decrypted_c2s:
        hdr = smb2_hdr(msg)
        if not hdr or hdr["cmd"] != 9:
            continue
        body = msg[64:]
        data_off = struct.unpack("<H", body[2:4])[0]
        length = struct.unpack("<I", body[4:8])[0]
        offset = struct.unpack("<Q", body[8:16])[0]
        data = msg[data_off:data_off + length]
        uploads.append((offset, data))

    if uploads:
        total = max(off + len(data) for off, data in uploads)
        exe = bytearray(total)
        for off, data in uploads:
            exe[off:off + len(data)] = data
        outdir = Path("file_transfer_out")
        outdir.mkdir(exist_ok=True)
        (outdir / "DaVinci.exe").write_bytes(exe)
        print(f"[+] Recovered uploaded file: {outdir / 'DaVinci.exe'} ({len(exe)} bytes)")

    # Decode side-channel traffic
    side_server_chunks = [
        payload for src, sport, dst, dport, seq, ack, flags, payload in side
        if src == "10.1.2.211" and sport == 55544 and payload
    ]
    key = b"sorry_im_not_the_flag_:)"
    decoded = xor_reset_each_chunk(side_server_chunks, key)

    print("[+] Decoded side-channel replies:")
    for i, chunk in enumerate(decoded):
        print(f"    chunk {i}: {chunk!r}")

    merged = b"".join(decoded)
    m = re.search(rb"jctf\{[^}]+\}", merged)
    if not m:
        raise RuntimeError("Flag not found")
    flag = m.group(0).decode()

    print(f"\n[+] FLAG: {flag}")


if __name__ == "__main__":
    main()


# $ python3 solve.py export.pcap
# [+] total packets: 109
# [+] smb packets  : 91
# [+] side packets : 18
# [+] domain      : IT640
# [+] user        : operator1
# [+] workstation : W11-C1
# [+] challenge   : a83c46425815db34
# [+] cracked NTLMv2 password: 'password'
# [+] session key          : c6f366b63fe4dc75cddfc119f26d708c
# [+] SMB C2S key          : 02b4aea9c85733f8de0a909ba3c95541
# [+] SMB S2C key          : 039c6063b9f3403446c3a061886fa6ff
# [+] Recovered uploaded file: file_transfer_out/DaVinci.exe (128000 bytes)
# [+] Decoded side-channel replies:
#     chunk 0: b'start "" "C:\\Program Files\\DaVinci\\latmove.bat"-wk'
#     chunk 1: b'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /V "DaVinci" /t REG_SZ /F /D "C:\\Program Files\\DaVinci\\DaVinci.exe"[jk'
#     chunk 2: b'echo Mess with the best, die like the rest >> C:\\Users\\Public\\Desktop\\pwnd.txt & echo jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce} >> C:\\Users\\Public\\Desktop\\pwnd.txtbhe'
#     chunk 3: b'wkv'

# [+] FLAG: jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}