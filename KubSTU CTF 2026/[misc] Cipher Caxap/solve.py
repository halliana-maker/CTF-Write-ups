#!/usr/bin/env python3
"""
Solver for KubSTU Cipher "Сахар" / Sugar Capybara Talks.

What it does:
1. Parses the PCAP without tshark/scapy.
2. Finds the real encrypted Sugar protocol TCP stream.
3. Parses frames: uint32_be(length) || 16-byte IV || AES-CBC ciphertext.
4. Cracks the passphrase from built-in candidates or a wordlist.
5. Decrypts the captured session.
6. Optionally connects to the live nc server and tries flag commands.

Usage:
  pip install pycryptodome
  python3 solve_sugar.py 'sugar_traffic.pcap'

With rockyou:
  sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
  python3 solve_sugar.py 'sugar_traffic.pcap' -w /usr/share/wordlists/rockyou.txt --live

If you already know the passphrase:
  python3 solve_sugar.py 'sugar_traffic.pcap' -p 'PASSPHRASE' --live
"""

import argparse
import collections
import hashlib
import gzip
import os
import socket
import urllib.request
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

# Prefer PyCryptodome, fall back to cryptography.
_AES_BACKEND = None
try:
    from Crypto.Cipher import AES as _PYAES
    _AES_BACKEND = "pycryptodome"
except Exception:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        _AES_BACKEND = "cryptography"
    except Exception:
        print("[-] Need one AES backend: pip install pycryptodome", file=sys.stderr)
        raise

BANNER_END = b">>>ENCRYPTED_CHANNEL_ACTIVE<<<\n"

_W_FRAMES = None
_W_SALT = None


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block != 0:
        raise ValueError("bad padded length")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS#7 padding")
    return data[:-n]


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    if _AES_BACKEND == "pycryptodome":
        return _PYAES.new(key, _PYAES.MODE_CBC, iv).decrypt(ct)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    if _AES_BACKEND == "pycryptodome":
        return _PYAES.new(key, _PYAES.MODE_CBC, iv).encrypt(pt)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pt) + enc.finalize()


def ip4(b: bytes) -> str:
    return socket.inet_ntoa(b)


def read_pcap_tcp_payloads(path: str):
    packets = []
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("bad pcap header")

        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError(f"unknown pcap magic: {magic.hex()}")

        pktno = 0
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break

            ts, usec, caplen, _origlen = struct.unpack(endian + "IIII", ph)
            data = f.read(caplen)
            pktno += 1

            if len(data) < 14:
                continue

            eth_type = struct.unpack("!H", data[12:14])[0]
            off = 14
            if eth_type == 0x8100 and len(data) >= 18:
                eth_type = struct.unpack("!H", data[16:18])[0]
                off = 18
            if eth_type != 0x0800:
                continue

            ip = data[off:]
            if len(ip) < 20:
                continue

            ihl = (ip[0] & 0x0F) * 4
            if len(ip) < ihl or ip[9] != 6:
                continue

            total_len = struct.unpack("!H", ip[2:4])[0]
            tcp = ip[ihl:total_len]
            if len(tcp) < 20:
                continue

            sport, dport, seq, ack, offres, flags, *_ = struct.unpack("!HHIIBBHHH", tcp[:20])
            doff = (offres >> 4) * 4
            payload = tcp[doff:]

            if payload:
                packets.append({
                    "pktno": pktno,
                    "time": ts + usec / 1_000_000,
                    "src": ip4(ip[12:16]),
                    "sport": sport,
                    "dst": ip4(ip[16:20]),
                    "dport": dport,
                    "seq": seq,
                    "ack": ack,
                    "flags": flags,
                    "payload": payload,
                })

    return packets


def reassemble(segs):
    out = b""
    cur = None

    for seq, payload in sorted(segs, key=lambda x: x[0]):
        if cur is None:
            cur = seq

        if seq < cur:
            skip = cur - seq
            if skip >= len(payload):
                continue
            payload = payload[skip:]
            seq = cur

        if seq > cur:
            out += b"<GAP>"
            cur = seq

        out += payload
        cur += len(payload)

    return out


def build_streams(packets, server_port=31337):
    streams = collections.defaultdict(lambda: {"cs": [], "sc": []})

    for p in packets:
        if p["dport"] == server_port:
            streams[p["sport"]]["cs"].append((p["seq"], p["payload"]))
        elif p["sport"] == server_port:
            streams[p["dport"]]["sc"].append((p["seq"], p["payload"]))

    return {
        port: {"cs": reassemble(v["cs"]), "sc": reassemble(v["sc"])}
        for port, v in streams.items()
    }


def extract_salt(sc_data: bytes):
    marker = b"SALT:"
    i = sc_data.find(marker)
    if i < 0:
        return None
    j = sc_data.find(b"\n", i)
    if j < 0:
        return None
    return sc_data[i + len(marker):j].strip()


def parse_frames(buf: bytes):
    frames = []
    pos = 0

    while pos + 4 <= len(buf):
        n = struct.unpack(">I", buf[pos:pos + 4])[0]

        if n < 32 or n > 1_000_000:
            return frames, buf[pos:], f"bad length {n} at offset {pos}"

        if pos + 4 + n > len(buf):
            return frames, buf[pos:], f"truncated frame at offset {pos}"

        body = buf[pos + 4:pos + 4 + n]

        if len(body) < 32 or (len(body) - 16) % 16 != 0:
            return frames, buf[pos:], f"bad AES body length {len(body)} at offset {pos}"

        frames.append(body)
        pos += 4 + n

    return frames, buf[pos:], None


def find_real_session(streams):
    candidates = []

    for port, data in streams.items():
        sc = data["sc"]
        cs = data["cs"]

        if BANNER_END not in sc:
            continue

        salt = extract_salt(sc)
        after_banner = sc.split(BANNER_END, 1)[1]

        cframes, _, cerr = parse_frames(cs)
        sframes, _, serr = parse_frames(after_banner)

        if salt and cframes and sframes and not cerr and not serr:
            score = sum(len(x) for x in cframes) + sum(len(x) for x in sframes)
            candidates.append((score, port, salt, cframes, sframes))

    if not candidates:
        raise RuntimeError("could not find a clean encrypted Sugar session")

    candidates.sort(reverse=True)
    return candidates[0]


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum((32 <= c < 127) or c in (9, 10, 13) for c in b) / len(b)


def derive_keys(passphrase: str, salt_ascii: bytes):
    p = passphrase.encode("utf-8", errors="ignore")

    yield "sha256(passphrase || salt-ascii)", hashlib.sha256(p + salt_ascii).digest()

    try:
        salt_hex = bytes.fromhex(salt_ascii.decode())
        yield "sha256(passphrase || salt-hex)", hashlib.sha256(p + salt_hex).digest()
        yield "sha256(salt-hex || passphrase)", hashlib.sha256(salt_hex + p).digest()
    except Exception:
        pass

    yield "sha256(salt-ascii || passphrase)", hashlib.sha256(salt_ascii + p).digest()


def decrypt_body(key: bytes, body: bytes) -> bytes:
    iv = body[:16]
    ct = body[16:]
    return pkcs7_unpad(aes_cbc_decrypt(key, iv, ct), 16)


def check_passphrase(passphrase: str, salt: bytes, test_frames):
    for kdf_name, key in derive_keys(passphrase, salt):
        pts = []
        try:
            for body in test_frames:
                pt = decrypt_body(key, body)
                if printable_ratio(pt) < 0.80:
                    raise ValueError("not printable")
                pts.append(pt)
            return kdf_name, key, pts
        except Exception:
            continue
    return None


def builtin_candidates():
    roots = [
        "sugar", "Sugar", "SUGAR", "sugar!", "sugar123", "sug4r",
        "sugarrush", "sugar_rush", "sugarprotocol", "sugar_protocol",
        "capybara", "capybaras", "sugarcapybara", "sugar_capybara",
        "SugarCapybara", "SugarCapybaraTalks", "sugarcapybaratalks",
        "sahar", "sakhar", "saxar", "saxap", "caxap",
        "Сахар", "сахар", "сахарок", "rafinad", "рафинад",
        "sucrose", "glucose", "fructose", "caramel", "molasses",
        "honey", "toffee", "candy", "sweet", "sweetness",
        "thankspluxury", "pluxury", "luxury", "kubstu", "KubSTU",
        "secret", "protocol", "command", "server", "31337",
    ]

    suffixes = ["", "!", "123", "1234", "2024", "2025", "2026", "31337", "_31337", "_2024", "-31337"]

    out = []
    for r in roots:
        forms = {r, r.lower(), r.upper(), r.title(), r.capitalize()}
        for f in forms:
            for s in suffixes:
                out.append(f + s)

    return list(dict.fromkeys(out))


def worker_init(frames, salt):
    global _W_FRAMES, _W_SALT
    _W_FRAMES = frames
    _W_SALT = salt


def worker_check_chunk(words):
    for word in words:
        w = word.strip("\r\n")
        if not w:
            continue

        hit = check_passphrase(w, _W_SALT, _W_FRAMES)
        if hit:
            kdf_name, _key, pts = hit
            return w, kdf_name, pts

    return None


ROCKYOU_URLS = [
    # Kali Linux package mirror; usually the most reliable direct gzip source.
    "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz",
    # Public GitHub mirror.
    "https://raw.githubusercontent.com/teamstealthsec/wordlists/master/rockyou.txt.gz",
    # Weakpass public mirror.
    "https://weakpass.com/wordlists/rockyou.txt.gz",
]


def download_file(url, out_path):
    print(f"[*] Downloading wordlist:")
    print(f"    {url}")
    print(f"    -> {out_path}")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 CTF-solver"}
    )

    with urllib.request.urlopen(req, timeout=60) as r, open(out_path, "wb") as f:
        total = r.headers.get("Content-Length")
        total = int(total) if total and total.isdigit() else None
        got = 0

        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)

            if total:
                pct = got * 100 / total
                print(f"\r    downloaded {got / 1024 / 1024:.1f} MiB / {total / 1024 / 1024:.1f} MiB ({pct:.1f}%)", end="", flush=True)
            else:
                print(f"\r    downloaded {got / 1024 / 1024:.1f} MiB", end="", flush=True)

    print()
    return out_path


def ensure_rockyou(download=False, out_path="rockyou.txt.gz"):
    found = resolve_wordlist_path(None)
    if found:
        return found

    if not download:
        return None

    for url in ROCKYOU_URLS:
        try:
            if os.path.exists(out_path) and os.path.getsize(out_path) > 1024 * 1024:
                return out_path
            return download_file(url, out_path)
        except Exception as e:
            print(f"[!] Download failed from {url}: {e}")

    return None


def resolve_wordlist_path(path):
    """
    Accept:
      /usr/share/wordlists/rockyou.txt
      /usr/share/wordlists/rockyou.txt.gz
      ./rockyou.txt
      ./rockyou.txt.gz

    If the user gives rockyou.txt but only rockyou.txt.gz exists, use the .gz directly.
    """
    if not path:
        candidates = [
            "rockyou.txt",
            "rockyou.txt.gz",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
            "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
        ]
    else:
        candidates = [path]
        if not path.endswith(".gz"):
            candidates.append(path + ".gz")

    for p in candidates:
        if os.path.exists(p):
            return p

    return None


def open_wordlist_text(path, encoding="latin-1"):
    real = resolve_wordlist_path(path)
    if not real:
        checked = [path, path + ".gz"] if path and not path.endswith(".gz") else [path]
        raise FileNotFoundError(
            "wordlist not found. Checked: " + ", ".join(x for x in checked if x)
        )

    print(f"[*] Using wordlist file: {real}")
    if real.endswith(".gz"):
        return gzip.open(real, "rt", encoding=encoding, errors="ignore")
    return open(real, "r", encoding=encoding, errors="ignore")


def chunks_from_wordlist(path, chunk_size=5000, encoding="latin-1"):
    with open_wordlist_text(path, encoding=encoding) as f:
        chunk = []
        for line in f:
            chunk.append(line)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

        if chunk:
            yield chunk


def crack_passphrase(salt, cframes, sframes, wordlist=None, jobs=None, download_wordlist=False):
    test_frames = [cframes[0], sframes[0]]

    print("[*] Trying built-in/theme candidates...")
    for cand in builtin_candidates():
        hit = check_passphrase(cand, salt, test_frames)
        if hit:
            kdf_name, key, _pts = hit
            return cand, kdf_name, key

    # If no explicit wordlist was passed, try common locations automatically.
    # If --download-rockyou was given, download rockyou.txt.gz into the current folder.
    if not wordlist:
        wordlist = ensure_rockyou(download=download_wordlist)
        if not wordlist:
            return None, None, None

    if jobs is None or jobs < 1:
        jobs = max(1, (os.cpu_count() or 2) - 1)

    print(f"[*] Cracking with wordlist: {wordlist}")
    print(f"[*] Workers: {jobs}")

    submitted = 0
    with ProcessPoolExecutor(max_workers=jobs, initializer=worker_init, initargs=(test_frames, salt)) as ex:
        futures = set()

        for chunk in chunks_from_wordlist(wordlist):
            submitted += len(chunk)
            futures.add(ex.submit(worker_check_chunk, chunk))

            if submitted % 100000 == 0:
                print(f"[*] submitted {submitted} candidates...")

            if len(futures) >= jobs * 4:
                done = next(as_completed(futures))
                futures.remove(done)
                res = done.result()

                if res:
                    w, kdf_name, _pts = res
                    hit = check_passphrase(w, salt, test_frames)
                    if hit:
                        _kdf, key, _ = hit
                        ex.shutdown(cancel_futures=True)
                        return w, kdf_name, key

        for done in as_completed(futures):
            res = done.result()
            if res:
                w, kdf_name, _pts = res
                hit = check_passphrase(w, salt, test_frames)
                if hit:
                    _kdf, key, _ = hit
                    return w, kdf_name, key

    return None, None, None


def decrypt_session(key, cframes, sframes):
    print("\n========== DECRYPTED CAPTURED SESSION ==========")
    n = max(len(cframes), len(sframes))

    for i in range(n):
        if i < len(cframes):
            try:
                pt = decrypt_body(key, cframes[i])
                print(f"\n[C -> S #{i}] {pt.decode('utf-8', errors='replace')}")
            except Exception as e:
                print(f"\n[C -> S #{i}] <decrypt error: {e}>")

        if i < len(sframes):
            try:
                pt = decrypt_body(key, sframes[i])
                text = pt.decode("utf-8", errors="replace")
                print(f"[S -> C #{i}] {text}")
                if "KubSTU{" in text or "KubSTU(" in text:
                    print("[+] Possible flag is in the server output above.")
            except Exception as e:
                print(f"[S -> C #{i}] <decrypt error: {e}>")


def recvn(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError("connection closed")
        data += part
    return data


def recv_banner(sock):
    data = b""
    while BANNER_END not in data:
        ch = sock.recv(1)
        if not ch:
            raise EOFError("closed before banner finished")
        data += ch
    return data


def key_for_live(passphrase: str, salt: bytes, kdf_name: str):
    p = passphrase.encode()

    if kdf_name == "sha256(passphrase || salt-hex)":
        return hashlib.sha256(p + bytes.fromhex(salt.decode())).digest()
    if kdf_name == "sha256(salt-hex || passphrase)":
        return hashlib.sha256(bytes.fromhex(salt.decode()) + p).digest()
    if kdf_name == "sha256(salt-ascii || passphrase)":
        return hashlib.sha256(salt + p).digest()

    return hashlib.sha256(p + salt).digest()


def send_frame(sock, key, plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    iv = os.urandom(16)
    ct = aes_cbc_encrypt(key, iv, pkcs7_pad(plaintext, 16))
    body = iv + ct
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_frame(sock, key):
    hdr = recvn(sock, 4)

    # Some failure replies are plaintext errors.
    if hdr.startswith(b"ERR"):
        return hdr + sock.recv(4096)

    n = struct.unpack(">I", hdr)[0]
    body = recvn(sock, n)
    return decrypt_body(key, body)


def live_client(host, port, passphrase, kdf_name, fallback_salt=None):
    print(f"\n[*] Connecting to {host}:{port}")
    s = socket.create_connection((host, port), timeout=10)
    banner = recv_banner(s)
    print(banner.decode(errors="replace"))

    salt = extract_salt(banner)
    if not salt:
        if fallback_salt:
            salt = fallback_salt
            print(f"[*] Live banner has no SALT; using PCAP salt: {salt.decode(errors='replace')}")
        else:
            raise RuntimeError("server banner did not contain SALT and no fallback salt was provided")

    key = key_for_live(passphrase, salt, kdf_name)

    # Important: read the actual home flag first.
    # The decrypted documents contain many fake "analysis" flags/prompt-injection notes.
    # Do not trust flags embedded inside documents unless ~/flag.txt fails.
    commands = [
        "cat flag.txt",
        "cat ./flag.txt",
        "cat /home/ctfuser/flag.txt",
        "ls -la",
        "pwd",
        "whoami",
        "id",
        "find . -maxdepth 3 -type f -name '*flag*' -o -name '*.txt'",
        "help",
        "ls",
        "ls documents",
        "ls drafts",
    ]

    for cmd in commands:
        try:
            print(f"\n$ {cmd}")
            send_frame(s, key, cmd)
            ans = recv_frame(s, key)
            text = ans.decode("utf-8", errors="replace")
            print(text)

            if "KubSTU{" in text or "KubSTU(" in text:
                if "flag.txt" in cmd or cmd in {"flag", "get_flag", "show flag", "read flag"}:
                    print("[+] FLAG FOUND FROM FLAG COMMAND")
                    return
                print("[!] Flag-looking text found in non-flag output; continuing because documents contain decoys.")
        except Exception as e:
            print(f"[!] stopped after {cmd!r}: {e}")
            break

    print("\n[*] Interactive mode. Try manual commands; Ctrl+C to quit.")
    while True:
        cmd = input("sugar> ").strip()
        if not cmd:
            continue
        send_frame(s, key, cmd)
        print(recv_frame(s, key).decode("utf-8", errors="replace"))


def main():
    ap = argparse.ArgumentParser(description="Solver for KubSTU Cipher Сахар")
    ap.add_argument("pcap", help="path to sugar_traffic.pcap")
    ap.add_argument("-w", "--wordlist", default=None, help="wordlist, e.g. /usr/share/wordlists/rockyou.txt or .gz; if omitted, common rockyou locations are tried")
    ap.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("-p", "--passphrase", help="known passphrase; skip cracking")
    ap.add_argument("--live", action="store_true", help="connect to live server after cracking")
    ap.add_argument("--download-rockyou", action="store_true", help="download rockyou.txt.gz automatically if no local wordlist exists")
    ap.add_argument("--host", default="62.113.108.12")
    ap.add_argument("--port", type=int, default=31337)
    args = ap.parse_args()

    packets = read_pcap_tcp_payloads(args.pcap)
    streams = build_streams(packets, 31337)
    score, client_port, salt, cframes, sframes = find_real_session(streams)

    print(f"[+] AES backend: {_AES_BACKEND}")
    print(f"[+] Real encrypted TCP stream: client port {client_port}")
    print(f"[+] Salt: {salt.decode(errors='replace')}")
    print(f"[+] Client frames: {len(cframes)}")
    print(f"[+] Server frames: {len(sframes)}")

    if args.passphrase:
        hit = check_passphrase(args.passphrase, salt, [cframes[0], sframes[0]])
        if hit:
            kdf_name, key, _pts = hit
            print(f"[+] Passphrase verified: {args.passphrase!r}")
            print(f"[+] KDF: {kdf_name}")
        else:
            print("[!] Given passphrase did not decrypt captured traffic with tested KDFs.")
            print("[!] Falling back to header KDF: sha256(passphrase || salt-ascii)")
            kdf_name = "sha256(passphrase || salt-ascii)"
            key = hashlib.sha256(args.passphrase.encode() + salt).digest()
    else:
        passphrase, kdf_name, key = crack_passphrase(salt, cframes, sframes, args.wordlist, args.jobs, args.download_rockyou)

        if not passphrase:
            print("[-] Could not crack with built-ins/current wordlist.")
            print("[*] Use rockyou or another CTF password list.")
            print("[*] Direct download method:")
            print("    python3 solve_sugar_v3.py 'sugar_traffic.pcap' --download-rockyou --live")
            print("[*] Manual download method:")
            print("    curl -L -o rockyou.txt.gz https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz")
            print("    python3 solve_sugar_v3.py 'sugar_traffic.pcap' -w ./rockyou.txt.gz --live")
            return

        args.passphrase = passphrase
        print(f"[+] PASSPHRASE FOUND: {passphrase!r}")
        print(f"[+] KDF: {kdf_name}")

    decrypt_session(key, cframes, sframes)

    if args.live:
        live_client(args.host, args.port, args.passphrase, kdf_name, fallback_salt=salt)


if __name__ == "__main__":
    main()
