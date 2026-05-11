import hashlib
import socket
import ssl
import sys
from dataclasses import dataclass

HOST = "chal-1024-hash-based-537f0a1af597.plfanzen.garden"
PORT = 443

TAU = 11
K = 16
BITS = 256
BLEN = BITS // 8
T = 1 << TAU

# Found offline. Public/deterministic because vi = f(SHA256(b"MESG" + msg)).
TARGET = b"gimme flag pls|6892940"
SIGN_MESSAGES = [
    b"sign|1150070",
    b"sign|2085463",
    b"sign|19770698",
]


def _make_hash(prefix: bytes):
    prefixed = hashlib.sha256(prefix)

    def h(m: bytes) -> bytes:
        x = prefixed.copy()
        x.update(m)
        return x.digest()

    return h


SECRET_KEY_HASH = _make_hash(b"SCRT")
COMBINE_HASH = _make_hash(b"COMB")
MESSAGE_HASH = _make_hash(b"MESG")


def generate_vi(message: bytes) -> set[int]:
    m = int.from_bytes(MESSAGE_HASH(message), "little")
    vi = set()
    for _ in range(K):
        vi.add(m % T)
        m //= T
    return vi


class Tube:
    """Small buffered socket wrapper. Important: recv_until preserves bytes after marker."""

    def __init__(self, sock: socket.socket, debug: bool = False):
        self.sock = sock
        self.buf = b""
        self.debug = debug

    def recv_some(self) -> bytes:
        chunk = self.sock.recv(4096)
        if not chunk:
            raise EOFError(f"connection closed; buffered={self.buf!r}")
        if self.debug:
            sys.stderr.write(chunk.decode(errors="replace"))
            sys.stderr.flush()
        self.buf += chunk
        return chunk

    def recv_until(self, marker: bytes, timeout_note: str = "") -> bytes:
        while marker not in self.buf:
            self.recv_some()
        pos = self.buf.index(marker) + len(marker)
        out = self.buf[:pos]
        self.buf = self.buf[pos:]
        return out

    def readline(self) -> bytes:
        while b"\n" not in self.buf:
            self.recv_some()
        pos = self.buf.index(b"\n") + 1
        out = self.buf[:pos]
        self.buf = self.buf[pos:]
        return out

    def sendline(self, line: bytes) -> None:
        if self.debug:
            sys.stderr.write(f"\n>>> {line!r}\n")
            sys.stderr.flush()
        self.sock.sendall(line + b"\n")

    def drain(self, timeout: float = 3.0) -> bytes:
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        out = self.buf
        self.buf = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            out += chunk
        self.sock.settimeout(old)
        return out


def read_signature(t: Tube) -> bytes:
    # We arrive just after "Here is your signature:". The next meaningful line is Length.
    t.recv_until(b"Length: ")
    length_line = t.readline()
    length = int(length_line.strip())

    sig = b""
    while len(sig) < length:
        line = t.readline().strip()
        if not line:
            continue
        try:
            sig += bytes.fromhex(line.decode())
        except ValueError as exc:
            raise ValueError(f"non-hex signature line while reading sig: {line!r}") from exc
    return sig[:length]


def parse_signature(message: bytes, sig: bytes):
    vi = generate_vi(message)
    chunks = [sig[i:i + BLEN] for i in range(0, len(sig), BLEN)]

    known_sk = {}
    known_hash = {}

    # First chunks are raw secret leaves for sorted vi.
    for v in sorted(vi):
        s = chunks.pop(0)
        known_sk[v] = s
        known_hash[(0, v)] = SECRET_KEY_HASH(s)

    # Remaining chunks are Merkle proof nodes in challenge order.
    known = set(vi)
    level = 0
    while True:
        needed = {v + 1 - (v % 2) * 2 for v in known} - known

        if not needed:
            idx = max(known) + 1
            for i, h in enumerate(chunks):
                known_hash[(level, idx + i)] = h
            chunks = []
            break

        for v in sorted(needed):
            known_hash[(level, v)] = chunks.pop(0)

        parents = {v // 2 for v in known}
        for p in parents:
            a = known_hash.get((level, 2 * p))
            b = known_hash.get((level, 2 * p + 1))
            if a is not None and b is not None:
                known_hash[(level + 1, p)] = COMBINE_HASH(a + b)

        known = parents
        level += 1

    # Close known nodes upward wherever both children are known.
    changed = True
    while changed:
        changed = False
        for level in range(TAU):
            for ll, idx in list(known_hash.keys()):
                if ll != level or idx % 2 != 0:
                    continue
                right = (level, idx + 1)
                parent = (level + 1, idx // 2)
                if right in known_hash and parent not in known_hash:
                    known_hash[parent] = COMBINE_HASH(known_hash[(level, idx)] + known_hash[right])
                    changed = True

    return known_sk, known_hash


def build_forged_signature(target: bytes, all_sk: dict, all_hash: dict) -> bytes:
    vi = generate_vi(target)

    missing = sorted(vi - set(all_sk))
    if missing:
        raise RuntimeError(f"missing target leaf secrets: {missing}")

    proof = b""
    for v in sorted(vi):
        proof += all_sk[v]

    known = set(vi)
    level = 0
    while True:
        needed = {v + 1 - (v % 2) * 2 for v in known} - known

        if not needed:
            idx = max(known) + 1
            width = T >> level
            for v in range(idx, width):
                key = (level, v)
                if key not in all_hash:
                    raise RuntimeError(f"missing final tail hash node level={level} index={v}")
                proof += all_hash[key]
            break

        for v in sorted(needed):
            key = (level, v)
            if key not in all_hash:
                raise RuntimeError(f"missing auth-path hash node level={level} index={v}")
            proof += all_hash[key]

        known = {v // 2 for v in known}
        level += 1

    return proof


def sign(t: Tube, message: bytes) -> bytes:
    t.recv_until(b"> ")
    t.sendline(b"1")
    t.recv_until(b"message > ")
    t.sendline(message.hex().encode())
    t.recv_until(b"Here is your signature:")
    sig = read_signature(t)
    print(f"[+] signed {message!r}, len={len(sig)}, vi={sorted(generate_vi(message))}")
    return sig


def get_flag(t: Tube, target: bytes, forged: bytes) -> bytes:
    t.recv_until(b"> ")
    t.sendline(b"2")
    t.recv_until(b"message > ")
    t.sendline(target.hex().encode())
    t.recv_until(b"signature length > ")
    t.sendline(str(len(forged)).encode())

    # Server input() has a 4096-byte line limit, so use chunks safely below that.
    for i in range(0, len(forged), 64):
        t.sendline(forged[i:i + 64].hex().encode())

    return t.drain(timeout=5.0)


def main() -> None:
    print(f"[*] target = {TARGET!r}")
    print(f"[*] target vi = {sorted(generate_vi(TARGET))}")

    debug = "--debug" in sys.argv

    ctx = ssl.create_default_context()
    raw = socket.create_connection((HOST, PORT), timeout=30)
    raw.settimeout(30)
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    sock.settimeout(30)
    t = Tube(sock, debug=debug)

    all_sk = {}
    all_hash = {}

    for message in SIGN_MESSAGES:
        sig = sign(t, message)
        sk_part, hash_part = parse_signature(message, sig)
        all_sk.update(sk_part)
        all_hash.update(hash_part)

    missing = sorted(generate_vi(TARGET) - set(all_sk))
    print(f"[+] missing target leaves after 3 signatures: {missing}")

    forged = build_forged_signature(TARGET, all_sk, all_hash)
    print(f"[+] forged signature length = {len(forged)}")

    out = get_flag(t, TARGET, forged)
    print(out.decode(errors="replace"))


if __name__ == "__main__":
    main()
