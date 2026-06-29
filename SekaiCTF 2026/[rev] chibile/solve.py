#!/usr/bin/env python3
"""
SEKAI CTF 2026 - Chibile solver

Reimplements the hidden quiz gate, UM/KM attestations, CBL2 transport,
and Phase-1 secret decryption.  A successful run prints the SEKAI{...} flag.

Dependency (one of):
    python3 -m pip install cryptography
    python3 -m pip install pycryptodome
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any

HOST = "8875cf0267a7c5510933aebf9de827b9.chals.sekai.team"
PORT = 1337
CLIENT_BUILD = "CHIBILE-R3-20260615"
SOLVER_VERSION = "2026-06-28-v4-save-png"

# Hidden 73-byte secret-room answer recovered from the quiz decoder.
HIDDEN_ANSWER = (
    b"CONGRATS, YOU FOUND SOMETHING! TWEET AT @0XN*** "
    b"AND MENTION THIS MESSAGE."
)
QUIZ_SEED = bytes.fromhex(
    "81928d9335c6452d2588b681d6ef9807"
    "5a79b38684840fac5198c40e4842c0de"
)
SECRET_ROOM_DIGEST = bytes.fromhex(
    "78a39767f1c301728aa1f169ffe9b486"
    "3207805ad6f2396c606c86bc32c1d31e"
)

# Result of the unpacked DLL's secret-room gate for SECRET_ROOM_DIGEST.
UM_GATE = bytes.fromhex(
    "bb41607fc79bd502145ec8cd92ce5e20"
    "5e13e8fc9f16da18f2e441c81c0b5789"
)
KM_GATE_KEY = b"CHIBILE-GATE-V1"
KM_ATTEST_CONST = bytes.fromhex(
    "4e912cd763ba18ef057ac3398651fd20"
    "a8146dbf429ed037cb60851cf32974ae"
)

# Baked half-keys recovered from eac_nocrt.dll and eac_shield.sys.
# UM is at unpacked DLL RVA 0x6030; KM is at driver RVA 0x1420.
BK_UM = bytes.fromhex(
    "9a47d31eb8056cf283217eca4d901b66"
    "5fe80ab377c429d13ca6528b14ff9d70"
)
BK_KM = bytes.fromhex(
    "4e912cd763ba18ef057ac3398651fd20"
    "a8146dbf429ed037cb60851cf32974ae"
)

RSA_E = 65537
RSA_N = int(
    "d460ce918e9898c8dab3fb406bc6c7065ea18a6d9adc36a7ca9aa0f0fc93dc02"
    "bf0ba54237c51df0fb5aa5bb1c9d50e955536a906578f5c58f4561c484fbcf63"
    "23eb1acb057072a37f89d81acbd03ae4c7ed3195feedcb17006c4350c2eed2890"
    "790467e42d0b98b263a901e741819e39e445fc25a19e0be60df69ff5c3426bfd"
    "aa2476aa7be84d5745b02e7d451a09fefcf8e73b79ba1255b79202cf45a8acff"
    "d6eef59d500fdd108125d8b0164925d8c2658fb9f334502ec50f69f85345b3df"
    "aadb6a27263550a657a38543171958ba2b8176add7331f7c6ba07d019ecc7b0c0"
    "9d0c963e6f61b0323ef7c979d0a5cbb3fac555f9b6fac9da7b2bd4e3b84bbb",
    16,
)

ALPHABET = set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
FLAG_RE = re.compile(rb"SEKAI\{[^\r\n\x00]+\}")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def attest(nonce: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    um = hmac256(UM_GATE, b"UM-ATTEST" + nonce)
    km_gate = hmac256(KM_GATE_KEY, um + KM_ATTEST_CONST)
    km = hmac256(km_gate, b"KM-ATTEST" + nonce)
    return um, km


def mask_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """CBL2 stream mask. The operation is its own inverse."""
    if len(key) != 32 or len(nonce) != 16:
        raise ValueError("bad mask key/nonce length")
    out = bytearray(data)
    for block, start in enumerate(range(0, len(out), 32)):
        ks = hmac256(key, nonce + struct.pack("<Q", block))
        end = min(start + 32, len(out))
        for i in range(start, end):
            out[i] ^= ks[i - start]
    return bytes(out)


class CryptoBackend:
    def __init__(self) -> None:
        self.kind = ""
        try:
            from cryptography.hazmat.primitives import hashes, padding  # type: ignore
            from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa  # type: ignore
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore

            self.hashes = hashes
            self.padding = padding
            self.apad = apad
            self.rsa = rsa
            self.Cipher = Cipher
            self.algorithms = algorithms
            self.modes = modes
            self.kind = "cryptography"
            return
        except ImportError:
            pass

        try:
            from Crypto.Cipher import AES, PKCS1_OAEP  # type: ignore
            from Crypto.Hash import SHA256  # type: ignore
            from Crypto.PublicKey import RSA  # type: ignore
            from Crypto.Util.Padding import pad, unpad  # type: ignore

            self.AES = AES
            self.PKCS1_OAEP = PKCS1_OAEP
            self.SHA256 = SHA256
            self.RSA = RSA
            self.pad = pad
            self.unpad = unpad
            self.kind = "pycryptodome"
            return
        except ImportError as exc:
            raise RuntimeError(
                "missing crypto backend; install 'cryptography' or 'pycryptodome'"
            ) from exc

    def rsa_oaep_encrypt(self, message: bytes) -> bytes:
        if self.kind == "cryptography":
            pub = self.rsa.RSAPublicNumbers(RSA_E, RSA_N).public_key()
            return pub.encrypt(
                message,
                self.apad.OAEP(
                    mgf=self.apad.MGF1(algorithm=self.hashes.SHA256()),
                    algorithm=self.hashes.SHA256(),
                    label=None,
                ),
            )
        pub = self.RSA.construct((RSA_N, RSA_E))
        return self.PKCS1_OAEP.new(pub, hashAlgo=self.SHA256).encrypt(message)

    def aes_cbc_encrypt(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        if self.kind == "cryptography":
            padder = self.padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            enc = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv)).encryptor()
            return enc.update(padded) + enc.finalize()
        return self.AES.new(key, self.AES.MODE_CBC, iv).encrypt(self.pad(plaintext, 16))

    def aes_cbc_decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError("invalid AES-CBC ciphertext length")
        if self.kind == "cryptography":
            dec = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv)).decryptor()
            padded = dec.update(ciphertext) + dec.finalize()
            unpadder = self.padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        return self.unpad(self.AES.new(key, self.AES.MODE_CBC, iv).decrypt(ciphertext), 16)


@dataclass
class SessionKeys:
    enc: bytes
    mac: bytes
    mask: bytes
    nonce: bytes

    @classmethod
    def fresh(cls, nonce: bytes) -> "SessionKeys":
        return cls(os.urandom(32), os.urandom(32), os.urandom(32), nonce)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"connection closed with {remaining} bytes still expected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def cbl2_request(crypto: CryptoBackend, plaintext: bytes, keys: SessionKeys) -> bytes:
    masked = mask_xor(plaintext, keys.mask, keys.nonce)
    iv = os.urandom(16)
    ciphertext = crypto.aes_cbc_encrypt(keys.enc, iv, masked)
    package = keys.enc + keys.mac + keys.mask + keys.nonce
    if len(package) != 112:
        raise AssertionError("bad CBL2 key package")
    wrapped = crypto.rsa_oaep_encrypt(package)
    if len(wrapped) != 256:
        raise AssertionError(f"unexpected RSA ciphertext length: {len(wrapped)}")
    body = b"CBL2" + keys.nonce + wrapped + iv + ciphertext
    return body + hmac256(keys.mac, body)


def cbl2_response(crypto: CryptoBackend, packet: bytes, keys: SessionKeys) -> bytes:
    # CBR2 + IV(16) + at least one AES block + HMAC(32)
    if len(packet) < 4 + 16 + 16 + 32:
        raise ValueError(f"short CBR2 packet ({len(packet)} bytes)")
    if packet[:4] != b"CBR2":
        raise ValueError(f"bad response magic: {packet[:4]!r}")
    body, got_tag = packet[:-32], packet[-32:]
    want_tag = hmac256(keys.mac, body)
    if not hmac.compare_digest(got_tag, want_tag):
        raise ValueError("CBR2 HMAC verification failed")
    iv = packet[4:20]
    ciphertext = packet[20:-32]
    masked = crypto.aes_cbc_decrypt(keys.enc, iv, ciphertext)
    return mask_xor(masked, keys.mask, keys.nonce)


def transport(
    crypto: CryptoBackend,
    host: str,
    port: int,
    plaintext: bytes,
    nonce: bytes,
    timeout: float,
) -> bytes:
    keys = SessionKeys.fresh(nonce)
    request = cbl2_request(crypto, plaintext, keys)
    if len(request) > 0x10000:
        raise ValueError("request too large")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("<I", len(request)))
        sock.sendall(request)
        response_len = struct.unpack("<I", recv_exact(sock, 4))[0]
        if not (68 <= response_len <= 0xC00000):
            raise ValueError(f"invalid response length: {response_len}")
        response = recv_exact(sock, response_len)
    return cbl2_response(crypto, response, keys)


def compact_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def parse_prefixed_json(payload: bytes, prefix: bytes) -> dict[str, Any]:
    if not payload.startswith(prefix):
        raise ValueError(
            f"expected {prefix!r}; got plaintext prefix {payload[:64]!r}"
        )
    raw = payload[len(prefix) :].rstrip(b"\x00\r\n ")
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid JSON after {prefix!r}: {raw[:300]!r}") from exc
    if not isinstance(value, dict):
        raise ValueError("server JSON is not an object")
    return value


def decode_blob(value: Any, name: str) -> bytes:
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in value):
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string/byte array, got {type(value).__name__}")
    text = value.strip()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return bytes.fromhex(text)
    # Accept standard or URL-safe Base64, with omitted padding.
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder(padded.encode("ascii"))
            if data:
                return data
        except Exception:
            pass
    raise ValueError(f"cannot decode {name}: {value!r}")


def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def rotr8(x: int, n: int) -> int:
    return ((x >> n) | (x << (8 - n))) & 0xFF


def decrypt_secret(ciphertext: bytes, local_half: bytes, baked_key: bytes, tag: bytes, mode: str) -> str:
    if len(baked_key) != 32:
        raise ValueError("baked key must be 32 bytes")
    dk = hmac256(baked_key, local_half)
    out = bytearray(len(ciphertext))
    streams: dict[int, bytes] = {}
    for i, c in enumerate(ciphertext):
        block, j = divmod(i, 32)
        ks = streams.setdefault(block, hmac256(dk, tag + struct.pack("<I", block)))
        if mode == "um":
            out[i] = rotl8(c ^ ks[j], 3) ^ baked_key[j]
        elif mode == "km":
            out[i] = rotr8(c ^ dk[(i * 7) % 32], 3) ^ ks[j]
        else:
            raise ValueError(f"unknown mode: {mode}")
    try:
        secret = out.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"decrypted {mode.upper()} secret is not ASCII: {out.hex()}") from exc
    if len(secret) != 12 or any(ch not in ALPHABET for ch in secret):
        raise ValueError(
            f"decrypted {mode.upper()} value failed validation: {secret!r} ({out.hex()})"
        )
    return secret


def decrypt_phase1(obj: dict[str, Any]) -> tuple[str, str, str]:
    required = ("sid", "c_um", "lh_um", "c_km", "lh_km")
    missing = [x for x in required if x not in obj]
    if missing:
        raise KeyError(f"Phase-1 object is missing: {', '.join(missing)}")
    sid = str(obj["sid"])
    c_um = decode_blob(obj["c_um"], "c_um")
    lh_um = decode_blob(obj["lh_um"], "lh_um")
    c_km = decode_blob(obj["c_km"], "c_km")
    lh_km = decode_blob(obj["lh_km"], "lh_km")
    um = decrypt_secret(c_um, lh_um, BK_UM, b"UM-KS", "um")
    km = decrypt_secret(c_km, lh_km, BK_KM, b"KM-KS", "km")
    return sid, um, km


def inverse_encrypt_secret(secret: bytes, local_half: bytes, baked_key: bytes, tag: bytes, mode: str) -> bytes:
    """Used only by --self-test to verify both inverse formulas."""
    dk = hmac256(baked_key, local_half)
    out = bytearray(len(secret))
    streams: dict[int, bytes] = {}
    for i, s in enumerate(secret):
        block, j = divmod(i, 32)
        ks = streams.setdefault(block, hmac256(dk, tag + struct.pack("<I", block)))
        if mode == "um":
            out[i] = rotr8(s ^ baked_key[j], 3) ^ ks[j]
        else:
            out[i] = rotl8(s ^ ks[j], 3) ^ dk[(i * 7) % 32]
    return bytes(out)


def self_test(crypto: CryptoBackend) -> None:
    assert len(HIDDEN_ANSWER) == 73
    assert hmac256(QUIZ_SEED, b"secret-room") == SECRET_ROOM_DIGEST
    nonce = bytes(range(16))
    um, km = attest(nonce)
    assert um.hex() == "cabd2e1fb7e5bb8edaa37079c9878a91b94e38a84259e37a550382c0c84c7999"
    assert km.hex() == "536161a0b9484f321bda39341826343a94034a22a3f7cc65a326826a944cc15a"
    # Verify the recovered baked keys against a captured live Phase-1 response.
    captured = {
        "sid": "74e4464e83a6f3bc7e690988dab0c7be",
        "c_um": "614c5d0024a1cfd4991f703b",
        "lh_um": "1d4a019b003e9e0f5298297e828a39ddddfe2ff7033aed17f63a46809dab9532",
        "c_km": "ea3e6c5b96905f6e26a259df",
        "lh_km": "213b458120e1f5398375f258b9a206c1d2526678990ea3eb987c335ebbdfbed4",
    }
    _, cap_um, cap_km = decrypt_phase1(captured)
    assert cap_um == "RQEQM8XQCR7R"
    assert cap_km == "XCLXHLPPHFGU"

    # Second independent live capture: catches the stale 932a... UM key
    # that happened to be shipped in the first solver revision.
    captured2 = {
        "sid": "70334c10cd88d574410fda96a78a17e4",
        "c_um": "e554ee09a6d50fdf76a74a7c",
        "lh_um": "ea52166bf5dc07dd67d33b4f640b97101f5636e06664f38bbc7668249ba8be5b",
        "c_km": "29362fdf835cec7da0a1cae2",
        "lh_km": "e340f0f8f399ce1433b93dc4e1ad0a3bddebc17f6e31e013a95856c6d225e194",
    }
    _, cap2_um, cap2_km = decrypt_phase1(captured2)
    assert cap2_um == "EHF4LBFCSYVH"
    assert cap2_km == "JTR2UWMQYWQA"

    sample = b"CBM1" + b"x" * 77
    key = bytes(range(32))
    n = bytes(range(16))
    assert mask_xor(mask_xor(sample, key, n), key, n) == sample
    iv = bytes(range(16))
    ct = crypto.aes_cbc_encrypt(key, iv, sample)
    assert crypto.aes_cbc_decrypt(key, iv, ct) == sample
    assert len(crypto.rsa_oaep_encrypt(b"A" * 112)) == 256

    lh = bytes(range(32, 64))
    s_um = b"ABCDEFGH2345"
    s_km = b"JKLMNPQR6789"
    c_um = inverse_encrypt_secret(s_um, lh, BK_UM, b"UM-KS", "um")
    c_km = inverse_encrypt_secret(s_km, lh, BK_KM, b"KM-KS", "km")
    assert decrypt_secret(c_um, lh, BK_UM, b"UM-KS", "um") == s_um.decode()
    assert decrypt_secret(c_km, lh, BK_KM, b"KM-KS", "km") == s_km.decode()
    print(f"[+] self-test passed ({crypto.kind})")


def load_inner_json(arg: str) -> dict[str, Any]:
    if arg == "-":
        text = sys.stdin.read()
    elif os.path.isfile(arg):
        with open(arg, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = arg
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("offline Phase-1 JSON must be an object")
    return value


def run_live(args: argparse.Namespace, crypto: CryptoBackend) -> str:
    if args.verbose:
        print(f"[*] solver     = {SOLVER_VERSION}")
        print(f"[*] BK_UM      = {BK_UM.hex()}")
        print(f"[*] BK_KM      = {BK_KM.hex()}")
    nonce1 = os.urandom(16)
    um_attest, km_attest = attest(nonce1)
    phase1 = compact_json(
        {
            "phase": 1,
            "nonce": nonce1.hex(),
            "um_attest": um_attest.hex(),
            "km_attest": km_attest.hex(),
            "pid": os.getpid(),
            "ts": int(time.time()),
            "client_build": CLIENT_BUILD,
        }
    )
    if args.verbose:
        print(f"[*] host       = {args.host}:{args.port}")
        print(f"[*] nonce1     = {nonce1.hex()}")
        print(f"[*] um_attest  = {um_attest.hex()}")
        print(f"[*] km_attest  = {km_attest.hex()}")
        print(f"[*] phase1 JSON= {phase1.decode()}")
    print("[*] requesting Phase 1")
    plain1 = transport(crypto, args.host, args.port, phase1, nonce1, args.timeout)
    if args.verbose:
        print(f"[*] Phase-1 plaintext: {plain1!r}")
    inner = parse_prefixed_json(plain1, b"CBM1")
    print("[+] Phase-1 object:")
    print(json.dumps(inner, indent=2, sort_keys=True))
    sid, typed_um, typed_km = decrypt_phase1(inner)
    print(f"[+] SID      = {sid}")
    print(f"[+] typed_um = {typed_um}")
    print(f"[+] typed_km = {typed_km}")

    nonce2 = os.urandom(16)
    phase2 = compact_json(
        {
            "phase": 2,
            "nonce": nonce2.hex(),
            "sid": sid,
            "typed_um": typed_um,
            "typed_km": typed_km,
            "ts": int(time.time()),
            "client_build": CLIENT_BUILD,
        }
    )
    if args.verbose:
        print(f"[*] nonce2     = {nonce2.hex()}")
        print(f"[*] phase2 JSON= {phase2.decode()}")
    print("[*] submitting Phase 2")
    plain2 = transport(crypto, args.host, args.port, phase2, nonce2, args.timeout)
    if not plain2.startswith(b"CBF2"):
        raise ValueError(f"expected CBF2 response, got {plain2[:100]!r}")

    # The original GUI does not treat the CBF2 body as text. It passes it to
    # raylib's LoadImageFromMemory(".png", ...), so a successful response is
    # normally a PNG containing the flag. Never print arbitrary binary to a
    # terminal: compressed image bytes may contain escape/control sequences.
    result = plain2[4:]

    match = FLAG_RE.search(result)
    if match:
        flag = match.group().decode("ascii")
        print(f"[+] FLAG: {flag}")
        return flag

    png_sig = b"\x89PNG\r\n\x1a\n"
    if result.startswith(png_sig):
        output_path = os.path.abspath(args.output)
        with open(output_path, "wb") as f:
            f.write(result)
        width = height = None
        if len(result) >= 24 and result[12:16] == b"IHDR":
            width, height = struct.unpack(">II", result[16:24])
        dims = f" ({width}x{height})" if width is not None else ""
        print(f"[+] Received PNG flag image{dims}: {output_path}")
        print(f"[+] Open it with: explorer.exe {output_path!r}")
        return output_path

    # Keep any unexpected successful body for analysis, but only print a safe
    # escaped prefix rather than corrupting the terminal.
    output_path = os.path.abspath(args.output + ".bin")
    with open(output_path, "wb") as f:
        f.write(result)
    preview = result[:96].hex()
    raise ValueError(
        f"CBF2 body is not text/PNG; saved {len(result)} bytes to "
        f"{output_path}; hex prefix={preview}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve SEKAI CTF Chibile")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--output",
        default="chibile_flag.png",
        help="path used for the Phase-2 PNG (default: chibile_flag.png)",
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--inner-json",
        metavar="JSON_OR_FILE",
        help="offline: decrypt a captured {sid,c_um,lh_um,c_km,lh_km} object",
    )
    args = parser.parse_args()

    try:
        crypto = CryptoBackend()
        if args.self_test:
            self_test(crypto)
            if not args.inner_json:
                return 0
        if args.inner_json:
            obj = load_inner_json(args.inner_json)
            sid, um, km = decrypt_phase1(obj)
            print(f"[+] SID      = {sid}")
            print(f"[+] typed_um = {um}")
            print(f"[+] typed_km = {km}")
            return 0
        run_live(args, crypto)
        return 0
    except KeyboardInterrupt:
        print("\n[-] interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
