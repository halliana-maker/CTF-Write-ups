#!/usr/bin/env python3
import asyncio
import struct
import websockets

HOST = '178.105.199.41'
PORT = 20013
URL = f'ws://{HOST}:{PORT}/ws'

TAG = {
    'NAME': 0x01, 'SID': 0x02, 'MOTD': 0x03, 'ROOM': 0x04, 'DRAFT': 0x05,
    'TOKEN': 0x06, 'ROLE': 0x07, 'SCOPE': 0x08, 'MESSAGE': 0x09, 'FLAG': 0x0A,
    'EXPORT': 0x0B, 'DIALECT': 0x0C, 'BLOB': 0x0D, 'CAPSULE': 0x0E, 'CACHE': 0x0F,
}
OP = {
    'HELLO': 0x10, 'HELLO_ACK': 0x11, 'OPEN': 0x20, 'OPENED': 0x21, 'SEAL': 0x30,
    'SEALED': 0x31, 'RESUME': 0x40, 'RESUMED': 0x41, 'FLAGREQ': 0x50, 'FLAG': 0x51,
    'CAPSULE': 0x60, 'CAPPED': 0x61, 'ERROR': 0x7F,
}

PREFIX = b'CACHE::SIGNME::!'
BRIDGE = b'kind=cache&blob='
assert len(PREFIX) == 16
assert len(BRIDGE) == 16

def swap_nibbles(buf: bytes) -> bytes:
    return bytes((((b & 0x0f) << 4) | ((b & 0xf0) >> 4)) for b in buf)

def crc16_ccitt(buf: bytes) -> int:
    crc = 0xffff
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
    return crc

def encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            return bytes(out)

def decode_varint(buf: bytes, off: int):
    val = 0
    shift = 0
    pos = off
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7

def encode_fields(fields):
    out = bytearray()
    for tag, value in fields:
        out.append(tag)
        out += encode_varint(len(value))
        out += value
    return bytes(out)

def decode_fields(payload: bytes):
    out = {}
    off = 0
    while off < len(payload):
        tag = payload[off]
        off += 1
        ln, off = decode_varint(payload, off)
        out[tag] = payload[off:off + ln]
        off += ln
    return out

def xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def blocks16(buf: bytes):
    assert len(buf) % 16 == 0
    return [buf[i:i + 16] for i in range(0, len(buf), 16)]

def parse_pairs(msg: bytes):
    out = []
    for part in msg.decode().split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
        else:
            k, v = part, ''
        out.append((k, v))
    return out

def first(pairs, key, default=''):
    for k, v in pairs:
        if k == key:
            return v
    return default

def pad_resume(text: str) -> bytes:
    b = text.encode()
    b += b'A' * ((-len(b)) % 16)
    return b

def mk_resume(room: str, cache: str, role: str, scope: str, extra='') -> bytes:
    s = f'kind=resume&role={role}&scope={scope}&room={room}&cache={cache}'
    if extra:
        s += '&' + extra
    if 'pad=' not in s:
        s += '&pad=ops'
    return pad_resume(s)

class Client:
    def __init__(self):
        self.ws = None
        self.dialect = None
        self.next_xid = 1

    def wire_opcode(self, op):
        if self.dialect is None or op in (OP['HELLO'], OP['HELLO_ACK']):
            return op
        return op ^ self.dialect

    def real_opcode(self, op):
        if self.dialect is None or op in (OP['HELLO'], OP['HELLO_ACK']):
            return op
        return op ^ self.dialect

    def encode_frame(self, op, fields):
        xid = self.next_xid
        self.next_xid += 1
        payload = encode_fields(fields)
        head = bytes([self.wire_opcode(op)]) + struct.pack('<H', xid) + encode_varint(len(payload)) + payload
        crc = crc16_ccitt(head)
        return b'R1' + swap_nibbles(head + struct.pack('<H', crc))

    def decode_frame(self, data):
        raw = bytes(data)
        if raw[:2] != b'R1':
            raise RuntimeError('bad magic')
        body = swap_nibbles(raw[2:])
        pkt, got = body[:-2], struct.unpack('<H', body[-2:])[0]
        if crc16_ccitt(pkt) != got:
            raise RuntimeError('bad crc')
        op = self.real_opcode(pkt[0])
        xid = struct.unpack('<H', pkt[1:3])[0]
        ln, off = decode_varint(pkt, 3)
        payload = pkt[off:off + ln]
        return op, xid, decode_fields(payload)

    async def send(self, op, fields):
        await self.ws.send(self.encode_frame(op, fields))
        return self.decode_frame(await self.ws.recv())

async def expect(op, fields, want):
    if op == OP['ERROR']:
        raise RuntimeError(fields.get(TAG['MESSAGE'], b'').decode(errors='ignore'))
    if op != want:
        raise RuntimeError(f'unexpected op {op:#x}')
    return fields

async def sign_blob(c: Client, blob: bytes) -> bytes:
    op, _, fields = await c.send(OP['CAPSULE'], [(TAG['BLOB'], blob)])
    fields = await expect(op, fields, OP['CAPPED'])
    return fields[TAG['CAPSULE']]

async def bridge_state(c: Client) -> bytes:
    return (await sign_blob(c, BRIDGE))[-16:]

async def cbc_mac_via_blocks(c: Client, target: bytes) -> bytes:
    """Compute MAC(target) without ever submitting target itself."""
    state = await bridge_state(c)  # state after PREFIX || BRIDGE
    prev = b'\x00' * 16
    for blk in blocks16(target):
        q = BRIDGE + xor16(xor16(blk, prev), state)
        tag = (await sign_blob(c, q))[-16:]
        prev = tag
    return prev

async def forge_capsule(c: Client, target: bytes) -> bytes:
    return target + await cbc_mac_via_blocks(c, target)

async def resume_and_flag(c: Client, token: bytes, cap: bytes, desc: str):
    op, _, fields = await c.send(OP['RESUME'], [(TAG['TOKEN'], token), (TAG['CAPSULE'], cap)])
    if op == OP['ERROR']:
        print(f'        [-] resume failed: {fields.get(TAG["MESSAGE"], b"").decode(errors="ignore")}')
        return False
    role = fields.get(TAG['ROLE'], b'').decode(errors='ignore')
    scope = fields.get(TAG['SCOPE'], b'').decode(errors='ignore')
    room = fields.get(TAG['ROOM'], b'').decode(errors='ignore')
    print(f'        [+] resumed as role={role} scope={scope} room={room}')
    op, _, fields = await c.send(OP['FLAGREQ'], [])
    if op == OP['FLAG']:
        print(fields[TAG['FLAG']].decode(errors='ignore'))
        return True
    msg = fields.get(TAG['MESSAGE'], b'').decode(errors='ignore') if op == OP['ERROR'] else f'unexpected op {op:#x}'
    print(f'        [-] flag failed: {msg}')
    return False

async def try_msg(c: Client, token: bytes, desc: str, msg: bytes):
    print(f'    [*] trying {desc}: {msg.decode(errors="replace")}')
    try:
        cap = await forge_capsule(c, msg)
    except Exception as e:
        print(f'        [-] forge failed: {e}')
        return False
    return await resume_and_flag(c, token, cap, desc)

async def one_room(c: Client, room_name: str):
    print(f'[*] opening room: {room_name}')
    op, _, fields = await c.send(OP['OPEN'], [(TAG['ROOM'], room_name.encode())])
    fields = await expect(op, fields, OP['OPENED'])
    draft = fields[TAG['DRAFT']]

    op, _, fields = await c.send(OP['SEAL'], [(TAG['DRAFT'], draft)])
    fields = await expect(op, fields, OP['SEALED'])
    token = fields[TAG['TOKEN']]
    legit = fields[TAG['CAPSULE']][:-16]
    pairs = parse_pairs(legit)
    room = first(pairs, 'room')
    cache = first(pairs, 'cache')
    print(f'    [i] legit room={room} cache={cache} msg={legit.decode()}')

    candidates = [
        ('admin+flag', mk_resume(room, cache, 'admin', 'flag')),
        ('admin+chat', mk_resume(room, cache, 'admin', 'chat')),
        ('admin+admin', mk_resume(room, cache, 'admin', 'admin')),
        ('admin+ops', mk_resume(room, cache, 'admin', 'ops')),
        ('user+flag', mk_resume(room, cache, 'user', 'flag')),
        ('ops+flag', mk_resume(room, cache, 'ops', 'flag')),
        ('root+flag', mk_resume(room, cache, 'root', 'flag')),
        ('dup-role-scope', mk_resume(room, cache, 'user', 'chat', 'role=admin&scope=flag&x=AA')),
        ('dup-scope-role', mk_resume(room, cache, 'user', 'chat', 'scope=flag&role=admin&x=AA')),
    ]
    seen = set()
    for desc, msg in candidates:
        if msg in seen:
            continue
        seen.add(msg)
        if await try_msg(c, token, desc, msg):
            return True
    return False

async def main():
    c = Client()
    async with websockets.connect(URL, open_timeout=10, max_size=1 << 20) as ws:
        c.ws = ws
        op, _, fields = await c.send(OP['HELLO'], [(TAG['NAME'], b'guest')])
        fields = await expect(op, fields, OP['HELLO_ACK'])
        c.dialect = fields.get(TAG['DIALECT'], b'\x00')[0]

        for room in ['FlagRoom', 'FLAGROOM', 'fLagroom', 'flAgroom', 'flagroom']:
            if await one_room(c, room):
                return
        print('[!] no candidate worked')

if __name__ == '__main__':
    asyncio.run(main())
