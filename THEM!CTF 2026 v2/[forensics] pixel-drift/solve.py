#!/usr/bin/env python3
import os
import socket
import struct
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else 'output.pcapng'
OUT_TXT = 'pixel_flag_render.txt'
OUT_PNG = 'pixel_flag_vertical_flip.png'


def iter_udp_pcapng(path):
    data = open(path, 'rb').read()
    off = 0
    idx = 0

    while off + 12 <= len(data):
        btype, blen = struct.unpack('<II', data[off:off + 8])
        if blen < 12 or off + blen > len(data):
            break

        body = data[off + 8:off + blen - 4]

        # Enhanced Packet Block
        if btype == 6 and len(body) >= 20:
            _iid, _tshi, _tslo, caplen, _origlen = struct.unpack('<IIIII', body[:20])
            frame = body[20:20 + caplen]

            # Ethernet + IPv4
            if len(frame) >= 42 and frame[12:14] == b'\x08\x00':
                ipoff = 14
                ihl = (frame[ipoff] & 0x0f) * 4

                # UDP
                if len(frame) >= ipoff + ihl + 8 and frame[ipoff + 9] == 17:
                    uoff = ipoff + ihl
                    sport, dport, ulen, _checksum = struct.unpack('!HHHH', frame[uoff:uoff + 8])
                    payload = frame[uoff + 8:uoff + ulen]
                    src = socket.inet_ntoa(frame[ipoff + 12:ipoff + 16])
                    dst = socket.inet_ntoa(frame[ipoff + 16:ipoff + 20])
                    yield idx, src, sport, dst, dport, payload

            idx += 1

        off += blen


def shift_left_stream(blob, shift):
    if shift == 0:
        return blob
    return bytes(
        (((blob[i] << shift) & 0xff) | (blob[i + 1] >> (8 - shift)))
        for i in range(len(blob) - 1)
    )


def good_pair(x1, y1, z1, x2, y2, z2):
    return (
        1000 < x1 < 2500 and 1000 < x2 < 2500 and
        1000 < y1 < 2000 and 1000 < y2 < 2000 and
        -200 < z1 < 300 and -200 < z2 < 300 and
        abs((z1 + z2) - 110.0) < 1e-2 and
        abs(((y1 + y2) / 2.0) - 1346.12) < 4.0
    )


def extract_points(path):
    points = []

    for pkt_idx, src, sport, dst, dport, payload in iter_udp_pcapng(path):
        # SA-MP/open.mp server-to-client traffic.
        if sport != 7777:
            continue

        # Query packets are protocol-identification noise, not the flag.
        if payload.startswith(b'SAMP'):
            continue

        shifted = shift_left_stream(payload, 3)

        # Records are 55 bytes, but packet-local alignment may vary.
        best_records = []
        for base in range(55):
            current = []
            for off in range(base, len(shifted) - 54, 55):
                record = shifted[off:off + 55]
                try:
                    x1, y1, z1 = struct.unpack('<fff', record[14:26])
                    x2, y2, z2 = struct.unpack('<fff', record[26:38])
                except struct.error:
                    continue

                if good_pair(x1, y1, z1, x2, y2, z2):
                    current.append(((x1 + x2) / 2.0, (y1 + y2) / 2.0))

            if len(current) > len(best_records):
                best_records = current

        if len(best_records) >= 2:
            points.extend(best_records)

    # Deduplicate near-identical game coordinates.
    return sorted(set((round(x, 3), round(y, 3)) for x, y in points))


def render(points, flip_y=True):
    minx = min(x for x, y in points)
    miny = min(y for x, y in points)

    normalized = set((round(x - minx), round(y - miny)) for x, y in points)
    width = max(x for x, y in normalized) + 1
    height = max(y for x, y in normalized) + 1

    if flip_y:
        pixels = set((x, height - 1 - y) for x, y in normalized)
    else:
        pixels = normalized

    lines = []
    for y in range(height):
        line = ''.join('█' if (x, y) in pixels else ' ' for x in range(width))
        lines.append(line.rstrip())

    return pixels, width, height, lines


def save_png(pixels, width, height, path):
    try:
        from PIL import Image
    except ImportError:
        print('[!] Pillow is not installed; skipping PNG output')
        return

    scale = 8
    margin = 2
    img = Image.new('RGB', ((width + 2 * margin) * scale, (height + 2 * margin) * scale), 'white')
    px = img.load()

    for x, y in pixels:
        for yy in range((y + margin) * scale, (y + margin + 1) * scale):
            for xx in range((x + margin) * scale, (x + margin + 1) * scale):
                px[xx, yy] = (0, 0, 0)

    img.save(path)
    print(f'[+] wrote {path}')


def main():
    points = extract_points(PCAP)
    print(f'[+] extracted {len(points)} unique pixel points')

    pixels, width, height, lines = render(points, flip_y=True)
    print(f'[+] canvas: {width} x {height}')
    print('\n'.join(lines))

    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'[+] wrote {OUT_TXT}')

    save_png(pixels, width, height, OUT_PNG)
    print('[+] flag: THEM?!CTF{SH3_IS_S0_PERF3FCT_BL4H_BLAH_BL4H}')   # As u can see in the image, it is easy to read, but I still included it in the program


if __name__ == '__main__':
    main()