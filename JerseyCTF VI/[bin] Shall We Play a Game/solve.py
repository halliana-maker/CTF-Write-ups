#!/usr/bin/env python3
from pathlib import Path
import struct

BIN_PATH = Path("tictactoe")
PNG_PATH = Path("board.png")

def main():
    bin_data = BIN_PATH.read_bytes()
    png_data = PNG_PATH.read_bytes()

    sprt = bin_data.find(b"SPRT")
    if sprt == -1:
        raise SystemExit("SPRT magic not found in tictactoe")

    # Layout:
    #   4 bytes  magic: "SPRT"
    #   4 bytes  version
    #   4 bytes  unknown / count-like field
    #   4 bytes  reserved
    #   8 pairs  (offset, length) as little-endian u32
    #
    # The eight chunks are the hidden payload pieces.
    table_off = sprt + 16
    pairs = [
        struct.unpack_from("<II", bin_data, table_off + i * 8)
        for i in range(8)
    ]

    blob = b"".join(png_data[off:off + length] for off, length in pairs)

    # The payload strings are XOR-obfuscated with 0x80.
    dec = bytes(b ^ 0x80 for b in blob)

    start = dec.find(b"jctf{")
    if start == -1:
        raise SystemExit("flag marker not found after XOR decode")

    end = dec.find(b"}", start)
    if end == -1:
        raise SystemExit("flag terminator not found")

    flag = dec[start:end + 1].decode("ascii", errors="strict")
    print(flag)

if __name__ == "__main__":
    main()
