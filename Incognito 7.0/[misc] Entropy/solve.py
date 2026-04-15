#!/usr/bin/env python3
from pwn import remote
import re
from collections import deque

HOST = '34.131.216.230'
PORT = 1340
N = 51
ANSI_RE = re.compile(rb'\x1b\[[0-9;?]*[A-Za-z]')
SGR_RE = re.compile(rb'\x1b\[([0-9;]*)m')

BASE16 = {
    0: (0, 0, 0), 1: (128, 0, 0), 2: (0, 128, 0), 3: (128, 128, 0),
    4: (0, 0, 128), 5: (128, 0, 128), 6: (0, 128, 128), 7: (192, 192, 192),
    8: (128, 128, 128), 9: (255, 0, 0), 10: (0, 255, 0), 11: (255, 255, 0),
    12: (0, 0, 255), 13: (255, 0, 255), 14: (0, 255, 255), 15: (255, 255, 255),
}


def ansi256_to_rgb(n: int):
    if 0 <= n <= 15:
        return BASE16[n]
    if 16 <= n <= 231:
        n -= 16
        r, g, b = n // 36, (n % 36) // 6, n % 6
        table = [0, 95, 135, 175, 215, 255]
        return table[r], table[g], table[b]
    if 232 <= n <= 255:
        v = 8 + 10 * (n - 232)
        return v, v, v
    return None


def utf8_len(b0: int) -> int:
    if b0 < 0x80:
        return 1
    if (b0 & 0xE0) == 0xC0:
        return 2
    if (b0 & 0xF0) == 0xE0:
        return 3
    if (b0 & 0xF8) == 0xF0:
        return 4
    return 1


def strip_ansi(bs: bytes) -> str:
    return ANSI_RE.sub(b'', bs).decode('utf-8', 'ignore')


def looks_like_board_line(bs: bytes) -> bool:
    s = strip_ansi(bs).rstrip('\r\n')
    return len(s) == 2 * N and ('><' in s or '▓▓' in s or re.fullmatch(r'[0-9A-F]{102}', s) is not None)


def recv_board(io):
    saw_controls = False
    lines = []
    while True:
        try:
            line = io.recvline(timeout=1)
        except EOFError:
            line = b''
        if not line:
            raise EOFError(f'connection closed; captured {len(lines)} board lines')
        plain = strip_ansi(line)
        if '[CONTROLS]' in plain:
            saw_controls = True
            lines = []
            continue
        if not saw_controls:
            continue
        if looks_like_board_line(line):
            lines.append(line)
            if len(lines) == N:
                return lines
        elif lines:
            lines = []


def parse_sgr(params: bytes, fg, bg):
    vals = [int(x) for x in params.split(b';') if x]
    i = 0
    while i < len(vals):
        v = vals[i]
        if v == 0:
            fg = bg = None
            i += 1
        elif 30 <= v <= 37:
            fg = BASE16[v - 30]
            i += 1
        elif 90 <= v <= 97:
            fg = BASE16[8 + (v - 90)]
            i += 1
        elif 40 <= v <= 47:
            bg = BASE16[v - 40]
            i += 1
        elif 100 <= v <= 107:
            bg = BASE16[8 + (v - 100)]
            i += 1
        elif v == 38 and i + 2 < len(vals) and vals[i + 1] == 5:
            fg = ansi256_to_rgb(vals[i + 2])
            i += 3
        elif v == 48 and i + 2 < len(vals) and vals[i + 1] == 5:
            bg = ansi256_to_rgb(vals[i + 2])
            i += 3
        elif v == 38 and i + 4 < len(vals) and vals[i + 1] == 2:
            fg = tuple(vals[i + 2:i + 5])
            i += 5
        elif v == 48 and i + 4 < len(vals) and vals[i + 1] == 2:
            bg = tuple(vals[i + 2:i + 5])
            i += 5
        else:
            i += 1
    return fg, bg


def tokenize_line(line: bytes):
    pos = 0
    fg = bg = None
    out = []
    while pos < len(line):
        m = SGR_RE.match(line, pos)
        if m:
            fg, bg = parse_sgr(m.group(1), fg, bg)
            pos = m.end()
            continue
        if line[pos:pos + 1] in b'\r\n':
            break
        n = utf8_len(line[pos])
        raw = line[pos:pos + n]
        try:
            ch = raw.decode('utf-8')
        except UnicodeDecodeError:
            ch = raw.decode('utf-8', 'ignore')
        out.append((ch, fg, bg))
        pos += n
    return out


def luminance(rgb):
    if rgb is None:
        return None
    r, g, b = rgb
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def parse_board(lines):
    grid = []
    start = goal = None
    lums = []
    for r, line in enumerate(lines):
        toks = tokenize_line(line)
        if len(toks) < 2 * N:
            raise RuntimeError(f'line {r}: tokenized {len(toks)} chars, need {2*N}')
        row = []
        for c in range(N):
            a = toks[2 * c]
            b = toks[2 * c + 1]
            txt = a[0] + b[0]
            rgb = a[2] or a[1] or b[2] or b[1]
            lum = luminance(rgb)
            row.append((txt, lum))
            if txt == '><':
                start = (r, c)
            elif txt == '▓▓':
                goal = (r, c)
            elif lum is not None:
                lums.append(lum)
        grid.append(row)
    if start is None or goal is None:
        raise RuntimeError(f'failed to find start/goal: start={start} goal={goal}')
    if not lums:
        raise RuntimeError('parsed zero colored cells')
    return grid, start, goal, lums


def bfs(grid, start, goal, ok):
    q = deque([start])
    prev = {start: None}
    dirs = [(1, 0, 's'), (-1, 0, 'w'), (0, 1, 'd'), (0, -1, 'a')]
    while q:
        r, c = q.popleft()
        if (r, c) == goal:
            path = []
            cur = goal
            while prev[cur] is not None:
                cur, mv = prev[cur]
                path.append(mv)
            return ''.join(reversed(path))
        for dr, dc, mv in dirs:
            nr, nc = r + dr, c + dc
            if not (0 <= nr < N and 0 <= nc < N):
                continue
            if (nr, nc) in prev:
                continue
            if (nr, nc) == goal or ok(grid[nr][nc]):
                prev[(nr, nc)] = ((r, c), mv)
                q.append((nr, nc))
    return None


def solve(grid, start, goal, lums):
    thr = (min(lums) + max(lums)) / 2.0
    preds = [
        lambda cell: cell[1] is not None and cell[1] >= thr,
        lambda cell: cell[1] is not None and cell[1] < thr,
    ]
    for pred in preds:
        path = bfs(grid, start, goal, pred)
        if path:
            return path
    raise RuntimeError('no path found in either brightness class')


def main():
    io = remote(HOST, PORT)
    try:
        lines = recv_board(io)
        grid, start, goal, lums = parse_board(lines)
        path = solve(grid, start, goal, lums)
        print(f'[+] start={start} goal={goal} path_len={len(path)}')
        io.sendline(path.encode())
        print(io.recvrepeat(2).decode('utf-8', 'ignore'))
    finally:
        io.close()


if __name__ == '__main__':
    main()