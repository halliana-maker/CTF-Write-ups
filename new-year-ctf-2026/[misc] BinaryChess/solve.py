import io, re, math
import chess, chess.pgn

def fix_pgn(pgn_text: str) -> str:
    header, moves = pgn_text.split("\n\n", 1)
    moves = moves.strip()
    if not re.match(r"^1\.\s", moves):
        moves = "1. " + moves
    return header + "\n\n" + moves + "\n"

pgn_text = open("output.pgn", "r", encoding="utf-8", errors="ignore").read()
game = chess.pgn.read_game(io.StringIO(fix_pgn(pgn_text)))  # PGN parsing [web:65]

board = chess.Board()
moves = list(game.mainline_moves())

bitbuf = ""          # store bits that are not yet a full byte
out = bytearray()

for i, mv in enumerate(moves):
    legal = list(board.generate_legal_moves())              # no sorting [web:37]
    legal_uci = [m.uci() for m in legal]

    idx = legal_uci.index(mv.uci())
    n = len(legal_uci)
    k = int(math.log2(n))

    # Important: on the last move, only take the bits needed to complete a byte.
    if i == len(moves) - 1:
        need = (8 - (len(bitbuf) % 8)) % 8
        if need != 0:
            k = min(k, need)

    bits = bin(idx)[2:].zfill(k)
    bitbuf += bits

    # flush full bytes
    while len(bitbuf) >= 8:
        out.append(int(bitbuf[:8], 2))
        bitbuf = bitbuf[8:]

    board.push(mv)

data = bytes(out)
print("len:", len(data))
print("hex:", data.hex())
print("ascii:", data.decode(errors="ignore"))
