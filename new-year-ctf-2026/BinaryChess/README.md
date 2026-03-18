# BinaryChess

*   **Event:** New Year CTF 2026
*   **Category:** Stegano (Chess PGN)
*   **Description:** *In this chess game, a smart guy hid a flag. Find it. Pay attention to the moves. 0 and 1 are significant.*

## TL;DR
The PGN is not meant to be “solved” as a chess puzzle; it is a data container.
For each position in the game, enumerate all legal moves; the played move’s **index** among those legal moves encodes a chunk of bits, and concatenating these chunks recovers the flag.
Decoding results: `grodno{wh@t_d0_u_me@n_st3g0_1n_ch3ss}`.

## Problem Analysis

### Why the hint points to bits
The statement “0 and 1 are significant” is a classic stego hint: there is likely a binary message embedded somewhere, not a normal chess strategy problem.
In chess, every turn is a *choice* among multiple legal moves; that “choice” can act like selecting one symbol from an alphabet, which naturally carries information.

### Key stego concept: “choice among legal moves”
A standard approach in PGN steganography is:

- At a given position, list all legal moves.
- Assign each legal move a binary value (e.g., by numbering them 0, 1, 2, …).
- The move actually played tells you which number (and therefore which bits) were chosen.

The GIAC paper illustrates exactly this idea: if there are 4 possible moves, you can encode 2 bits; if there are 8 possible moves, you can encode 3 bits, etc.
So the *more legal moves a position has*, the *more bits* can be embedded at that step.

### Early guesses (and how they were tested)
A beginner-friendly way to approach this kind of CTF is to start from the cheapest hypothesis and escalate:

- **Guess 1: 1 bit per move from SAN features**  
  Examples: “capture = 1 else 0”, “check = 1 else 0”, “destination square color parity”, etc.
  These often fail because you only get ~66 bits total here (66 plies), which is usually too small for a full `grodno{...}` flag.

- **Guess 2: use the legal-move set**  
  This is the “high-capacity” method: each move can encode multiple bits, because the player is choosing 1 move out of many.
  This aligns perfectly with the hint “pay attention to the moves” because the bits come from which move was selected.

## First try (what went wrong)

### The “ordering” trap (why sorting broke things)
Once you decide “legal-move index encodes bits”, the next question is: *in which order are legal moves numbered?*
The GIAC paper explicitly warns that if the sender and receiver use different “priorities” (i.e., different ordering of the legal move list), you decode the wrong bits.

A natural but dangerous move is to sort legal moves (by SAN or UCI) to “make it deterministic”. That sounds reasonable, but it only works if the encoder used the same sorting.
In this challenge, trying several sorted orderings still produced garbage and even caused “move not in the top \(2^k\) subset” issues, which strongly suggested the encoder did **not** use a custom sorted list.

### Important realization
Many challenge authors simply rely on the chess library’s native move enumeration order (whatever order `generate_legal_moves()` yields) because it is deterministic within the same library/version and requires no extra work.
So the correct strategy becomes: **do not reorder** the legal moves; treat the generator’s output order as the shared “dictionary”.

## Flag Recovery

### Correct method (step-by-step)
The successful decoding pipeline is:

1. **Parse the PGN** into a sequence of moves (main line).
2. Start from the standard initial chess position.
3. For each move in the PGN:
   - Generate the list of all legal moves for the current position.
   - Keep the move list in its original enumeration order (no sorting).
   - Find the index `idx` of the played move within that list.  
   - Convert `idx` to binary and append it to the output bitstream.
4. After processing all moves, group the bitstream into bytes and decode to ASCII to reveal the message/flag.

### How many bits per move?
If there are `n` legal moves, you can safely extract \(k=\lfloor\log_2(n)\rfloor\) bits from the chosen move index because \(2^k \le n\).
This matches the idea in PGN steganography writeups: more legal moves → larger “alphabet” → more bits embedded.

### Result
Using the method above, the decoded ASCII output is exactly:

`grodno{wh@t_d0_u_me@n_st3g0_1n_ch3ss}`

### Reference 
[1] https://www.giac.org/paper/gsec/4127/stenganography-chess-pgn-standard-format/106529    
[2] https://github.com/niklasf/python-chess