# Entropy - Incognito 7.0 Writeup

## 1. TL;DR
The challenge exposed an interactive maze over `nc 34.131.216.230 1340`, but the real path information was not in the printed hexadecimal-looking text. Instead, the maze structure was encoded in ANSI terminal colors, with `><` as the start tile and `▓▓` as the goal. By capturing one board frame, parsing the ANSI color escapes, splitting tiles by brightness, and running BFS, we recovered the flag:

```text
IIITL{K4l31d05c0p3_M4z3_M4573r_9921_n0_3y35_fbea254d4834}
```

## 2. Provided Data and Interaction
We were given only a remote service:

```text
nc 34.131.216.230 1340
```

No downloadable files were provided. The challenge was entirely interactive through the terminal.

### Server Interaction
When connecting, the server displayed a status banner, a countdown warning, the movement controls, and then a full board. The controls shown by the server were:

```text
[CONTROLS] W: Up | S: Down | A: Left | D: Right | Q: Quit
```

The board was a `51 x 51` grid. Each cell was rendered as two visible characters, usually hexadecimal-looking values, with two special markers:

- `><` — player start
- `▓▓` — destination

A representative stripped preview looked like this:


![gameboard](gameboard(Screenshot).png)



### What Was Special
At first glance, the board contents suggested a text puzzle, because almost every tile looked like random hex. That was misleading. The important part was the ANSI formatting applied to each tile, especially the background colors. Raw capture showed escape sequences such as:

```text
\x1b[48;5;60m\x1b[30m03\x1b[0m
```

That detail mattered because the board used **xterm 256-color ANSI codes** like `48;5;N`, not truecolor escapes like `48;2;R;G;B`. Any parser that only handled truecolor would fail to extract usable color information.

### Player Output
The player only needed to send movement input:

- `w` for up
- `s` for down
- `a` for left
- `d` for right
- `q` for quit

In the final solve, we sent the full BFS-derived path as one line and received the success message and flag.

## 3. Problem Analysis
The challenge name, the visual noise, and the terminal rendering all suggested that the visible text was camouflage rather than signal. Since the board looked like a maze but the characters themselves did not form clear walls or paths, the most likely hidden structure was in the rendering layer.

Capturing the raw socket output confirmed this. The terminal stream contained ANSI escape sequences before every tile, which means the server was encoding board state through color. After stripping ANSI codes, the board lost almost all useful structure except the `><` and `▓▓` markers. That was a strong indicator that the walkable tiles were determined by color, not by the text content.

The next question was how to interpret the colors. The capture showed `48;5;N` sequences, which are 256-color background codes. So the solver had to:

1. Receive one full board frame after the controls banner.
2. Parse ANSI SGR sequences without losing formatting state.
3. Convert xterm 256-color values into RGB.
4. Compute each tile's brightness.
5. Infer which brightness class corresponded to walkable tiles.
6. Run graph search from `><` to `▓▓`.

Because the exact rule was not known in advance, the safest strategy was to test both possibilities:

- bright cells are walkable, or
- dark cells are walkable.

That turns the puzzle into a standard maze search once the terminal rendering has been translated into data.

## 4. Initial Guesses / First Try
The first manual guess was that the correct route might simply be the visually bright path leading to `▓▓`. That was a reasonable hypothesis because the terminal displayed strong bright/dark contrast, and the puzzle description hinted that the visual pattern mattered.

However, manual solving was unreliable for two reasons:

1. The board was large (`51 x 51`).
2. Plain pasted output loses the terminal colors, which are the actual signal.

The first automated attempt tried to parse ANSI colors, but it assumed truecolor escape sequences such as `38;2` and `48;2`. That failed with the equivalent of “no ANSI colors found,” even though the board was clearly colored.

To debug that, we captured raw bytes from the service and printed both a raw `repr(...)` preview and a stripped preview. That immediately exposed the real issue: the server was using `48;5;N` background colors instead of truecolor.

## 5. Exploitation Walkthrough / Flag Recovery
Once the format was understood, the solve path became straightforward.

### Step 1: Capture one board frame
We connected to the remote service and waited until the controls line appeared. After that, we collected exactly one `51 x 51` board frame.

### Step 2: Preserve ANSI formatting
Instead of treating each line as plain text, we tokenized the ANSI stream. For each tile, we kept both:

- the visible two-character string, and
- the current foreground/background color state.

### Step 3: Convert xterm colors to RGB
The board used xterm 256-color escapes, so the solver converted color IDs into RGB values. This made it possible to assign each tile a brightness value using a luminance formula.

### Step 4: Classify cells by brightness
For every non-special tile, we computed its luminance and split the board into two groups:

- brighter tiles
- darker tiles

Because the challenge rule was not explicit, the solver tried both interpretations.

### Step 5: Run BFS
We treated `><` as the source and `▓▓` as the destination, then ran BFS over:

1. bright tiles first
2. dark tiles if the first attempt failed

As soon as one class produced a valid path, the solver reconstructed the `wasd` route.

### Step 6: Send the route
The computed path was sent back to the service as a single line of movement commands. The server accepted the path and returned:

```text
[+] DATA EXTRACTION COMPLETE. FLAG: IIITL{K4l31d05c0p3_M4z3_M4573r_9921_n0_3y35_42ec7532681f}
```

## 6. What We Learned
1. **Rendered output can be the real challenge input.** If a service draws colored frames, copying plain terminal text may throw away the actual signal.
2. **Always inspect raw bytes when terminal behavior looks suspicious.** A short debug capture immediately revealed that the maze used ANSI background colors.
3. **Support the full ANSI color stack.** Assuming only truecolor caused the first parser to fail; this challenge used xterm 256-color escapes.
4. **Once the representation is decoded, standard algorithms are enough.** After translating the board into walkable and blocked cells, the challenge reduced to BFS on a grid.
