# qss - b01lers CTF 2026 Writeup

**Description:**  "quantum secret sharing is the way of the future!"

We are given a remote challenge at `qss.opus4-7.b01le.rs 8443` and a Python source file implementing the protocol.

---

## 1. TL;DR

This challenge simulates a quantum secret sharing (QSS) protocol. Instead of breaking a cipher, we act as an attacker trying to balance:

- low disturbance (QBER)
- high information gain

By designing a custom 3-qubit unitary and adapting our measurement strategy based on the revealed `public_set`, we can satisfy all constraints and recover the flag.

Final flag:
> bctf{phy51c5_1s_l1k3_s3x}

---

## 2. What Data/File We Have & What is Special

We are provided with:

- a Python server (challenge.py)
- a remote interactive service

There is no ciphertext or classical encryption. The challenge is entirely protocol-based.

---

### Interactive Flow
```
Each round (96 total):

--- round i ---
round_type: info/test

pre_public_announce_json>   (player sends basis + outcome)

public_set: S0 or S1
public_alice_basis: z/x

(info rounds only)
measurement_plan_json>      (player sends measurement plan)
measurement_outcomes: ...
secret_guess_bit>           (player sends guess)
```
---

### What is special

- The protocol simulates a quantum system with 3 qubits
- We must choose:
  - an ancilla state
  - a 3-qubit unitary
- The server evaluates us using:
  - QBER (error rate)
  - mutual information
  - theoretical optimal bound

This is not a classical crypto problem — it is an interactive optimization problem.

---

## 3. Problem Analysis (In Details)

Goal:
qber <= 0.32
mutual_info >= 0.5
raw_info_accuracy >= 0.6

The challenge enforces a tradeoff:
information gain vs disturbance.

---

## 4. Initial Guesses / First Try

- Random strategy → fails
- Identity unitary → low information
- Fixed measurement → fails constraints

Conclusion: need adaptive strategy.

---

## 5. Exploitation Walkthrough / Flag Recovery

Strategy:

Announcement:
- info rounds → x
- test rounds → mostly z, occasional x

Measurement:

S0:
measure b:x, c:x
guess = b XOR c

S1:
measure b:z, c:x
guess = 1 if b == c else 0

Result:

kept_info_accuracy ≈ 0.96
qber ≈ 0.20
raw_info_accuracy ≈ 0.73

All constraints satisfied.

---

## 6. What We Learned

- This is protocol analysis, not classical crypto
- Interaction order matters
- Optimization beats exact recovery
