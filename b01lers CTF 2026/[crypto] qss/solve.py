#!/usr/bin/env python3
import json
import math
import re
from pwn import remote
import numpy as np

HOST = "qss.opus4-7.b01le.rs"
PORT = 8443

# Best-performing schedule I found:
TEST_X_EVERY = 4

# Coefficients for the attack isometry.
# These give high kept-round accuracy while keeping the observed QBER
# inside the acceptance window often enough to win after a few retries.
A, B, C, D = 0.8, 0.6, 0.4, 0.4


def normalize(v):
    v = np.array(v, dtype=np.complex128)
    n = np.linalg.norm(v)
    if n == 0:
        raise ValueError("zero vector")
    return v / n


def ket(a, b, c):
    v = np.zeros(8, dtype=np.complex128)
    v[(a << 2) | (b << 1) | c] = 1.0
    return v


def gram_schmidt_extend(initial_cols, dim=8):
    basis = []
    for v in initial_cols:
        w = np.array(v, dtype=np.complex128)
        for b in basis:
            w -= np.vdot(b, w) * b
        n = np.linalg.norm(w)
        if n > 1e-12:
            basis.append(w / n)

    for i in range(dim):
        e = np.zeros(dim, dtype=np.complex128)
        e[i] = 1.0
        w = e.copy()
        for b in basis:
            w -= np.vdot(b, w) * b
        n = np.linalg.norm(w)
        if n > 1e-12:
            basis.append(w / n)
        if len(basis) == dim:
            break

    if len(basis) != dim:
        raise RuntimeError("failed to extend basis")
    return np.column_stack(basis)


def build_unitary():
    # Input logical basis used by the challenge:
    # v0 = |phi->
    # v1 = |psi+>
    phi_minus = np.array([1, 0, 0, -1], dtype=np.complex128) / math.sqrt(2)
    psi_plus = np.array([0, 1, 1, 0], dtype=np.complex128) / math.sqrt(2)
    anc0 = np.array([1, 0], dtype=np.complex128)

    v0 = np.kron(phi_minus, anc0)
    v1 = np.kron(psi_plus, anc0)

    # Output pair on the 3-qubit space (abc ordering).
    w0 = (
        A * ket(0, 0, 0)
        + B * ket(0, 1, 1)
        + C * ket(1, 0, 1)
        + D * ket(1, 1, 0)
    )
    w1 = (
        A * ket(1, 0, 0)
        - B * ket(1, 1, 1)
        + C * ket(0, 0, 1)
        - D * ket(0, 1, 0)
    )
    w0 = normalize(w0)
    w1 = normalize(w1)

    V = gram_schmidt_extend([normalize(v0), normalize(v1)], dim=8)
    W = gram_schmidt_extend([w0, w1], dim=8)
    U = W @ V.conj().T

    # Emit JSON-compatible scalars/strings.
    out = []
    for row in U:
        rr = []
        for x in row:
            re = 0.0 if abs(x.real) < 1e-12 else float(x.real)
            im = 0.0 if abs(x.imag) < 1e-12 else float(x.imag)
            if im == 0.0:
                rr.append(re)
            elif re == 0.0:
                rr.append(f"{im}j")
            else:
                sign = "+" if im >= 0 else ""
                rr.append(f"{re}{sign}{im}j")
        out.append(rr)
    return out


def recvline_text(io):
    line = io.recvline(timeout=15)
    if not line:
        raise EOFError("connection closed")
    return line.decode(errors="replace").rstrip("\n")


def run_once():
    io = remote(HOST, PORT, ssl=True)

    ancilla = [1, 0]
    unitary = build_unitary()

    round_type = None
    public_set = None
    test_seen = 0
    current_basis = None
    pending_guess = None

    while True:
        try:
            line = recvline_text(io)
        except EOFError:
            break

        print(line)

        if "ancilla_statevector_json>" in line:
            io.sendline(json.dumps(ancilla).encode())

        elif "unitary_8x8_json>" in line:
            io.sendline(json.dumps(unitary).encode())

        elif line.startswith("round_type:"):
            round_type = line.split(":", 1)[1].strip().lower()
            public_set = None
            current_basis = None
            pending_guess = None

        elif "pre_public_announce_json>" in line:
            if round_type == "info":
                # Use x on info rounds to keep balance easy.
                basis = "x"
            else:
                # Use x on every 4th test round, z otherwise.
                test_seen += 1
                basis = "x" if (test_seen % TEST_X_EVERY == 0) else "z"

            # Best constants for this attack family:
            # z -> 0, x -> 1
            outcome = 1 if basis == "x" else 0
            current_basis = basis
            io.sendline(json.dumps({"basis": basis, "outcome": outcome}).encode())

        elif line.startswith("public_set:"):
            public_set = 0 if "S0" in line else 1

        elif "measurement_plan_json>" in line:
            if public_set == 0:
                # Best on S0: measure b:x, c:x; guess b xor c
                plan = [["b", "x"], ["c", "x"]]
            else:
                # Best on S1: measure b:z, c:x; guess 1 iff equal
                plan = [["b", "z"], ["c", "x"]]
            io.sendline(json.dumps(plan).encode())

        elif line.startswith("measurement_outcomes:"):
            # Examples:
            # measurement_outcomes: b:x=0 c:x=1
            # measurement_outcomes: b:z=1 c:x=1
            parts = line.split()[1:]
            vals = {}
            for tok in parts:
                left, right = tok.split("=")
                vals[left] = int(right)

            if public_set == 0:
                b = vals["b:x"]
                c = vals["c:x"]
                guess = b ^ c
            else:
                b = vals["b:z"]
                c = vals["c:x"]
                guess = 1 if b == c else 0

            pending_guess = guess

        elif "secret_guess_bit>" in line:
            if pending_guess is None:
                raise RuntimeError("server asked for secret guess unexpectedly")
            io.sendline(str(pending_guess).encode())
            pending_guess = None

        elif line.startswith("bctf{"):
            print("\nFLAG:", line)
            io.close()
            return True

        elif line.startswith("ABORT:") or line.startswith("No flag yet:"):
            # Let the score block finish; server usually closes after that.
            pass

    io.close()
    return False


def main():
    attempt = 1
    while True:
        print(f"\n[+] attempt {attempt}")
        try:
            if run_once():
                break
        except Exception as e:
            print(f"[-] run failed: {e}")
        attempt += 1


if __name__ == "__main__":
    main()


# Output:
# .......

# === score ===
# rounds=96
# info_rounds=28
# info_total_rounds=62
# correct=28
# kept_info_accuracy=1.0000
# info_error=0.0000
# raw_info_accuracy=0.7258
# qber_checked_by_basis=z:9 x:4
# qber_by_basis=z:0.2222 x:0.2500
# qber=0.2308
# max_qber=0.3200
# min_info_rounds=16
# min_mutual_info_bits=0.5000
# min_qber_checked=4
# min_qber_checked_per_basis=2
# max_frontier_abs_dev_bits=0.2500
# bctf{phy51c5_1s_l1k3_s3x}