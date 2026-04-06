from sage.all import *
import asyncio
import base64
import json
import os
import sys
import hashlib
import ipaddress
from collections import defaultdict
from Crypto.Cipher import AES

PARAMS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'params.json')
PORT = 1337
MAX_QUERIES = 200
MAX_CONNECTIONS_PER_IP = 5
BANNER = "PORTOBELO v1.0"


def load_params():
    with open(PARAMS_FILE) as f:
        raw = json.load(f)

    p = int(raw["p"])
    primes = [int(x) for x in raw["primes"]]
    base_A = int(raw["base_curve_A"])
    secret_key = [int(x) for x in raw["secret_key"]]
    poisoned_index = int(raw["poisoned_index"])
    iso_challenge_A = int(raw["iso_challenge_A"])
    gr48_poly = [int(x) for x in raw["gr48_poly"]]
    gr48_gen = [int(x) for x in raw["gr48_generator"]]
    flag_ct = bytes.fromhex(raw["flag_ct"])
    flag_nonce = bytes.fromhex(raw["flag_nonce"])
    flag_tag = bytes.fromhex(raw["flag_tag"])

    return {
        "p": p,
        "primes": primes,
        "base_A": base_A,
        "secret_key": secret_key,
        "poisoned_index": poisoned_index,
        "iso_challenge_A": iso_challenge_A,
        "gr48_poly": gr48_poly,
        "gr48_gen": gr48_gen,
        "flag_ct": flag_ct,
        "flag_nonce": flag_nonce,
        "flag_tag": flag_tag,
    }


def mul(a, b, poly):
    deg = 8
    prod = [0] * (2 * deg - 1)
    for i in range(deg):
        for j in range(deg):
            prod[i + j] = (prod[i + j] + a[i] * b[j]) % 4

    for d in range(2 * deg - 2, deg - 1, -1):
        if prod[d] != 0:
            coeff = prod[d]
            for k in range(deg + 1):
                prod[d - deg + k] = (prod[d - deg + k] - coeff * poly[k]) % 4
            prod[d] = 0
    return prod[:deg]


def kdf(secret_key, poly_coeffs, gen_coeffs):
    sk_bytes = bytes([e + 127 for e in secret_key])

    h = hashlib.shake_256(sk_bytes)
    state_bytes = h.digest(136)

    mixed = bytearray()
    for off in range(0, len(state_bytes), 8):
        block = state_bytes[off:off + 8]
        if len(block) < 8:
            block = block + bytes(8 - len(block))

        elem = [int(b) % 4 for b in block]
        product = mul(elem, gen_coeffs, poly_coeffs)
        mixed.extend(bytes(c % 256 for c in product))

    squeeze = h.digest(32)
    derived = hashlib.shake_256(bytes(mixed)).digest(32)
    return bytes(a ^ b for a, b in zip(derived, squeeze))


def xdbl(X, Z, A24, p):
    XX = (X * X) % p
    ZZ = (Z * Z) % p
    XZ = (X * Z) % p
    X2 = (XX - ZZ) * (XX - ZZ) % p
    t = (XX + ZZ) % p
    Z2 = (4 * XZ * (t + (4 * A24 - 2) * XZ)) % p
    return X2 % p, Z2 % p


def xadd(X1, Z1, X2, Z2, Xd, Zd, p):
    U = (X1 - Z1) * (X2 + Z2) % p
    V = (X1 + Z1) * (X2 - Z2) % p
    add = (U + V) % p
    sub = (U - V) % p
    X3 = Zd * add * add % p
    Z3 = Xd * sub * sub % p
    return X3, Z3


def xmul(x0, k, A, p):
    if k == 0:
        return None
    A24 = (A + 2) * pow(4, -1, p) % p
    X0, Z0 = 1, 0
    X1, Z1 = x0 % p, 1

    bits = k.bit_length()
    for i in range(bits - 1, -1, -1):
        if (k >> i) & 1:
            X0, Z0 = xadd(X0, Z0, X1, Z1, x0, 1, p)
            X1, Z1 = xdbl(X1, Z1, A24, p)
        else:
            X1, Z1 = xadd(X0, Z0, X1, Z1, x0, 1, p)
            X0, Z0 = xdbl(X0, Z0, A24, p)

    if Z0 == 0:
        return None
    return X0 * pow(Z0, -1, p) % p


def velu(kernel_x, ell, A, p):
    inv = lambda x: pow(x % p, -1, p)

    A = A % p
    kernel_xs = [kernel_x % p]

    if ell >= 5:
        A24 = (A + 2) * pow(4, -1, p) % p
        X2, Z2 = xdbl(kernel_x % p, 1, A24, p)
        if Z2 != 0:
            kernel_xs.append(X2 * inv(Z2) % p)

        for _ in range(3, (ell + 1) // 2):
            if len(kernel_xs) < 2:
                break
            Xprev, Xprev2 = kernel_xs[-1], kernel_xs[-2]
            Xnew, Znew = xadd(Xprev, 1, kernel_xs[0], 1, Xprev2, 1, p)
            if Znew == 0:
                break
            kernel_xs.append(Xnew * inv(Znew) % p)

    sigma = 0
    for xk in kernel_xs:
        if xk == 0:
            continue
        fprime = (3 * xk * xk + 2 * A * xk + 1) % p
        fdprime = (6 * xk + 2 * A) % p
        if fprime != 0:
            sigma = (sigma + fdprime * inv(fprime)) % p

    return (A - 12 * sigma) % p


def trace(query_A, secret_key, primes, p, skip_index=-1):
    A_pow = 1
    trace = 0
    for i in range(len(primes)):
        if i != skip_index:
            trace = (trace + secret_key[i] * A_pow) % p
        A_pow = A_pow * query_A % p
    return trace


def group_action(input_A, secret_key, small_primes, p):
    remaining = list(secret_key)
    ops_count = 0
    max_outer = 400
    A_int = input_A % p

    for outer_iter in range(max_outer):
        if not any(r != 0 for r in remaining):
            break

        x_try = outer_iter + 1
        rhs = (pow(x_try, 3, p) + A_int * pow(x_try, 2, p) + x_try) % p

        if rhs == 0:
            continue

        leg = pow(rhs, (p - 1) // 2, p)

        if leg == 1:
            sign = 1
        elif leg == p - 1:
            sign = -1
        else:
            continue

        made_progress = False
        for i, ell in enumerate(small_primes):
            if remaining[i] == 0:
                continue

            if not ((remaining[i] > 0 and sign == 1) or (remaining[i] < 0 and sign == -1)):
                continue

            cofactor = (p + 1) // ell
            kernel_x = xmul(x_try, cofactor, A_int, p)
            if kernel_x is None:
                continue

            check = xmul(kernel_x, ell, A_int, p)
            if check is not None:
                continue

            try:
                new_A = velu(kernel_x, ell, A_int, p)
                if new_A is None:
                    continue
            except Exception:
                continue

            A_int = new_A % p
            ops_count += 1

            if remaining[i] > 0:
                remaining[i] -= 1
            else:
                remaining[i] += 1

            made_progress = True

        if not made_progress and outer_iter > 100:
            x_try = (x_try * 3 + 7) % p
            if x_try == 0:
                x_try = 1

    return A_int, ops_count


def j_invariant(A, p):
    A = A % p
    A2 = A * A % p
    denom = (A2 - 4) % p
    if denom == 0:
        return 0
    num = pow((A2 - 3) % p, 3, p)
    return 256 * num % p * pow(denom, -1, p) % p


def params_b64(params):
    pub = {
        "p": str(params["p"]),
        "primes": params["primes"],
        "base_curve_A": params["base_A"],
        "iso_challenge_A": str(params["iso_challenge_A"]),
        "gr48_poly": params["gr48_poly"],
        "gr48_generator": params["gr48_gen"],
    }
    raw = json.dumps(pub).encode()
    return base64.b64encode(raw).decode()


class PortobeloProtocol(asyncio.Protocol):

    ip_connection_counts = defaultdict(int)
    server_params = None

    def __init__(self):
        self.transport = None
        self.peer_ip = None
        self.query_count = 0
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info('peername')
        self.peer_ip = peer[0] if peer else "unknown"

        if PortobeloProtocol.ip_connection_counts[self.peer_ip] >= MAX_CONNECTIONS_PER_IP:
            self.write_line("Too many connections from your IP")
            transport.close()
            return

        PortobeloProtocol.ip_connection_counts[self.peer_ip] += 1
        self.greet()

    def connection_lost(self, exc):
        if self.peer_ip:
            count = PortobeloProtocol.ip_connection_counts.get(self.peer_ip, 0)
            if count > 0:
                PortobeloProtocol.ip_connection_counts[self.peer_ip] = count - 1

    def write_line(self, line):
        self.transport.write((line + "\n").encode())

    def greet(self):
        params = PortobeloProtocol.server_params
        pb64 = params_b64(params)

        ct_hex = params["flag_ct"].hex()
        nonce_hex = params["flag_nonce"].hex()
        tag_hex = params["flag_tag"].hex()

        self.write_line(BANNER)
        self.write_line(f"PARAMS {pb64}")
        self.write_line(f"ENCRYPTED_FLAG {ct_hex} {nonce_hex} {tag_hex}")
        self.write_line("READY")

    def data_received(self, data):
        self.buffer += data
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self.handle_line(line.decode(errors='replace').strip())

    def handle_line(self, line):
        if not line:
            return

        parts = line.split()
        if not parts:
            return

        cmd = parts[0].upper()

        if cmd == "QUERY":
            self.handle_query(parts)
        elif cmd == "QUIT" or cmd == "EXIT":
            self.write_line("BYE")
            self.transport.close()
        else:
            self.write_line("Unknown command. Use: QUERY <montgomery_A>")

    def handle_query(self, parts):
        if self.query_count >= MAX_QUERIES:
            self.write_line("RATE_LIMIT")
            self.transport.close()
            return

        if len(parts) < 2:
            self.write_line("Usage: QUERY <montgomery_A_integer>")
            return

        try:
            query_A = int(parts[1])
        except ValueError:
            self.write_line("Invalid Montgomery coefficient: must be integer")
            return

        params = PortobeloProtocol.server_params
        p = params["p"]

        if not (0 <= query_A < p):
            self.write_line(f"Montgomery coefficient must be in [0, p-1]")
            return

        if pow(query_A, 2, p) == 4 % p:
            self.write_line("Singular curve (A^2 = 4)")
            return

        self.query_count += 1

        try:
            ops_count = params["ops_count"]
            j_inv = j_invariant(query_A, p)
            trace = trace(query_A, params["secret_key"],
                                        params["primes"], p,
                                        skip_index=params["poisoned_index"])
            self.write_line(f"RESULT {j_inv} {ops_count} {trace}")
        except Exception:
            self.write_line(f"Internal error")
            return

async def main():
    try:
        params = load_params()
        params["ops_count"] = sum(abs(e) for e in params["secret_key"])
        PortobeloProtocol.server_params = params
    except FileNotFoundError:
        print("no params.json, run gen.py")
        sys.exit(1)

    print(f"p = {params['p'].bit_length()} bits, {len(params['primes'])} primes")

    loop = asyncio.get_event_loop()
    server = await loop.create_server(PortobeloProtocol, '0.0.0.0', PORT)
    print(f":{PORT}, {MAX_QUERIES} queries max, {MAX_CONNECTIONS_PER_IP} conns/ip")
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
