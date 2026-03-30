import ast
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ── Parse output.txt ──────────────────────────────────────────────────────────
print("[*] Parsing output.txt...")
with open("3500output.txt", "r") as f:
    content = f.read()

lines = content.split("\n")
lfsr_polys_line = ct_hex = zstream_line = None
for line in lines:
    if line.startswith("lfsr_polys = "):
        lfsr_polys_line = line[len("lfsr_polys = "):]
    elif line.startswith("ct.hex() = "):
        ct_hex = line[len("ct.hex() = "):].strip().strip("'")
    elif line.startswith("z_stream = "):
        zstream_line = line[len("z_stream = "):]

z_list = ast.literal_eval(zstream_line)
ct_bytes = bytes.fromhex(ct_hex)

R = PolynomialRing(GF(2), "x")
x = R.gen()
lfsr_polys = sage_eval(lfsr_polys_line, locals={"x": x})

print(f"[*] Number of LFSRs: {len(lfsr_polys)}")
L_total = sum(C.degree() for C in lfsr_polys)
print(f"[*] L_total = {L_total}")

# ── Build Z ────────────────────────────────────────────────────────────────────
print("[*] Building Z polynomial...")
Z = R(z_list)

# ── Compute M = prod(C_i) using balanced product tree ─────────────────────────
print("[*] Computing M = prod(C_i) via product tree...")
polys = list(lfsr_polys)
while len(polys) > 1:
    next_level = []
    for i in range(0, len(polys), 2):
        if i+1 < len(polys):
            next_level.append(polys[i] * polys[i+1])
        else:
            next_level.append(polys[i])
    polys = next_level
    print(f"  level: {len(polys)} nodes, top deg = {polys[0].degree()}")
M = polys[0]
print(f"[*] M degree = {M.degree()}")

# ── Compute ZM_low = (Z * M) truncated to L_total coefficients ────────────────
# Math: (Z * M)[:L_total] = sum_i P_i * prod_{j!=i} C_j  (exact, deg < L_total)
print("[*] Computing Z * M (truncated to L_total)...")
ZM = Z * M
ZM_low = R(ZM.list()[:L_total])
print(f"[*] ZM_low degree = {ZM_low.degree()}")

# ── Recover each state via CRT ─────────────────────────────────────────────────
# For each i:
#   ZM_low mod C_i = P_i * (M/C_i) mod C_i
#   => P_i = (ZM_low mod C_i) * (M/C_i mod C_i)^{-1}  in GF(2)[x]/(C_i)
#   => state_i = (P_i * C_i^{-1} mod x^{L_i}).list()
print("[*] Recovering states via CRT...")
true_states = []

for idx, C in enumerate(lfsr_polys):
    L = C.degree()

    ZM_mod_C = ZM_low % C
    M_i = M // C              # exact polynomial division
    Mi_mod_C = M_i % C

    # Invert Mi_mod_C in GF(2)[x]/(C)  using extended GCD
    g, inv_Mi, _ = Mi_mod_C.xgcd(C)
    # g should be 1 (since C irreducible and Mi_mod_C != 0 mod C)

    P_i = (ZM_mod_C * inv_Mi) % C

    # state_i = (P_i * C^{-1} mod x^L).list()
    C_inv_trunc = R(C.inverse_series_trunc(L))
    state_poly = (P_i * C_inv_trunc).truncate(L)

    state = state_poly.list()
    state += [0] * (L - len(state))
    true_states.append(state)

    if idx % 100 == 0:
        print(f"  [{idx}/{len(lfsr_polys)}]")

# ── Decrypt ────────────────────────────────────────────────────────────────────
print("[*] Computing AES key...")
key = sha256(str(true_states).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(ct_bytes), 16)
print(f"[+] FLAG: {flag.decode()}")

# Output:
# [*] Parsing output.txt...
# [*] Number of LFSRs: 3500
# [*] L_total = 6823250
# [*] Building Z polynomial...
# [*] Computing M = prod(C_i) via product tree...
#   level: 1750 nodes, top deg = 401
#   level: 875 nodes, top deg = 806
#   level: 438 nodes, top deg = 1628
#   level: 219 nodes, top deg = 3320
#   level: 110 nodes, top deg = 6896
#   level: 55 nodes, top deg = 14816
#   level: 28 nodes, top deg = 33728
#   level: 14 nodes, top deg = 83840
#   level: 7 nodes, top deg = 233216
#   level: 4 nodes, top deg = 728576
#   level: 2 nodes, top deg = 2505728
#   level: 1 nodes, top deg = 6823250
# [*] M degree = 6823250
# [*] Computing Z * M (truncated to L_total)...
# [*] ZM_low degree = 6823249
# [*] Recovering states via CRT...
#   [0/3500]
#   [100/3500]
#   [200/3500]
#   [300/3500]
#   [400/3500]
#   [500/3500]
#   [600/3500]
#   [700/3500]
#   [800/3500]
#   [900/3500]
#   [1000/3500]
#   [1100/3500]
#   [1200/3500]
#   [1300/3500]
#   [1400/3500]
#   [1500/3500]
#   [1600/3500]
#   [1700/3500]
#   [1800/3500]
#   [1900/3500]
#   [2000/3500]
#   [2100/3500]
#   [2200/3500]
#   [2300/3500]
#   [2400/3500]
#   [2500/3500]
#   [2600/3500]
#   [2700/3500]
#   [2800/3500]
#   [2900/3500]
#   [3000/3500]
#   [3100/3500]
#   [3200/3500]
#   [3300/3500]
#   [3400/3500]
# [*] Computing AES key...
# [+] FLAG: kalmar{no_find_the_paper_here_only_skills_if_you_bruted_this_youre_skill_issued_4683264872364}