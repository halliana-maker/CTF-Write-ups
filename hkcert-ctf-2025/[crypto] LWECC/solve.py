#!/usr/bin/env sage
from sage.all import *
from Crypto.Cipher import AES
from hashlib import md5

# --- Data Loading ---
# Using exec is a common CTF shortcut to load 'A = [...]' etc. from a file
with open("output.txt", "r") as f:
    exec(f.read())

p = 1096126227998177188652856107362412783873814431647
E = EllipticCurve(GF(p), [0, 5])
G = E.gens()[0]
# Anomalous curve check: E.order() == p. Smart's attack is implicit in pt.log(G)

# --- 1. Linearize the EC-LWE ---
print("[*] Solving ECDLPs (Smart's Attack)...")
# Convert all curve points in 'b' to scalars mod p
B_scalars = vector(Zmod(p), [E(pt).log(G) for pt in b])
A_mat = Matrix(GF(p), 137, 73, A)

# --- 2. Eliminate Secret s using Kernel ---
print("[*] Computing Left Kernel...")
K = A_mat.left_kernel().basis() # 64 basis vectors
# Equation per kernel vector v: v.B = (sum v_i)E0 + (sum v_i*x_i)deltaE
# Let W_i = sum(v_i), Z_i = v_i . B
W = [sum(v) for v in K]
Z = [v * B_scalars for v in K]

# --- 3. Lattice to find choice vector x ---
# We use indices 0 and 1 to eliminate E0 and deltaE from the rest
# Equation: X_k(Z0*W1 - Z1*W0) + X_1(Zk*W0 - Z0*Wk) + X_0(Z1*Wk - Zk*W1) = 0 mod p
print("[*] Constructing Lattice...")
n = 137
m = len(K)
eqs = []

for k in range(2, m):
    c_k = (Z[0]*W[1] - Z[1]*W[0])
    c_1 = (Z[k]*W[0] - Z[0]*W[k])
    c_0 = (Z[1]*W[k] - Z[k]*W[1])
    
    # This equation is sum( (c_k*K[k]_j + c_1*K[1]_j + c_0*K[0]_j) * x_j ) = 0 mod p
    eq_vector = [(c_k*K[k][j] + c_1*K[1][j] + c_0*K[0][j]) for j in range(n)]
    eqs.append(eq_vector)

# LLL Matrix: [ Identity (nxn) | Equations (nx62) ]
#             [ 0              | Modulo p (62x62) ]
WEIGHT = 2**100
L = Matrix(ZZ, n + (m-2), n + (m-2))
for i in range(n):
    L[i, i] = 1
    for j in range(m-2):
        L[i, n+j] = int(eqs[j][i]) * WEIGHT

for i in range(m-2):
    L[n+i, n+i] = p * WEIGHT

print("[*] Running LLL...")
B = L.LLL()

choices = None
for row in B:
    x = row[:n]
    if all(val in [0, 1] for val in x) and any(val != 0 for val in x):
        choices = list(x)
        break
    if all(val in [0, -1] for val in x) and any(val != 0 for val in x):
        choices = [-val for val in x]
        break

if not choices:
    print("[-] Failed to find choice vector")
    exit()

# --- 4. Solve for Secret Points s ---
print("[*] Recovering s...")
# Group indices where choices[i] is 0 to cancel out error choice
idx0 = [i for i, v in enumerate(choices) if v == 0]

# (A_i - A_j)s = B_i - B_j
final_A = []
final_B = []
for i in range(1, 74):
    final_A.append(A_mat[idx0[i]] - A_mat[idx0[0]])
    final_B.append(B_scalars[idx0[i]] - B_scalars[idx0[0]])

s_scalars = Matrix(GF(p), final_A).solve_right(vector(GF(p), final_B))
s_points = [G * int(val) for val in s_scalars]

# --- 5. Decrypt ---
key = md5(str(s_points).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=b"LWECC")
print(f"[+] Flag: {cipher.decrypt(enc).decode()}")