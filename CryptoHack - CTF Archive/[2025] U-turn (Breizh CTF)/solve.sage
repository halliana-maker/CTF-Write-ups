from ast import literal_eval

# Load matrix and hash
with open("A.txt", "r") as f: A_data = literal_eval(f.read())
h_hex = "fdac962720ab6e0c60ddbdf06d05112e315b86294e6bef26a695d851bb898b025dd3f6a65620cb4b509292cb64d0aa88"
h = vector(ZZ, list(bytes.fromhex(h_hex)))

k, l, n = 48, 50, 256
W = 1000

# Build Lattice
M = Matrix(ZZ, l + k + 1, l + k + 1)
M[:l, :l] = identity_matrix(l)
M[:l, l:-1] = Matrix(ZZ, A_data).transpose() * W
M[l:-1, l:-1] = identity_matrix(k) * n * W
M[-1, l:-1] = -h * W
M[-1, -1] = 1

# Reduce
L = M.LLL()
target_x = [row[:l] for row in L if abs(row[-1]) == 1 and all(abs(v) <= 2 for v in row[:l])][0]

# Search for flag
R = sum((int(target_x[i]) + 2) * (5**i) for i in range(l))
for k_val in range(4000):
    a_int = R + k_val * (5**50)
    a_bytes = int(a_int).to_bytes(16, 'little')
    flag_cand = bytes([int(b) ^^ 0x10 for b in a_bytes])
    if all(c in b"0123456789abcdef" for c in flag_cand):
        print(f"BZHCTF{{{flag_cand.decode()}}}")
        break