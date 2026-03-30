from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256
from random import choices
from tqdm import tqdm
from os import getenvb

FLAG = getenvb(b'FLAG', b'kalmar{fake_flag_pls_ignore_hehe}')

R = PolynomialRing(GF(2), 'x')
x = R.gen()
amt = 3500
lfsr_size = 200

lfsr_polys = [R.irreducible_element(lfsr_size + idx, algorithm = 'random') for idx in range(amt)]
print('Irred done')

true_states = [choices(range(2), k = lfsr_polys[idx].degree()) for idx in range(len(lfsr_polys))]
print('Init done')

L_total = sum(C.degree() for C in lfsr_polys)

def generate_combined_lfsr_stream(lfsr_polys, states, length):
	"""
	Computes the XOR sum of multiple LFSR streams using very cool math.
	Originally I wanted to just use the normal tap construction, and then XOR outputs together,
	But that was insanely slow...
	"""
	Z_poly = R(0) # Output of combined LFSR stream
	
	for C, state in tqdm(zip(lfsr_polys, states)):
		L = C.degree()
		S_init = R(state)
		P = (S_init * C).truncate(L)
		C_inv = C.inverse_series_trunc(length)
		LFSR_output = (P * C_inv).truncate(length)
		
		Z_poly += LFSR_output # XOR LFSR output into the combined stream
		
	z_stream = Z_poly.list()
	z_stream.extend([0] * (length - len(z_stream)))
	
	return z_stream

z_stream = generate_combined_lfsr_stream(lfsr_polys, true_states, L_total) # A very long time
print('Gen done')
print(f'{lfsr_polys = }')
print(f'{z_stream = }')

key = sha256(str(true_states).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)

ct = cipher.encrypt(pad(FLAG, 16))
print(f'{ct.hex() = }')
