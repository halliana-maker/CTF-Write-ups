from sage.all import *  
from sage.crypto.util import random_blum_prime
from Crypto.Util.number import *
from secret import flag

nbit = 512
gamma = 0.44
delta = 0.51
dm,dl = 0.103, 0.145
cpbit = ceil(nbit * gamma) 
kbit  = int(nbit * delta)
msbit = int(nbit * dm)
lsbit = int(nbit * dl)
g = random_blum_prime(2**(cpbit - 1), 2**cpbit-1)  
while 1:
    p = q = 0
    while is_prime(p) or len(bin(p)) - 2 != nbit // 2:
        a = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        p = 2 * g * a + 1 
    while is_prime(q) or len(bin(q)) - 2 != nbit // 2:
        b = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        q = 2 * g * b + 1
    L = 2 * g * a * b   
    if is_prime(L + a + b):
        n = p * q
        break

d = random_prime(2**kbit-1, lbound=2**(kbit - 1)) 
e = inverse_mod(d, L)
k = (e * d - 1) // L
dm = d // (2 ** (kbit - msbit))
dl = d % (2 ** lsbit)
m = bytes_to_long(flag)
print(dm, dl, e, n)
print(pow(m, e, n))
"""
3203202584971257 7274383203268085152331 36346110007425305872660997908648011390452485009167380402907988449045651435844811625907 8073736467273664280056643912209398524942152147328656910931152412352288220476046078152045937002526657533942284160476452038914249779936821603053211888330755
8042279705649954745962644909235780183674555369775538455015331686608683922326562829164835918982642084136603628007677118144681339970688028985720674063973679
"""