from Crypto.Util.number import *
from Crypto.Cipher import AES
from random import choice
from hashlib import md5
from secret import flag

p = 1096126227998177188652856107362412783873814431647
E = EllipticCurve(GF(p), [0, 5])

s = [E.random_element() for _ in range(73)]
e = [E.random_element() for _ in "01"]
A = random_matrix(GF(p), 137, 73)
b = [(sum(i*j for i,j in zip(_,s)) + choice(e)).xy() for _ in A]


print("A =", A.list())
print("b =", b)
print("enc =", AES.new(key=md5(str(s).encode()).digest(), nonce=b"LWECC", mode=AES.MODE_CTR).encrypt(flag))