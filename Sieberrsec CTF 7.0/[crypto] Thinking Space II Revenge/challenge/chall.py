from pow import PoW
from uov import uov_1p_pkc as uov

PoW(25000)

pk, sk = uov.keygen()
thought = b'I am thinking of the flag'
print(pk.hex())

# sign
msg = input('msg: ').encode()
assert msg != thought
print(uov.sign(msg,sk,pk).hex())

# verify
sig = bytes.fromhex(input('sig: '))
if uov.verify(sig,thought,pk):
    print(open('flag.txt','r').read().strip())
