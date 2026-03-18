from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


class PaddingOracleClass:
    def __init__(self):
        self.key = os.urandom(16)
        self.auth = os.urandom(16)
        self.nonces = set()

        self.update(nonce=os.urandom(12))
    
    def update(self, nonce: bytes):
        assert nonce not in self.nonces, "Nonce Reuse Detected"

        self.nonces.add(nonce)
        self.nonce = nonce
        self.cnt = 2
    
    def register(self, username: bytes) -> tuple[bytes, bytes]:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = aes.encrypt_and_digest(pad(username, 16))
        return tok+en

    def login(self, token: bytes) -> bytes:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = token[:-16], token[-16:]
        username = unpad(aes.decrypt_and_verify(tok, en), 16)
        return username


MENU = '''
========== MENU ==========
cnt = {}
nonce = {}

= [U]pdate
= [R]egister
= [L]ogin
= [Q]uit
==========================
'''

poc = PaddingOracleClass()
while True:
    print(MENU.format(poc.cnt, poc.nonce.hex()))
    try:
        inp = input('>').upper()
        if inp == "Q":
            raise Exception
        
        elif inp == "U":
            poc.update(
                nonce=bytes.fromhex(input("nonce(hex)>"))
            )

        elif inp == "R":
            username = os.urandom(8)
            token = poc.register(username=username)
            print(f"Register!\n{token.hex()}")
            print(username.hex())

        elif inp == "L":
            token = bytes.fromhex(input("token(hex)>"))
            username = poc.login(token=token)
            print(f"Login!")
            if username == b"admin":
                with open("flag", "r") as f:
                    print(f.read())
                raise Exception
            else:
                print(f"Hello, what can I help you? {username.hex()}")
    except:
        print("Bye")
        break