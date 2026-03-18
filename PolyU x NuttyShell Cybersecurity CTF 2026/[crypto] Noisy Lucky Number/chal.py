import os, json, hashlib, struct
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigdecode_string, sigencode_string

# [REDACTED] Secret parameters loaded from server
D_HEX = os.environ.get("PRIVATE_KEY_HEX", "00" * 32)
HW_ID = int(os.environ.get("HW_ID", "0")) # A 16-bit integer
PLAINTEXT_FLAG = os.environ.get("FLAG", "PUCTF{fake_flag_for_testing}").encode()

class EntropyMixer:
    def __init__(self, hw_id):
        self.hw_id = hw_id & 0xFFFF
        # Hardware sometimes fails to initialize the mixer correctly
        self.mixer_stable = (os.urandom(1)[0] > 35) 
        
    def generate_nonce(self):
        raw_entropy = os.urandom(30)
        
        if self.mixer_stable:
            # Combine the entropy with the lucky number into a 32-byte buffer
            mixed_buffer = struct.pack(">30sH", raw_entropy, self.hw_id)
            return int.from_bytes(mixed_buffer, "big")
        else:
            # Failsafe: just return 32 bytes of pure entropy
            return int.from_bytes(os.urandom(32), "big")

# Setup
curve = SECP256k1
n = curve.order
sk = SigningKey.from_secret_exponent(int(D_HEX, 16), curve=curve)
vk = sk.get_verifying_key()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def xor_stream(data: bytes, key32: bytes) -> bytes:
    ks = (key32 * ((len(data) // 32) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))

encrypted_flag = xor_stream(PLAINTEXT_FLAG, sha256(int(D_HEX, 16).to_bytes(32, "big"))).hex()

def sign_transaction():
    msg = os.urandom(32)
    h = sha256(msg)
    
    # Initialize a fresh entropy mixer for each transaction
    mixer = EntropyMixer(HW_ID)
    
    while True:
        k = mixer.generate_nonce()
        if 1 <= k < n:
            break
            
    sig = sk.sign_digest(h, sigencode=sigencode_string, k=k)
    r, s = sigdecode_string(sig, n)
    return {"r": hex(r), "s": hex(s), "hash": h.hex()}

if __name__ == "__main__":
    # The server logged 50 transactions today
    data = [sign_transaction() for _ in range(50)]

    task = {
        "name": "Noisy Lucky Number",
        "curve": "secp256k1",
        "n": hex(n),
        "pubkey_compressed": vk.to_string("compressed").hex(),
        "encrypted_flag": encrypted_flag,
        "count_total": len(data),
        "data": data
    }

    with open("task_data.json", "w") as f:
        json.dump(task, f, indent=2)
    print("Log exported.")
