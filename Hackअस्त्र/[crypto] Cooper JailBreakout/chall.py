import os
import binascii
from random import randint
from hashlib import md5
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long, GCD
from gmpy2 import legendre as legendre_symbol
from sage.all import *

class BaseChallenge:
    def __init__(self, level):
        self.level = level
        self.note_file = f"note_level{level}.txt"
        self.output_file = f"output_level{level}.txt"
        self.note = self.read_note()

    def read_note(self):
        with open(self.note_file, "rb") as f:
            return f.read().strip()

    def save_output(self, content):
        with open(self.output_file, "w") as f:
            f.write(content)

    def get_user_input(self, prompt="Submit the recovered note (raw or base64): "):
        return input(prompt).strip()

    def check_response(self, user_input, original_note):
        try:
            if user_input.startswith('b64:'):
                decoded = b64decode(user_input[4:])
            else:
                decoded = user_input.encode()

            if decoded == original_note:
                return True, "Correct!"
            else:
                return False, "Incorrect note."
        except Exception as e:
            return False, f"Error parsing input: {e}"


class Level1Challenge(BaseChallenge):
    def run(self):
        output = "[Level 1]  \n"

        prime_bits = 1337
        prime1, prime2 = getPrime(prime_bits), getPrime(prime_bits)
        modulus = prime1 * prime2

        factors = [1, 3, 3, 7]
        base = 1
        for f in factors:
            base *= f
        exponent = sum(factors)
        D_value = base ** exponent
        hint_value = int(D_value * sqrt(prime1) + D_value * sqrt(prime2))

        while True:
            candidate_x = randint(1337, modulus)
            leg_p = legendre_symbol(candidate_x, prime1)
            leg_q = legendre_symbol(candidate_x, prime2)
            if leg_p * leg_q > 0 and (leg_p + leg_q < 0):
                break

        message_bits = list(map(int, bin(bytes_to_long(self.note))[2:]))
        encrypted_list = []
        
        for bit in message_bits:
            while True:
                rand_val = randint(1337, modulus)
                if GCD(rand_val, modulus) == 1:
                    break
            encrypted_piece = (pow(candidate_x, 1337 + bit, modulus) * pow(rand_val, 2674, modulus)) % modulus
            encrypted_list.append(encrypted_piece)

        output += f"hint_val = {hint_value}\nD_const = {D_value}\nmodulus_n = {modulus}\nencrypted_bits = {encrypted_list}\n"

        user_input = self.get_user_input()
        is_correct, message = self.check_response(user_input, self.note)

        output += f"\n{message}\n"
        self.save_output(output)


class Level2Challenge(BaseChallenge):
    def run(self):
        output = "[Level 2]  \n"

        e = 3
        key = RSA.generate(2048)

        M1 = self.note + md5(self.note).digest()
        M2 = self.note + md5(b'One more time!' + self.note).digest()

        M1_int = int(binascii.hexlify(M1), 16)
        M2_int = int(binascii.hexlify(M2), 16)

        C1 = pow(M1_int, e, key.n)
        C2 = pow(M2_int, e, key.n)

        output += f"modulus = {hex(key.n)}\nexponent = {e}\nciphertext1 = {hex(C1)}\nciphertext2 = {hex(C2)}\n"

        user_input = self.get_user_input()
        is_correct, message = self.check_response(user_input, self.note)

        output += f"\n{message}\n"
        self.save_output(output)


class Level3Challenge(BaseChallenge):
    def run(self):
        output = "[Level 3]  \n"

        p, q = getPrime(1024), getPrime(1024)
        N = p * q
        e = 3

        m = bytes_to_long(self.note)
        x = bytes_to_long(os.urandom(256))
        c = pow(m | x, e, N)

        output += f"N = {N}\ne = {e}\nciphertext = {c}\n(m & x) = {m & x}\nx_original = {x}\n"

        user_input = self.get_user_input()
        is_correct, message = self.check_response(user_input, self.note)

        output += f"\n{message}\n"
        self.save_output(output)


class ChallengeRunner:
    def __init__(self):
        self.levels = {
            '1': Level1Challenge,
            '2': Level2Challenge,
            '3': Level3Challenge
        }

    def run(self):
        print(" Welcome to the Copper JailBreakout ")
        print(" Choose a challenge level (1, 2, 3)")
        level = input("Level: ").strip()
        challenge_class = self.levels.get(level)

        if challenge_class:
            challenge = challenge_class(level)
            challenge.run()
            print(f"Output saved to output_level{level}.txt")
        else:
            print("Invalid level selected.")


if __name__ == "__main__":
    runner = ChallengeRunner()
    runner.run()
