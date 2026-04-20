import base64
import codecs
import string

def solve():
    ciphertext = "4e5451315954517a4e5751315a6a55794e5749774d4455314e5451304d6a42694e5755314d6a55344e4745314e5455354e4459314e6a566d4d474531596a41774e5455314e4451774e544131596a55304e5467304e5455304d444d304d7a45304e5759314e6a566a4e4449314d54566d4e4449784e44566c4e574d3d"
    
    # Step 1: Hex Decode ("cursed")
    step1 = bytes.fromhex(ciphertext).decode('utf-8')
    
    # Step 2: Base64 Decode ("4 chunks away")
    step2 = base64.b64decode(step1).decode('utf-8')
    
    # Step 3: Hex Decode (The missing step from the riddle!)
    step3_bytes = bytes.fromhex(step2)
    
    # Step 4: XOR with 'bluehens' ("exorcise" / "UD's mascot")
    key = b"bluehens"
    step4_bytes = bytearray()
    for i in range(len(step3_bytes)):
        step4_bytes.append(step3_bytes[i] ^ key[i % len(key)])
    step4 = step4_bytes.decode('utf-8')
    
    # Step 5: ROT13 ("ROTting my social battery")
    step5 = codecs.decode(step4, 'rot_13')
    
    # Step 6: Hex Decode (The third hex decode from the riddle)
    step6 = bytes.fromhex(step5).decode('utf-8')
    
    # Step 7: Atbash ("bashing my head")
    normal_alpha = string.ascii_lowercase + string.ascii_uppercase
    reversed_alpha = string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1]
    atbash_trans = str.maketrans(normal_alpha, reversed_alpha)
    step7 = step6.translate(atbash_trans)
    
    # Step 8: 2-Rail Fence Decode ("stabbed in the back")
    final_flag = step7[0::2] + step7[1::2]
    
    print(f"Final Flag: {final_flag}")

if __name__ == "__main__":
    solve()