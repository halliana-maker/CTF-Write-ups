from Crypto.Util.number import long_to_bytes
import gmpy2

# Challenge Data
c = 30552929401084215063034197070424966877689134223841680278066312021587156531434892071537248907148790681466909308002649311844930826894649057192897551604881567331228562746768127186156752480882861591425570984214512121877203049350274961809052094232973854447555218322854092207716140975220436244578363062339274396240
d = 3888417341667647293339167810040888618410868462692524178646833996133379799018296328981354111017698785761492613305545720642074067943460789584401752506651064806409949068192314121154109956133705154002323898970515811126124590603285289442456305377146471883469053362010452897987327106754665010419125216504717347373
e = 0x10001

print("[*] Starting brute-force for k to recover phi and N...")

# e * d - 1 = k * phi
X = e * d - 1

# Iterate k
for k in range(1, e + 1):
    if X % k == 0:
        phi = X // k
        
        # p is approx sqrt(phi)
        # Since q = next_prime(p), q > p
        # phi = (p-1)(q-1) > (p-1)^2  => sqrt(phi) > p-1 => p < sqrt(phi) + 1
        # So p is likely the first prime <= isqrt(phi)
        
        p_base = gmpy2.isqrt(phi)
        p_curr = p_base
        
        # Check a few integers downwards for primality
        for _ in range(5):
            # Find nearest prime downwards
            while not gmpy2.is_prime(p_curr):
                p_curr -= 1
            
            p = int(p_curr)
            q = int(gmpy2.next_prime(p))
            
            # Verify if these generate the correct phi
            if (p - 1) * (q - 1) == phi:
                n = p * q
                print(f"[+] Match found! k={k}")
                print(f"    p = {p}")
                print(f"    q = {q}")
                print(f"    n = {n}")
                
                # Decrypt
                m = pow(c, d, n)
                try:
                    flag = long_to_bytes(m).decode()
                    print(f"[SUCCESS] FLAG: {flag}")
                    exit(0)
                except Exception as err:
                    print(f"[!] Decryption failed: {err}")
            
            # Continue checking lower primes for this k
            p_curr -= 1