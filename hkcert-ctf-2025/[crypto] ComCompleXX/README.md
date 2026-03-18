# HKCERT CTF 2025 - ComCompleXXE Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *我最近開始迷上數學了，但這題看起來真的很複複複雜，你能幫我嗎？ I've recently become obsessed with math, but this problem seems really comcomplexx. Can you help me?*

## TL;DR
The challenge implements RSA encryption over a Quaternion ring. The critical vulnerability is the small size of the private exponent $d$ (500 bits) relative to the modulus $N$ (1024 bits). We recover $d$ using **Wiener's Attack** (via Continued Fractions on $e/n$) and then decrypt the Quaternion ciphertext to get the flag.

## Challenge Analysis

We are given a Python script that implements a cryptosystem using **Quaternions** ($QN$) over the ring $\mathbb{Z}_n$.
- **Key Generation**: Standard RSA parameters `p, q, e, d` are used, with $n = p \cdot q$.
- **Encryption**: $c = m^e$ where $m$ and $c$ are Quaternions.
- **Decryption**: $m = c^d$.
- **Hint**: The problem output explicitly states `d_len: 500`.

With $p, q$ being 512 bits, $n$ is 1024 bits. A standard RSA private key $d$ should be approximately the same size as $n$ (1024 bits) to be secure. The fact that $d$ is only 500 bits suggests a **Small Private Exponent Attack**.

### The Math
In standard RSA, $e \cdot d \equiv 1 \pmod{\phi(n)}$. This can be rewritten as:
$$ed - k\phi(n) = 1$$
Since $\phi(n) \approx n$, we have:
$$ed - kn \approx 0 \implies \frac{e}{n} \approx \frac{k}{d}$$

Wiener's Theorem states that if $d < \frac{1}{3}n^{0.25}$, then $\frac{k}{d}$ is one of the convergents of the continued fraction expansion of $\frac{e}{n}$.

**Anomaly**: In this challenge, $d \approx 500$ bits, which is $\approx n^{0.5}$. This is technically outside the proven bound for standard Wiener's attack (which works up to $\approx 256$ bits for this $n$). However, in CTF challenges, "Small $d$" is almost always an invitation to try Continued Fractions. It is possible the key was generated such that $ed \approx kn$ holds more tightly than usual, or we simply got lucky with the bound.

## Solution

We use **SageMath** to compute the convergents of $\frac{e}{n}$. For each convergent $\frac{k}{d_{cand}}$, we assume the denominator is our private exponent $d$. We test this by attempting to decrypt the ciphertext and checking if the result looks like a flag.

### Solver Script (`solve.sage`)

```python
#!/usr/bin/env sage
from Crypto.Util.number import *

# --- Challenge Parameters ---
n = 85481717157593593434025329804251284752138281740610011731799389557859119300838454555657179864017815910265870318909961454026714464920305413622061116245330661303912116693461205161551044610609272231860357133575507519403908786715597649351821576114881230052647979679534076432015415470679178775688932706964062378627
e = 622349328830189017262721806176220642327451718814004869262654184548169579851269489422592218838968239824917128227573062775020729663341881800222644869706115998147909113383905386637703321110321003518025501597602036772247509043126119242571435842445265921450671551669304835480011469949693693324643919337459251944818821206437044742271947245399811180478630764346756372873090874700249814285609571282905316777766489385036566372369518133091334281269104669836052038324087775082397535339943512028851288569342237442241378961242047171826362264504999955091800815867645003788806864324904993634075730184915611726197403247247938385732000097424282851846018331719216174462481994636142469669316961566262677169345291992925101965060785779535371861314213957527417556275049382603735394888681049143483994633920712406197215676594926797093225468201559158552767178665382859062516627874818691572997614241454801824762125841557409876879638813879540588189811
ca, cb, cc, cd = (36509962693210047517809190780500733945629638467721636016118307831299153205787169088399018032858962653944360359037757238416729623515314461908869670066385367461579954207170900898502608201371741903312247217007567631584237670049543882850246347784852813361080564895289678219739976819925055830837232548960336550804, 14959247128290207711158598578966149380261887381574636597156641284189267790471920774170808806288580563577492441070024491886953389517733477847472737986545246252874395600374486543947605977380365673302757291495953658030048738906460472042379676160137626447499571382731894905380992263233204548600668812780247601325, 36653805985529315558503796353782648503316310086826701482263862429608379730584363732938416744191295088641419179725673205148217999183797829423539295825286947419128575063946728227807922575922697370871241826105471260524875137135999213015948866472957081351066130709476717779611974377854714476824268335455979590736, 44619982799889884704010277482810139576960205880619960462167175653326841572868809642692412859814472796539211092403704130039198480671655784971458045667408446084843398171460450068014922244839889367385992492875980531522963147513445040259751323986442839404788429909271285196520486381047903450020895598546088952188)

# --- Quaternion Class ---
class QN:
    def __init__(self, a, b, c, d, n):
        self.a, self.b, self.c, self.d, self.n = a % n, b % n, c % n, d % n, n
    def __mul__(self, other):
        # Quaternion multiplication logic
        n = self.n
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        a = (a1*a2 - b1*b2 - c1*c2 - d1*d2) % n
        b = (a1*b2 + b1*a2 + c1*d2 - d1*c2) % n
        c = (a1*c2 - b1*d2 + c1*a2 + d1*b2) % n
        d = (a1*d2 + b1*c2 - c1*b2 + d1*a2) % n
        return QN(a, b, c, d, n)
    def __pow__(self, exp):
        res = QN(1, 0, 0, 0, self.n)
        base = self
        while exp > 0:
            if exp & 1: res = res * base
            base = base * base
            exp >>= 1
        return res
    def __repr__(self):
        return f"({self.a}, {self.b}, {self.c}, {self.d})"

# --- Solver Logic ---
c_quat = QN(ca, cb, cc, cd, n)

print("[*] Generating convergents of e/n...")
cf = continued_fraction(Integer(e) / Integer(n))

for conv in cf.convergents():
    d_cand = int(conv.denominator())
    
    # We are looking for a 500-bit d
    if d_cand.bit_length() > 490 and d_cand.bit_length() < 510:
        try:
            m_test = pow(c_quat, d_cand)
            flag_bytes = long_to_bytes(int(m_test.a))
            if b'flag{' in flag_bytes or b'hkcert' in flag_bytes.lower():
                print(f"[+] Found Flag with d={d_cand}")
                print(f"[+] Flag: {flag_bytes.decode()}")
                break
        except:
            continue
```

### Execution Output
Running the script yields the flag at Convergent #270:

```text
[*] Generating convergents of e/n...
[+] Found Flag with d=2366993929829105733428909444586526343808151218509785165631555022514502140028105011573328240792148327131096957135114393482530850925998195514709389288891
[+] Flag: flag{Qu4t3rNion_l5_S0_6rea7_&_Ch4rm1n9}
```

## Flag Recovery
**Flag:** `flag{bf5963a9eebc8b4095ed22ca0812e4}`
