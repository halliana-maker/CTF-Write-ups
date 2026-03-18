# HKCERT CTF 2025 - EC Fun Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *密碼學很簡單！祝你玩得開心！ Crypto is so EC! May you have fun!*  

## TL;DR
The challenge implements a custom Elliptic Curve over a 140-bit prime but hides the curve equation. The encryption key is a small 54-bit integer used in a point multiplication operation ($Y = G_1 + k \cdot G_2$).
**Solution:**
1.  **Reconstruct the Curve:** Generate points using the provided "black box" addition function and use linear algebra to find the curve equation (General Weierstrass form).
2.  **Normalize:** Apply an isomorphism to transform the curve into a standard monic form supported by SageMath ($Y^2 = X^3 + \dots$).
3.  **Solve DLP:** Use Pollard's Lambda method (Sage's `discrete_log` with bounds) to recover the 54-bit key in seconds.

---

## 1. Reconnaissance & Analysis

We are given a Python script `task.py` containing:
1.  A large prime $p \approx 2^{140}$.
2.  Two mysterious lambda functions: `have(s, t)` and `fun(t)`.
3.  A `have_fun(a, b)` function that looks like a **Double-and-Add** algorithm.
4.  A generated public key `y` and an AES-encrypted flag.

```python
key = random.randrange(2, 1<<54) # Vulnerability: Small Key!
y = have_fun(g2, key)            # y = g1 + key * g2
```

### Identification
The rational functions inside `have` (addition) and `fun` (doubling) involve polynomials of degree 3 and 4. This complexity strongly suggests point arithmetic on an **Elliptic Curve** (likely in homogeneous projective coordinates or just affine with complex formulas).

The operation `have_fun` initializes `res = g1`, then adds `key` copies of `g2` to it.
Equation: $$Y = G_1 + k \cdot G_2$$
Target: Recover $k$ given $Y, G_1, G_2$.
This is the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.

---

## 2. The Vulnerability

### 1. Small Key Size
The key is explicitly generated with `random.randrange(2, 1<<54)`.
While 140-bit ECDLP is cryptographically secure ($2^{70}$ ops), a **54-bit** key is vulnerable to "Small Interval" attacks like **Pollard's Lambda (Kangaroo)** or **Baby-Step Giant-Step (BSGS)**.
Complexity: $\sqrt{2^{54}} = 2^{27}$ operations.
This takes $< 1$ second on a modern CPU.

### 2. Unknown Curve (Security by Obscurity)
We don't know the curve coefficients ($a, b$) or the equation form. However, we have an "Oracle" (the python code) that can generate valid points on the curve. This allows us to reconstruct the equation.

---

## 3. Solver Strategy

### Step 1: Curve Reconstruction
A generic cubic curve in 2D is defined by:
$$c_1 x^3 + c_2 x^2y + c_3 xy^2 + c_4 y^3 + c_5 x^2 + c_6 xy + c_7 y^2 + c_8 x + c_9 y + c_{10} = 0$$

We generate 10+ points using the `have` function and construct a matrix where each row represents a point evaluated at these monomials. The **kernel (null space)** of this matrix gives us the coefficients.

After running the linear algebra attack, we found a relation of the form:
$$A x^3 + B x^2 + C xy + y^2 + D x + E y + F = 0 \pmod p$$
*Note: The coefficient of $x^3$ ($A$) was not 1, meaning it's a non-monic curve.*

### Step 2: Isomorphism to Weierstrass Form
SageMath's optimized `EllipticCurve` class expects the standard Weierstrass form ($y^2 + a_1 xy + a_3 y = x^3 + \dots$).
We cannot simply divide by $A$ because that would mess up the $y^2$ term. Instead, we use a coordinate transformation.

Let $X = -Ax$ and $Y = Ay$.
Substituting these into the equation and multiplying by $A^2$ transforms the non-monic $Ax^3$ term into a monic $X^3$ term, perfectly matching the standard form:
$$Y^2 + a_1 XY + a_3 Y = X^3 + a_2 X^2 + a_4 X + a_6$$

Calculated parameters:
*   $a_1 = -C$
*   $a_2 = -B$
*   $a_3 = EA$
*   $a_4 = DA$
*   $a_6 = -FA^2$

### Step 3: Solving the DLP
We map the challenge points $G_1, G_2, Y_{target}$ to the new coordinate system using the same transformation ($x \to -Ax, y \to Ay$).
Then we setup the equation:
$$Target = Y_{new} - G_{1,new} = k \cdot G_{2,new}$$
We use Sage's `discrete_log` with `bounds=(2, 2^54)`.

---

## 4. Full Solver Script

```python
#!/usr/bin/env sage
import sys
from sage.all import *
from Crypto.Cipher import AES

def solve():
    # 1. Challenge Constants
    p = 1361137685787644823054950239221481267310111
    F = GF(p)
    
    # 2. "Black Box" Addition (Copied from challenge)
    def have(s, t):
        s0, s1 = F(s[0]), F(s[1])
        t0, t1 = F(t[0]), F(t[1])
        # ... (full math expressions from source) ...
        # (For brevity, math omitted in writeup, see solution code)
        # ...
        return (num_x / den_x, num_y / den_y)

    # 3. Generate Points for Reconstruction
    g1 = (F(1151954709424958906091046463160132564937644), F(709388597947225692614956015386635942863012))
    g2 = (F(981333628607549915704008747402562350211701), F(1251610635487471222383956310361676241534200))
    y_chal = (F(1233646914495991358880000369082822614720033), F(169216170896679696320800078452784590711491))

    pts = [g1, g2]
    curr = g1
    for _ in range(12):
        nxt = have(curr, g2)
        pts.append(nxt)
        curr = nxt

    # 4. Linear Algebra to find Curve Equation
    # Target form: A x^3 + B x^2 + C xy + y^2 + D x + E y + F = 0
    rows = [[x**3, x**2, x*y, y**2, x, y, F(1)] for x, y in pts]
    M = Matrix(F, rows)
    K = M.right_kernel().basis()[0]
    
    # Normalize so y^2 coefficient is 1
    coeffs = [k / K[3] for k in K] 
    A, B, C, _, D, E, F_const = coeffs

    # 5. Transform to Standard Weierstrass (Y^2 ... = X^3 ...)
    # Map: X = -Ax, Y = Ay
    a1, a2 = -C, -B
    a3, a4 = E*A, D*A
    a6 = -F_const * (A**2)
    
    E_curve = EllipticCurve(F, [a1, a2, a3, a4, a6])
    
    # 6. Map points and Solve DLP
    def map_pt(pt): return E_curve(-A*pt[0], A*pt[1])
    
    P_base = map_pt(g2)
    P_target = map_pt(y_chal) - map_pt(g1)
    
    print(f"[*] Solving DLP on {E_curve}")
    k = discrete_log(P_target, P_base, bounds=(2, 1<<55), operation='+')
    print(f"[+] Key found: {k}")

    # 7. Decrypt
    key_bytes = str(k).encode()[:16]
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    enc_flag = b"t\xf1x\xc2'}q\xe7i.\x0cmj\x0fkNkVJ-\xd5\xbf\xf9H_\xd1\x04hO\xcd\xe1\x95P\xad\xea\xe1\xec\x1c\xben?RCr\x932\x90t"
    print(f"[+] Flag: {cipher.decrypt(enc_flag).decode()}")

solve()
```

## 5. Result

The solver recovered the key `15946553602128288` almost instantly.

**Flag:**
`flag{Tw1s7ed_5tr4nge_Curve_but_S0_3asy}`