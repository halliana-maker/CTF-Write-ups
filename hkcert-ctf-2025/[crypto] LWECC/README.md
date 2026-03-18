# HKCERT CTF 2025 - LWECC Write-up

*   **Event:** HKCERT CTF 2025 (Qualifying Round)
*   **Category:** Cryptography
*   **Description:** *Easy ECC...and LWE maybe*

## 1. TL;DR
1.  **Analyze the Curve:** The prime $p$ and curve $E$ define an **anomalous curve** (where the number of points $\#E(\mathbb{F}_p) = p$). This makes the Elliptic Curve Discrete Logarithm Problem (ECDLP) trivial via Smart’s Attack.
2.  **Linearize:** Use the trivial DLP to convert point addition equations into linear scalar equations modulo $p$.
3.  **Kernel Attack:** Use the left kernel of matrix $A$ to eliminate the secret vector $s$, leaving a system involving only two fixed error points and a binary selection vector.
4.  **Lattice Reduction (LLL):** Construct a lattice to find the short binary vector representing which error point was used for each row.
5.  **Recover Secret:** With the errors identified, subtract them to get a clean system of linear equations. Solve for $s$ and decrypt the flag.

---

## 2. Problem Analysis

We are given an implementation of **Learning With Errors (LWE)** over an Elliptic Curve. The system is defined as:
$$b_i = \left( \sum_{j=1}^{73} A_{i,j} \cdot s_j \right) + e_{\text{choice}} \pmod p$$

Where:
*   $A$ is a $137 \times 73$ matrix of scalars.
*   $s$ is a vector of 73 secret curve points.
*   $e$ is a list of 2 curve points $[e_0, e_1]$.
*   $b$ is the resulting vector of 137 curve points.

The goal is to find $s$ to derive the AES key.

### The "Aha!" Moment: Anomalous Curves
In most ECC challenges, the Discrete Logarithm Problem (DLP) is the hard part. However, checking the curve $y^2 = x^3 + 5 \pmod p$ with the given $p$:
```python
p = 1096126227998177188652856107362412783873814431647
E = EllipticCurve(GF(p), [0, 5])
print(E.order() == p) # Returns True
```
When the order of the curve is exactly equal to $p$, the curve is **anomalous**. On such curves, the ECDLP can be solved in linear time (Smart's Attack). In Sage, `point.log(G)` handles this automatically and instantly.

---

## 3. Mathematical Transformation

By solving the DLP for all points $b_i$, $s_j$, and $e_k$ relative to a generator $G$, we can rewrite the point additions as scalar additions in $\mathbb{Z}_p$:
$$B_i \equiv \sum_{j=1}^{73} A_{i,j} S_j + E_{\text{choice}} \pmod p$$

Let $x_i \in \{0, 1\}$ be the index chosen from the error list `e`.
$$B_i \equiv \sum_{j=1}^{73} A_{i,j} S_j + E_0 + x_i(E_1 - E_0) \pmod p$$

Let $\Delta E = E_1 - E_0$. Our equation for each row $i$ is:
$$B_i \equiv \sum_{j=1}^{73} A_{i,j} S_j + E_0 + x_i \Delta E \pmod p$$

---

## 4. Eliminating the Secret

We have 137 equations but many unknowns ($S_j$, $E_0$, $\Delta E$, and $x_i$). To simplify, we look for a vector $v$ in the **left kernel** of $A$ (meaning $v \cdot A = 0$).

Multiplying the whole vector $B$ by $v$:
$$v \cdot B = (v \cdot A)S + (v \cdot \vec{1})E_0 + (v \cdot X) \Delta E \pmod p$$
$$v \cdot B = 0 + (v \cdot \vec{1})E_0 + (\sum v_i x_i) \Delta E \pmod p$$

Let $z = v \cdot B$ and $W = \sum v_i$.
$$z \equiv W \cdot E_0 + (\sum v_i x_i) \Delta E \pmod p$$

Since the dimension of $A$ is $137 \times 73$, the left kernel has a dimension of $137 - 73 = 64$. We have 64 such equations.

---

## 5. Finding the Binary Error Vector (LLL)

The only "small" values in our system are the $x_i$ values (which are 0 or 1). We need to isolate them.
From the kernel equations, for any three basis vectors $v^{(0)}, v^{(1)}, v^{(k)}$:
1. $z_0 = W_0 E_0 + X_0 \Delta E$
2. $z_1 = W_1 E_0 + X_1 \Delta E$
3. $z_k = W_k E_0 + X_k \Delta E$

where $X_k = \sum v_i^{(k)} x_i$. This is a linear system in $E_0$ and $\Delta E$. We can eliminate $E_0$ and $\Delta E$ by calculating the determinant of the augmented matrix and setting it to zero:
$$\det \begin{pmatrix} z_0 & W_0 & X_0 \\ z_1 & W_1 & X_1 \\ z_k & W_k & X_k \end{pmatrix} = 0 \pmod p$$

Expanding this gives an equation of the form:
$$c_0 X_0 + c_1 X_1 + c_k X_k = 0 \pmod p$$
Substituting $X_k = \sum v_i^{(k)} x_i$:
$$\sum_{i=1}^{137} (c_0 v_i^{(0)} + c_1 v_i^{(1)} + c_k v_i^{(k)}) x_i = 0 \pmod p$$

This is exactly what the LLL part of the script does. It creates a lattice where the target vector is the binary vector $\vec{x} = [x_1, \dots, x_{137}]$. Because the vector is extremely short (composed only of 0s and 1s), LLL finds it easily.

---

## 6. Flag Recovery

Once the binary vector $\vec{x}$ is found:
1.  Identify indices $i$ where $x_i = 0$. For these rows, $B_i = \sum A_{i,j} S_j + E_0$.
2.  Take two such rows $i_1, i_2$ and subtract them:
    $B_{i_1} - B_{i_2} = \sum (A_{i_1,j} - A_{i_2,j}) S_j \pmod p$.
3.  This is now a clean system of linear equations. Solve for $S_j$ using Gaussian elimination.
4.  Convert the resulting scalars back to points on the curve: $s_j = S_j \cdot G$.
5.  Replicate the key derivation: `md5(str(s).encode()).digest()`.
6.  Decrypt with AES-CTR.

**Flag:** `flag{bf5963a9eebc8b4095ed22ca0812e4}`

---

## 7. Reflections & Guesses
*   **The anomalous curve:** Initially, one might think about Index Calculus or Pollard's Rho. However, the prime size (163-bit) and the specific curve form $y^2 = x^3 + B$ strongly suggest checking for anomalous properties.
*   **LWE vs. Fixed Error:** In standard LWE, errors are small and random. Here, errors are from a set of two points. This "Fixed Error LWE" is significantly weaker because the error can be cancelled out once its position is known.
*   **Lattice construction:** The determinant trick is a standard way to eliminate multiple shared variables across linear equations to isolate small coefficients for LLL.