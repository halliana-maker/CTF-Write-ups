# 1n_jection - Zh3r0 CTF V2 2021 Writeup

**Description:** `"COVID: *exists* vaccine jokes: *challenge_name*"`

---

## 1. TL;DR
The challenge takes a string (the flag), converts it to an array of integers, and recursively compresses it into a single, massive integer using the **Cantor pairing function**. Since this function is a mathematical bijection, we can efficiently reverse the process by calculating the inverse Cantor function recursively until we reach standard ASCII values ($\le 255$).

---

## 2. What Data/File We Have and What is Special
We are provided with a single Python script (`challenge.py`) containing the encryption logic and the final encrypted integer. 

**The Script:**
```python
from secret import flag

def nk2n(nk):
    l = len(nk)
    if l==1:
        return nk[0]
    elif l==2:
        i,j = nk
        return ((i+j)*(i+j+1))//2 +j
    return nk2n([nk2n(nk[:l-l//2]), nk2n(nk[l-l//2:])])

print(nk2n(flag))
# 259774951998452001819353891497274402878076706737321063384...
```

**What is special:**
* **No standard cryptography:** There is no RSA, AES, or elliptic curve math. It's pure arithmetic.
* **No randomness/keys:** The script is entirely deterministic and relies completely on mathematical mapping.
* **Offline puzzle:** There is no interactive server or netcat connection. The challenge simply gives us the encryption function and its output, tasking us with reversing the math.

---

## 3. Problem Analysis (In Details)
Let's break down the `nk2n(nk)` function:
1. **Base Case 1 (`l == 1`):** If the array has one element, it returns the element.
2. **Base Case 2 (`l == 2`):** If the array has two elements `(i, j)`, it applies the formula:  
   $z = \frac{(i+j)(i+j+1)}{2} + j$
3. **Recursive Step:** If the array is larger, it splits the array in half, recursively calls `nk2n` on both halves to get two integers, and then groups those two integers using the logic above.

**The Mathematical Core:**
The equation $\frac{(i+j)(i+j+1)}{2} + j$ is the famous **Cantor pairing function**. 
It is a bijective mapping from $\mathbb{N} \times \mathbb{N} \to \mathbb{N}$. 
* **Bijective** means it is a perfect 1-to-1 mapping. Every unique pair of integers `(i, j)` produces a completely unique integer `z`. 
* More importantly, every integer `z` can be uniquely mapped back to exactly one `(i, j)` pair. Because it is lossless, we can completely recover the original data.

---

## 4. Initial Guesses / First Try
At first glance, one might assume this is a hashing function or a lossy compression algorithm where data is permanently destroyed via division `//`. 

A naive first attempt might be to brute-force the `(i, j)` combinations. However, because the array splits into a binary tree, the integers grow exponentially as they move up the tree. The final output is an integer with over 200 digits! Brute-forcing is impossible. 

However, recognizing the polynomial formula as a standard pairing function immediately shifts the strategy from "brute-forcing" to "mathematical inversion".

---

## 5. Exploitation Walkthrough / Flag Recovery
To reverse the Cantor pairing function, we need to map a given $z$ back to its $(i, j)$. 

Let $w = i + j$. 
The pairing function essentially calculates the $w$-th triangular number and adds $j$. 
We can invert this by solving for $w$ using the quadratic formula.
1. Find $w = \lfloor \frac{\sqrt{8z+1}-1}{2} \rfloor$.
2. Calculate the triangular number $t = \frac{w(w+1)}{2}$.
3. Recover $j = z - t$.
4. Recover $i = w - j$.

Since the script recursively applied this from the bottom up (building a binary tree), we need to apply our inverse function from the top down. We recursively split the large integer until the resulting numbers are $\le 255$ (which represents a valid ASCII byte).

**Exploit Script (SageMath/Python):**
```python
import sys

# Increase limits for huge integer conversions
sys.set_int_max_str_digits(100000)

def invert_cantor(z):
    """
    Inverts the Cantor pairing function for a given integer z.
    Returns the unique pair of integers (i, j).
    """
    # w = floor((sqrt(8z + 1) - 1) / 2)
    # Since z is huge, integer square root (isqrt) is highly efficient
    w = ((8 * z + 1).isqrt() - 1) // 2
    t = (w * (w + 1)) // 2
    j = z - t
    i = w - j
    return i, j

def get_leaves(z):
    """
    Recursively descends the binary tree. 
    Stops when the integer represents a valid ASCII byte (<= 255).
    """
    if z <= 255:
        return [int(z)]
    else:
        i, j = invert_cantor(z)
        return get_leaves(i) + get_leaves(j)

def solve():
    # The target integer from the challenge
    Z = 2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585
    
    print("[*] Inverting Cantor pairing function recursively...")
    leaves = get_leaves(Z)
    
    # Convert extracted integers back to ascii
    flag = bytes(leaves).decode('utf-8')
    print("[+] Flag found:")
    print(flag)

if __name__ == "__main__":
    solve()
```

**Output:**
```text
[*] Inverting Cantor pairing function recursively...
[+] Flag found:
zh3r0{wh0_th0ugh7_b1j3c710n5_fr0m_n^k_t0_n_c0uld_b3_s00000_c0000000l!}
```

---

## 6. What We Learned
* **Math in CS:** Mathematical bijections are incredibly powerful tools for mapping multidimensional arrays ($\mathbb{N}^k$) into a single dimension ($\mathbb{N}$).
* **Obscurity != Security:** Just because an algorithm turns a string into a massive, unrecognizable integer does not mean it is encrypted. Reversible functions without secret keys offer zero cryptographic security.
* **Algorithm Efficiency:** Even for an integer with over 250 digits, Python's native integer square root (`isqrt`) operates in near constant time, proving that proper mathematical analysis easily beats brute-force attempts.