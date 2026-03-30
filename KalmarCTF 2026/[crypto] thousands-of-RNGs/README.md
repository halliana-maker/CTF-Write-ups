# KalmarCTF — thousands-of-RNGs Write-Up

## 1. TL;DR

3500 LFSRs each produce an output stream which are XOR'd together to form a keystream. The AES key is derived from SHA256 of all 3500 initial states. By exploiting the rational power series structure of LFSR outputs and applying polynomial CRT over GF(2)[x], we recover all initial states from the combined keystream and decrypt the flag.

***

## 2. Challenge Files \& Setup

**Files provided:**

- `chall.sage` — challenge source code
- `3500output.txt` — program output containing:
    - `lfsr_polys` — 3500 irreducible polynomials over GF(2)[x], with degrees 200, 201, ..., 3699
    - `z_stream` — the combined XOR'd bitstream of all LFSR outputs, of length $L_{\text{total}} = \sum_{i=0}^{3499}(200+i) = 6{,}823{,}250$ bits
    - `ct.hex()` — AES-ECB encrypted flag ciphertext

**No interactive server.** Pure offline cryptanalysis.

***

## 3. Problem Analysis

### Encryption Flow

For each LFSR $i$ (with $i = 0, \ldots, 3499$):

- A random binary initial state of length $L_i = 200 + i$ is chosen
- An irreducible polynomial $C_i$ of degree $L_i$ over GF(2) is generated
- The LFSR output stream of length $L_{\text{total}}$ is computed

All 3500 output streams are XOR'd to produce `z_stream`. The AES key is `SHA256(str(true_states))`, where `true_states` is the list of all initial states.

### Mathematical Structure

Each LFSR output is computed as:

$$
P_i = (\text{state}_i(x) \cdot C_i(x)) \bmod x^{L_i}, \quad \deg P_i < L_i
$$

$$
\text{output}_i = P_i \cdot C_i^{-1} \pmod{x^{L_{\text{total}}}}
$$

So the combined stream is:

$$
Z = \sum_{i=0}^{3499} P_i \cdot C_i^{-1} \pmod{x^{L_{\text{total}}}}
$$

**Key observation:** $\text{output}_i$ is a rational power series $P_i / C_i$ in GF(2)[[x]], with the initial state encoded in the numerator $P_i$. Specifically, $(P_i \cdot C_i^{-1})_{[0, L_i)} = \text{state}_i$ — the first $L_i$ coefficients of the power series expansion equal the initial state directly.

***

## 4. Initial Attempts

**Attempt 1 — Direct truncation:** Trying `(Z * C_i).truncate(L_i)` to isolate $P_i$ — failed, because all other LFSRs contribute contamination terms in the low-degree coefficients.

**Attempt 2 — Polynomial modulo:** Trying `Z % C_i` to recover state — failed for 3+ LFSRs; only appeared to work in a degenerate 2-LFSR test case by coincidence.

**Attempt 3 — CRT with full $Z \cdot M$:** Forming $M = \prod C_i$ and working modulo each $C_i$ — initially failed due to a misunderstanding about truncation, but led to the correct insight below.

***

## 5. Solution

### The Core Identity

Let $M = \prod_{i=0}^{3499} C_i$, which has degree exactly $L_{\text{total}}$. Consider:

$$
Z \cdot M = \sum_i P_i \cdot \prod_{j \neq i} C_j
$$

Each term on the right has degree $< L_i + (L_{\text{total}} - L_i) = L_{\text{total}}$, so the **right-hand side is a polynomial of degree $< L_{\text{total}}$**. Crucially, $Z$ itself has degree $< L_{\text{total}}$, so we can write:

$$
(Z \cdot M)_{\text{low}} := \text{first } L_{\text{total}} \text{ coefficients of } Z \cdot M = \sum_i P_i \cdot \prod_{j \neq i} C_j \quad \text{(exactly)}
$$

The higher-degree terms of $Z \cdot M$ are irrelevant — the low part is already exact.

### CRT Recovery

Since all $C_i$ are pairwise coprime (distinct irreducibles), reducing modulo $C_i$ isolates the $i$-th term:

$$
(Z \cdot M)_{\text{low}} \bmod C_i = P_i \cdot \underbrace{\left(\frac{M}{C_i} \bmod C_i\right)}_{N_i}
$$

Since $C_i$ is irreducible, $\text{GF}(2)[x]/(C_i)$ is a field, so $N_i$ is invertible and:

$$
P_i = \left((Z \cdot M)_{\text{low}} \bmod C_i\right) \cdot N_i^{-1} \pmod{C_i}
$$

### State Recovery

From $P_i$, the initial state is recovered as:

$$
\text{state}_i = \left(P_i \cdot C_i^{-1} \bmod x^{L_i}\right).{\tt list()}
$$

which follows from $P_i \cdot C_i^{-1} = \text{state}_i(x) + O(x^{L_i})$ in GF(2)[[x]].

### Decryption

With all states recovered, compute `key = SHA256(str(true_states))` and AES-ECB decrypt the ciphertext to get the flag.

**Flag:**

```
kalmar{no_find_the_paper_here_only_skills_if_you_bruted_this_youre_skill_issued_4683264872364}
```


***

## 6. What We Learned

| Concept | Takeaway |
| :-- | :-- |
| **Rational power series** | LFSR output = $P/C$ in GF(2)[[x]]; the initial state is directly recoverable from the numerator $P$ |
| **Truncation cancellation** | The product $(Z \cdot M)_{\text{low}}$ eliminates truncation error because the exact result has degree $< L_{\text{total}}$ |
| **Polynomial CRT** | Directly analogous to integer CRT — pairwise coprime moduli allow independent recovery of each component |
| **Product tree** | Computing $M = \prod C_i$ efficiently with a balanced binary tree, reducing complexity from $O(n^2)$ to $O(n \log^2 n)$ |
| **Representation fidelity** | The AES key depends on Python's exact `str()` output of the state lists — padding each state to the correct length is critical |

