#!/usr/bin/env sage
import sys
from sage.all import *
from Crypto.Util.number import long_to_bytes, inverse
import itertools

# ==========================================
# INLINED COPPERSMITH IMPLEMENTATION (FIXED)
# ==========================================
def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    if isinstance(f, Polynomial):
        x, = polygens(f.base_ring(), f.variable_name(), 1)
        f = f(x)

    R = f.base_ring()
    N = R.cardinality()

    # Normalize the polynomial
    # We divide by the coefficient of the leading term to make it monic-ish
    # or just pick the constant term if monic is hard.
    # For this attack, just ensuring integer coefficients is key.
    
    # f /= f.coefficients().pop(0) # This can be risky if coeffs are tricky
    # Let's just convert to ZZ directly if possible, or clear denominators
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        # FIXED: Use ** instead of ^
        base = N**(m-i) * f**i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    print(f"[*] Lattice dimension: {B.nrows()}x{B.ncols()}")
    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots

    return []

# ==========================================
# MAIN SOLVER
# ==========================================
def solve():
    # Challenge Constants
    N = 3333577291839009732612693330613476891341287017491683764014849337158389717338712200133085615150269196268856288361865352673921704626130772582853528604556994221890454520933132803888321775335519781063447756692130742361931522856942232406992357982482263472763363458621836220024977864980600979194500121897419553619426163227
    k = 9352039867057736323
    r1 = 10421792656200324147964684790160875926436411483496860422433732508593789212449544620816674407170998779863336939494663076247759140488927744939619406024905901
    r2 = 8806088830734144089522276896226392806947836111998696180055727048752624989402057411311728398322297424598954586424896296000606209022432442660527640463521679
    leak1 = 4266222222502644630611545246271868348722888987303187402827005454059765428769160822475080050046035916876078546634293907218937483241284454918367519709206766322037148585465519188582916280829212776096606923824120883699251868362915920299645
    leak2 = 1176921186497191878459783787148403806360469809421921990427675048480656171919274113895695842508460760829511824635106692634456334400022597605585661597793889066395539405395254174368285751236344600489419240628821864912762242188289636510706

    q = 23520857
    p = N // q
    print(f"[*] p = {p}")

    # Setup Ring
    P = PolynomialRing(Zmod(p), names=['x', 'y'])
    x, y = P.gens()

    A1 = leak1 << 244
    A2 = leak2 << 244
    dr = r1 - r2
    
    # Equation Construction
    f = dr * x * y + (dr * A2 + k) * x + (dr * A1 - k) * y + (dr * A1 * A2 + k * (A1 - A2))
    
    bounds = (2**244, 2**244)
    
    print("[*] Launching Coppersmith attack...")
    roots = small_roots(f, bounds, m=2, d=4)
    
    print(f"[*] Roots found: {roots}")
    
    for delta1, delta2 in roots:
        t1 = int(A1 + delta1)
        try:
            m_val = (k * inverse(t1, p) - r1) % p
            flag = long_to_bytes(int(m_val))
            print(f"\n[+] FLAG: {flag.decode()}")
        except Exception as e:
            pass

if __name__ == "__main__":
    solve()