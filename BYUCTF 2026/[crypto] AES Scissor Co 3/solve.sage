#!/usr/bin/env sage -python
# AES Scissor Co 3 solver: AES-GCM nonce reuse / forbidden attack
# Usage: sage -python solve_aes_scissor_co_3.sage https://aes.chals.cyberjousting.com

import base64, re, sys, time
from collections import defaultdict
import requests

if len(sys.argv) >= 2:
    BASE = sys.argv[1].rstrip('/')
else:
    BASE = 'https://aes.chals.cyberjousting.com'

USERNAME_LEN = 48
NEED_SAME_NONCE = 3


def b64d(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + '=' * ((4 - len(s) % 4) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).decode()


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def build_plain(uid, role, username):
    # Rust serde_json struct field order is id, role, username, with no spaces.
    return (f'{{"id":"{uid}","role":"{role}","username":"{username}"}}').encode()


def split_cookie(cookie):
    raw = b64d(cookie)
    iv = raw[:12]
    body = raw[12:]
    return iv, body[:-16], body[-16:]


def blocks_for_ghash(c):
    out = []
    for i in range(0, len(c), 16):
        out.append(c[i:i+16].ljust(16, b'\x00'))
    out.append((0).to_bytes(8, 'big') + (len(c) * 8).to_bytes(8, 'big'))
    return out


def bitrev_int(n, bits=128):
    return int(f'{n:0{bits}b}'[::-1], 2)




def int_to_field_elem(F, n):
    """Portable replacement for F.fetch_int(n).
    Sage 10.7's NTL GF(2^m) backend may not expose fetch_int, so build the
    polynomial-basis element directly: bit i is the coefficient of a^i.
    """
    n = int(n)
    a = F.gen()
    out = F(0)
    pow_a = F(1)
    while n:
        if n & 1:
            out += pow_a
        n >>= 1
        pow_a *= a
    return out


def field_elem_to_int(e):
    """Portable inverse of int_to_field_elem for polynomial-basis elements."""
    try:
        return int(e.integer_representation())
    except Exception:
        poly = e.polynomial()
        out = 0
        for i, c in enumerate(poly.list()):
            if int(c) & 1:
                out |= 1 << i
        return out

def elem_normal(F, b):
    return int_to_field_elem(F, int.from_bytes(b, 'big'))


def out_normal(e):
    return field_elem_to_int(e).to_bytes(16, 'big')


def elem_bitrev(F, b):
    return int_to_field_elem(F, bitrev_int(int.from_bytes(b, 'big')))


def out_bitrev(e):
    return bitrev_int(field_elem_to_int(e)).to_bytes(16, 'big')


def ghash(F, to_elem, H, c):
    y = F(0)
    for blk in blocks_for_ghash(c):
        y = (y + to_elem(F, blk)) * H
    return y


def recover_candidates(records):
    # Try the two common bit order conventions and two modulus orientations.
    from sage.all import GF, PolynomialRing
    R = PolynomialRing(GF(2), 'z')
    z = R.gen()
    mod_normal = z**128 + z**7 + z**2 + z + 1
    mod_recip  = z**128 + z**127 + z**126 + z**121 + 1
    variants = [
        ('normal/mod_normal', mod_normal, elem_normal, out_normal),
        ('bitrev/mod_normal', mod_normal, elem_bitrev, out_bitrev),
        ('normal/mod_recip',  mod_recip,  elem_normal, out_normal),
        ('bitrev/mod_recip',  mod_recip,  elem_bitrev, out_bitrev),
    ]

    out = []
    r0, r1 = records[0], records[1]
    b0 = blocks_for_ghash(r0['ct'])
    b1 = blocks_for_ghash(r1['ct'])
    assert len(b0) == len(b1), 'use equal-length usernames so ciphertext lengths match'

    for name, modulus, to_elem, from_elem in variants:
        F = GF(2**128, name='a', modulus=modulus)
        PR = PolynomialRing(F, 'x')
        x = PR.gen()
        P = PR(0)
        n = len(b0)
        for i, (aa, bb) in enumerate(zip(b0, b1)):
            P += to_elem(F, bxor(aa, bb)) * (x ** (n - i))
        P += to_elem(F, bxor(r0['tag'], r1['tag']))

        try:
            roots = [root for root, _mult in P.roots()]
        except Exception as e:
            print(f'[-] {name}: root search failed: {e}')
            continue

        print(f'[*] {name}: {len(roots)} candidate H roots')
        for H in roots:
            S = to_elem(F, r0['tag']) + ghash(F, to_elem, H, r0['ct'])
            ok = True
            for r in records:
                if to_elem(F, r['tag']) != S + ghash(F, to_elem, H, r['ct']):
                    ok = False
                    break
            if ok:
                print(f'[+] {name}: candidate validates against all known cookies')
                out.append((name, F, to_elem, from_elem, H, S))
    return out


def register_one(session, username, i):
    data = {'username': username, 'password': 'x'}
    r = session.post(BASE + '/api/register', data=data, allow_redirects=False, timeout=10)
    cookie = r.cookies.get('session')
    if not cookie:
        sc = r.headers.get('Set-Cookie', '')
        m = re.search(r'session=([^;]+)', sc)
        if m:
            cookie = m.group(1)
    if not cookie:
        raise RuntimeError(f'no session cookie, status={r.status_code}, body={r.text[:200]!r}')

    iv, ct, tag = split_cookie(cookie)
    g = session.get(BASE + '/', cookies={'session': cookie}, timeout=10)
    uid = g.headers.get('X-User-ID')
    if not uid:
        raise RuntimeError(f'could not recover UUID from X-User-ID, status={g.status_code}')
    pt = build_plain(uid, 'user', username)
    assert len(pt) == len(ct), (len(pt), len(ct), pt)
    return {'cookie': cookie, 'iv': iv, 'ct': ct, 'tag': tag, 'uid': uid, 'username': username, 'pt': pt, 'idx': i}


def collect_same_nonce():
    session = requests.Session()
    attempt = 0
    while True:
        attempt += 1
        groups = defaultdict(list)
        print(f'[*] collecting cookies, attempt {attempt}')
        # Burst several requests inside the same Unix second. The app nonce is per-second.
        for i in range(12):
            uname = (f'u{attempt:04d}_{i:02d}_' + 'A' * USERNAME_LEN)[:USERNAME_LEN]
            try:
                rec = register_one(session, uname, i)
            except Exception as e:
                print(f'[-] request failed: {e}')
                continue
            groups[rec['iv']].append(rec)
            print(f'    iv={rec["iv"].hex()} group={len(groups[rec["iv"]])} uid={rec["uid"]}')
            if len(groups[rec['iv']]) >= NEED_SAME_NONCE:
                return groups[rec['iv']], session
        # wait for next second to make grouping cleaner
        time.sleep(1.05)


def main():
    records, session = collect_same_nonce()
    print(f'[+] got {len(records)} cookies with same nonce {records[0]["iv"].hex()}')

    candidates = recover_candidates(records)
    if not candidates:
        print('[-] no valid H candidate found. Re-run; if it persists, paste this output.')
        return

    base = records[0]
    desired_username = ('pwned_' + 'B' * USERNAME_LEN)[:USERNAME_LEN - 1]
    forged_pt = build_plain(base['uid'], 'admin', desired_username)
    assert len(forged_pt) == len(base['pt']) == len(base['ct'])

    stream = bxor(base['ct'], base['pt'])
    forged_ct = bxor(stream, forged_pt)

    for name, F, to_elem, from_elem, H, S in candidates:
        forged_tag_elem = S + ghash(F, to_elem, H, forged_ct)
        forged_tag = from_elem(forged_tag_elem)
        forged_cookie = b64e(base['iv'] + forged_ct + forged_tag)
        print(f'[*] trying forged admin cookie with {name}')
        # Important: do not use the session cookie jar here. It already contains
        # a normal user cookie, and requests can prefer/merge it in surprising
        # ways. Send exactly one Cookie header containing the forged value.
        r = requests.get(BASE + '/', headers={'Cookie': 'session=' + forged_cookie}, timeout=10)
        print(f'    status={r.status_code}, len={len(r.text)}')
        m = re.search(r'byuctf\{[^}]+\}', r.text)
        if m:
            print('[+] FLAG:', m.group(0))
            return
        if r.status_code == 200:
            print('[*] HTTP 200 but no flag in body; response snippet follows')
            print(r.text[:5000])
            # This candidate may authenticate but not be the actual admin forge.
            # Continue trying other bit-order candidates.
            continue
        else:
            print(r.text[:300])

    print('[-] all candidates tried, no flag. Paste output and response snippets.')

if __name__ == '__main__':
    main()
