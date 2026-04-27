# security-breach-ruin - UMDCTF 2026 Write-up
**Challenge Description:**  
> Just like in FNAF, Security Breach was buggy on release.  
> `nc challs.umdctf.io 31338`  
> *Flag format: `UMDCTF{...}`*

## TL;DR

This challenge is a **BREACH-style compression side-channel** over HTTPS.

We are placed inside an internal network with three hosts:

- `10.0.0.1` — admin box
- `10.0.0.2` — HTTPS server
- `10.0.0.3` — our box

The bug is that the server reflects our attacker-controlled `filter` into the same compressed JSON response that also contains the secret flag. The admin browser continuously requests the protected dashboard, so if we can observe the **encrypted response sizes**, we can recover the flag one character at a time.

The core idea is:

1. Submit a chosen `filter`
2. Let the admin request `/api/dashboard`
3. The server compresses a JSON object containing both our input and the flag
4. If our guess matches the next flag characters, compression gets better
5. The HTTPS response becomes slightly smaller
6. Observe packet lengths and recover the flag incrementally

Final flag:

```text
UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}
```

---

## Concept Map

```text
Attacker controls:
POST /api/suggestions  --> latest_suggestion = our chosen string
                                   |
                                   v
Admin repeatedly requests:
GET /api/dashboard  (authenticated, every ~50ms)
                                   |
                                   v
Server builds response:
{"filter":"<our input>","flag":"<secret flag>"}
                                   |
                                   v
Server compresses response (gzip / br / deflate)
                                   |
                                   v
If our guess matches the flag prefix,
compression becomes slightly better
                                   |
                                   v
Compressed response is slightly shorter
                                   |
                                   v
Even though TLS hides contents, packet sizes still leak information
                                   |
                                   v
Recover the flag character by character
```

---

## What data/file we have and what is special

### Challenge description

> Just like in FNAF, Security Breach was buggy on release.

We connect with:

```bash
nc challs.umdctf.io 31338
```

After connecting, we land in a restricted shell inside the internal network.

### Initial interactive environment

The first useful interaction was:

```bash
player@insider-market:~$ ls -la
total 8
drwxrwxrwt 2 player player   60 Apr 25 10:05 .
drwxr-xr-x 3 root   root   4096 Apr 25 01:29 ..
-rw-r--r-- 1 player player 1389 Apr 25 10:05 notes.md

player@insider-market:~$ cat notes.md
hey. i got this far and then had to drop it. you take it from here.

## what i know

we're on the internal umdmarket network. their admin is a
compulsive insider trader and keeps their private watchlist open in a browser
tab. their browser is literally hammering their own dashboard endpoint on a loop
to get live updates.

## the hosts

- 10.0.0.1 — the admin box. no services listening, just an outbound browser tab.
- 10.0.0.2 — the server. it's https on :443 with a self-signed cert (needs -k).
- 10.0.0.3 — you.

the server has some stuff open to anyone though:

POST /api/suggestions
GET  /api/suggestions/latest
GET  /api/dashboard?filter=X   # admin-only
POST /login
```

### What is special

At first glance, this does **not** look like a normal web challenge where we just log in, inject something obvious, or directly reach the flag.

Instead, the setup strongly suggests:

- we **cannot** directly access the admin dashboard
- the admin already **can** access it
- the admin browser is polling the protected endpoint continuously
- we can influence part of the dashboard response via `POST /api/suggestions`
- the server uses HTTPS, so we cannot read the contents directly
- however, HTTPS does **not** hide packet sizes

That combination is exactly the kind of setup where a **compression side-channel** becomes possible.

---

## Problem Analysis

### Step 1: Identify the trust boundary

The note tells us:

- the admin is polling `/api/dashboard`
- only the admin can access that endpoint
- anyone can submit a suggestion
- anyone can fetch the latest suggestion

So the important question becomes:

**How is the admin-only dashboard response constructed?**

Once the server code was examined, the critical lines were:

```python
DASHBOARD_TEMPLATE = '{{"filter":"{filter}","flag":"{flag}"}}'
```

and inside `/api/dashboard`:

```python
with state_lock:
    q = latest_suggestion
body = DASHBOARD_TEMPLATE.format(filter=q, flag=FLAG).encode()
enc_name, enc_fn = pick_encoding(self.headers.get("Accept-Encoding", ""))
if enc_fn is not None:
    body = enc_fn(body)
self._send(200, body, encoding=enc_name)
```

This means the dashboard response contains:

- attacker-controlled `filter`
- secret `flag`

inside the **same response body**, and that body is then compressed if the client supports it.

That is the vulnerability.

### Step 2: Confirm the admin behavior

The admin code showed:

```python
conn.request(
    "GET", "/api/dashboard",
    headers={
        "Cookie": cookie,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
    },
)
```

and it repeats this request every `0.05` seconds.

So:

- the admin is authenticated
- the admin repeatedly requests the secret-bearing dashboard
- the browser explicitly allows compressed responses
- this creates a steady stream of compressed HTTPS responses

That makes the challenge a textbook **BREACH-style attack**.

### Step 3: Why compression leaks the secret

Suppose the server response looks like:

```json
{"filter":"UMDCTF{s","flag":"UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}"}
```

Compression algorithms work by encoding repeated substrings efficiently.

If our chosen `filter` shares a prefix with the real flag, the compressor sees repetition and can encode the second occurrence more compactly.

So:

- wrong guess → less repeated structure → slightly larger compressed output
- correct guess → more repeated structure → slightly smaller compressed output

Even though TLS encrypts the response body, the **packet lengths** still reveal that size difference.

### Step 4: Why we needed ARP spoofing

One subtle issue is that the admin (`10.0.0.1`) and server (`10.0.0.2`) are talking to each other directly. Our machine is `10.0.0.3`.

So just running `tcpdump` normally may not show their traffic.

To solve that, we used **ARP spoofing / MITM**:

- tell the admin that the server IP maps to our MAC address
- tell the server that the admin IP maps to our MAC address
- forward packets so their traffic passes through us
- sniff only the **lengths** of the HTTPS response packets

This gave us visibility into the encrypted traffic sizes without needing to decrypt TLS.

---

## Initial Guesses / First Try

At the beginning, there were several possible directions:

### Guess 1: Login bypass or credential attack

Because `/login` exists and `/api/dashboard` is protected, it was natural to think about:

- weak credentials
- session fixation
- brute force
- direct cookie theft

But the note explicitly said no credentials were available, and the challenge structure strongly emphasized the polling admin browser instead.

So this was not the most promising route.

### Guess 2: SSRF / XSS / request smuggling

Another instinct was to ask:

- can `filter` trigger XSS in the admin browser?
- can we influence the admin into sending us something?
- can we abuse the dashboard query parameter?

But the input validation for `filter` was strict enough to block that:

```python
FILTER_RE = re.compile(r"^[A-Za-z0-9_{}]*$")
```

So we could only use alphanumerics, underscore, and braces. That rules out most script-based payloads immediately.

### Guess 3: Compression oracle

This turned out to be correct.

The important indicators were:

- attacker-controlled input reflected into the secret-bearing response
- authenticated victim repeatedly requests that response
- compression enabled
- TLS blocks contents but not sizes

This is almost the exact pattern of a BREACH vulnerability.

---

## Exploitation Walkthrough / Flag Recovery

### Overview

The exploitation process had four main stages:

1. Gain visibility into admin–server traffic
2. Submit chosen prefixes through `/api/suggestions`
3. Observe the encrypted response sizes
4. Recover the flag one character at a time

---

### 1. Confirm the challenge behavior

We first identified:

- the server is `10.0.0.2:443`
- the admin is continuously requesting `/api/dashboard`
- the dashboard includes both our `filter` and the real `flag`
- compression is enabled

At this point, the attack model was clear.

---

### 2. Become a man-in-the-middle for packet-size observation

Direct sniffing did not initially show the admin–server packets, because that traffic was not routed through our box.

So the solver:

- discovered the correct network interface
- learned the MAC address of the admin and server via ARP
- sent forged ARP replies to both sides
- enabled packet forwarding
- sniffed raw Ethernet frames
- extracted the TCP payload lengths for server → admin HTTPS responses

We did **not** need to decrypt TLS. The packet sizes alone were enough.

---

### 3. Submit controlled probes

The server stores the latest suggestion globally, so each request to:

```http
POST /api/suggestions
```

changes the `filter` field used in the admin’s future dashboard responses.

The solver repeatedly submitted probes like:

```text
UMDCTF{s
UMDCTF{sa
UMDCTF{sb
UMDCTF{sc
...
```

with padding to keep the total attacker-controlled length constant. Constant length is important because we want the observed difference to come from **compression efficiency**, not from the raw length of the input itself.

So the solver used a helper like:

```python
def make_probe(candidate):
    return "A" * (MAX_FILTER_LEN - len(candidate)) + candidate
```

---

### 4. Score candidates by the small TLS payload

Once traffic was visible, the logs showed a very useful pattern. For example, repeated packets looked like:

```text
214, 214, 107, 107
```

and for the correct guess they became:

```text
214, 214, 106, 106
```

The large packet (`214`) stayed constant. The useful leak was in the **small packet** around `100–110`.

That allowed us to speed up the solve significantly:

- ignore the large constant packet
- score only the smaller response packet
- choose the candidate with the **lowest** small-packet size
- verify only the best few candidates

This made the solver both faster and more stable.

---

### 5. Recover the flag incrementally

The solver began by discovering the early prefix:

```text
UMDCTF{s
```

Then continued character by character until the last step showed:

```text
'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}' score=105
'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_caa' score=107
'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cab' score=107
```

The closing brace `}` produced the best compression result, so it was selected as the final character.

Recovered flag:

```text
UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}
```

---

## Why the attack works

A compact version of the reasoning is:

- the server responds with:
  ```json
  {"filter":"<our input>","flag":"<secret>"}
  ```
- if our input matches the beginning of the flag, the compressor reuses that repeated substring
- repeated substrings compress better
- compressed output becomes smaller
- TLS encrypts bytes, not lengths
- response size becomes a side-channel leak

This is the classic BREACH principle, adapted to an internal polling dashboard.

---

## What We Learned

### 1. HTTPS does not hide everything

Encryption protects contents, but not metadata such as:

- timing
- sizes
- packet counts

That is enough for powerful side-channel attacks.

### 2. Compression and secrets are a dangerous combination

If attacker-controlled data and secret data are compressed together in the same response, secret-dependent size differences can leak information.

This is the key lesson behind BREACH-style bugs.

### 3. “Admin-only” is not automatically safe

Even though we were not allowed to access `/api/dashboard`, the admin continuously accessed it for us. Once we could influence the response and observe its size, we effectively turned the admin into an oracle.

### 4. Network position matters

This challenge also highlights the importance of the network layer:

- application-layer vulnerability: unsafe compression of mixed secret + attacker input
- network-layer technique: ARP spoofing to observe encrypted packet sizes

The final solve required combining both.

### 5. Small observations can matter

The breakthrough came from noticing that the useful leak was not the overall median but the smaller TLS payload:

- wrong guess → small packet `107`
- correct guess → small packet `106`
- final brace → even smaller `105`

That one-byte difference was enough to recover the flag.

---

## Final Answer

```text
UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}
```
