# hash-based - plfanzen CFT 2026 Writeup

> **Description:**  
> Horst from our team build this signature scheme. Can you break it?    
> `ncat --ssl-verify chal-1024-hash-based-537f0a1af597.plfanzen.garden 443`
---

## TL;DR

The service implements a hash-based signature scheme where every message deterministically maps to a set of leaf indexes:

```python
vi = f(SHA256(b"MESG" + message))
```

A valid signature reveals secret leaf values for the indexes required by that message. Because the server lets us request multiple signatures, we can search for several harmless messages whose required leaf indexes cover the target message's required indexes.

Our target message was:

```text
gimme flag pls|6892940
```

It required these target indexes:

```text
[100, 115, 179, 200, 316, 434, 1025, 1074, 1185, 1195, 1430, 1586]
```

By asking the server to sign three chosen messages, we leaked all required target leaves:

```text
sign|1150070
sign|2085463
sign|19770698
```

After combining the leaked leaf secrets and Merkle authentication data, we forged a signature for the target message and received the flag.

---

## What Data / Files We Have and What Is Special

We had a local solver script:

```text
solve.py
```

The solver interacted with the service over TLS and requested signatures for attacker-chosen messages. The important part was that signatures exposed reusable material from the hash-based signing key.

A normal interaction looked conceptually like this:

```text
player -> server: ask server to sign a message
server -> player: returns signature containing leaf secrets and Merkle proofs

player -> server: submit forged signature for privileged target message
server -> player: verifies forged signature and prints flag
```

The successful run showed:

```text
[*] target = b'gimme flag pls|6892940'
[*] target vi = [100, 115, 179, 200, 316, 434, 1025, 1074, 1185, 1195, 1430, 1586]

[+] signed b'sign|1150070', len=3840, vi=[41, 63, 115, 167, 237, 453, 719, 807, 929, 1025, 1185, 1272, 1586, 1655, 1857, 1990]

[+] signed b'sign|2085463', len=3552, vi=[179, 303, 434, 455, 489, 964, 1195, 1225, 1244, 1430, 1459, 1489, 1599, 1666, 1693, 1706]

[+] signed b'sign|19770698', len=3712, vi=[95, 100, 176, 200, 316, 345, 384, 563, 751, 935, 1074, 1401, 1488, 1494, 1522, 1928]

[+] missing target leaves after 3 signatures: []
[+] forged signature length = 2752
plfanzen{app4r3ntly_thr3e_time5_is_n0t_few_t1mes}
```

The special point is this line:

```text
[+] missing target leaves after 3 signatures: []
```

That means every leaf needed to sign the target message was already leaked by the three legitimate signatures.

---

## Concept Map

```mermaid
flowchart TD
    A[Target message: gimme flag pls\|6892940] --> B[Compute deterministic vi indexes]
    B --> C[Target needs 12 leaf indexes]

    D[Ask server to sign harmless messages] --> E[Signature leaks secret leaves]
    E --> F[Collect known leaves and Merkle proofs]

    G[Offline search for useful messages] --> H[Find messages whose vi sets cover target vi]
    H --> D

    C --> I{Do collected leaves cover all target indexes?}
    F --> I

    I -- No --> G
    I -- Yes --> J[Assemble forged signature]
    J --> K[Submit forged signature to server]
    K --> L[Server verifies target signature]
    L --> M[Flag printed]
```

---

## Problem Analysis In Detail

The challenge is based on a hash-based signature construction. In this type of scheme, a message does not get signed by ordinary RSA/ECDSA-style arithmetic. Instead, the message is hashed, and the hash determines which secret values from a large one-time signing structure are revealed.

The important behavior was:

```python
vi = f(SHA256(b"MESG" + message))
```

For every message, the signer computes a deterministic list of indexes `vi`. To sign the message, the signer reveals secret values corresponding to those indexes. The verifier hashes those secret values and checks them against a Merkle tree root using authentication paths.

This design is only safe if each signing key is used carefully. If the same hash-based signing key is reused across many different messages, each signature leaks more secret leaf values. After enough signatures, an attacker may collect enough leaked leaves to forge a new message.

The target message was:

```python
target = b"gimme flag pls|6892940"
```

Its required indexes were:

```python
target_vi = [
    100, 115, 179, 200,
    316, 434, 1025, 1074,
    1185, 1195, 1430, 1586
]
```

To forge the target, we needed valid secret leaf values for all of those indexes.

The trick was not to brute-force the signature itself. Instead, we searched for normal signable messages whose `vi` lists overlap with the target `vi`. Once we found enough messages whose combined indexes cover the target indexes, the forge became mechanical.

The three useful messages were:

```python
b"sign|1150070"
b"sign|2085463"
b"sign|19770698"
```

Their index sets were:

| Message | Useful target indexes leaked |
|---|---|
| `sign|1150070` | `115, 1025, 1185, 1586` |
| `sign|2085463` | `179, 434, 1195, 1430` |
| `sign|19770698` | `100, 200, 316, 1074` |

Together, they cover the full target set:

```text
target vi:
100, 115, 179, 200, 316, 434, 1025, 1074, 1185, 1195, 1430, 1586

covered by signatures:
100, 115, 179, 200, 316, 434, 1025, 1074, 1185, 1195, 1430, 1586
```

No target leaf was missing.

---

## Exploitation Walkthrough / Flag Recovery

First, choose a target message. The solver found this target:

```python
target = b"gimme flag pls|6892940"
```

The suffix `|6892940` is useful because the message-to-index mapping is deterministic. By changing the suffix, we can search for a target variant whose required indexes are easier to cover using allowed signed messages.

The target indexes were:

```python
[100, 115, 179, 200, 316, 434, 1025, 1074, 1185, 1195, 1430, 1586]
```

Then the solver requested signatures for three allowed messages.

First signed message:

```text
sign|1150070
```

Returned indexes:

```text
[41, 63, 115, 167, 237, 453, 719, 807, 929, 1025, 1185, 1272, 1586, 1655, 1857, 1990]
```

This leaked target leaves:

```text
115, 1025, 1185, 1586
```

Second signed message:

```text
sign|2085463
```

Returned indexes:

```text
[179, 303, 434, 455, 489, 964, 1195, 1225, 1244, 1430, 1459, 1489, 1599, 1666, 1693, 1706]
```

This leaked target leaves:

```text
179, 434, 1195, 1430
```

Third signed message:

```text
sign|19770698
```

Returned indexes:

```text
[95, 100, 176, 200, 316, 345, 384, 563, 751, 935, 1074, 1401, 1488, 1494, 1522, 1928]
```

This leaked target leaves:

```text
100, 200, 316, 1074
```

After collecting these signatures, the solver checked whether any target leaves were still missing:

```text
[+] missing target leaves after 3 signatures: []
```

At this point, the solver had all private leaf values needed for the target message.

The forged signature was assembled by taking the correct leaked leaf secret for each target index and pairing it with valid Merkle proof data. The resulting forged signature length was:

```text
[+] forged signature length = 2752
```

Finally, the solver submitted the forged signature to the server. The server accepted it as a valid signature for the target message and printed:

```text
plfanzen{app4r3ntly_thr3e_time5_is_n0t_few_t1mes}
```

---

## Why the Attack Works

Hash-based signatures are designed so that revealing a secret value proves ownership of one leaf. However, revealing too many leaves from the same signing key destroys the one-time or few-time security assumption.

In this challenge, every signature leaked several leaf secrets. Because the message-to-index function was deterministic and public, we could compute which indexes each candidate message would reveal before asking the server to sign it.

The attacker's job was therefore:

1. Compute the target message's required indexes.
2. Search for allowed messages with overlapping indexes.
3. Ask the server to sign those messages.
4. Extract leaked leaf secrets.
5. Recombine them into a signature for the forbidden target message.

The cryptographic mistake is key reuse in a hash-based signature setting.

---

## What We Learned

Hash-based signatures are very sensitive to reuse. If a scheme reveals private leaf material during signing, then signing multiple messages with the same key can leak enough material to forge other messages.

The challenge also shows that not every crypto exploit needs to break a hash function. SHA-256 was not broken here. The weak point was the surrounding protocol: deterministic index selection plus repeated signing using the same secret key.

The main CTF lesson is to model the signature as a leakage oracle. Once each signature is viewed as revealing a subset of useful secret leaves, the challenge becomes a coverage problem. The winning condition is not "recover the whole private key"; it is only "recover enough private key material for the target message."

Final flag:

```text
plfanzen{app4r3ntly_thr3e_time5_is_n0t_few_t1mes}
```
