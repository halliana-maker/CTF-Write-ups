# Pirate's Lost Log - RITSEC CTF 2026 write up
```
Description : Rumors have spread across the seven seas of a legendary pirate's log, hidden not on a physical island, but within the digital currents of the Domain Name System. This log, said to contain the coordinates of a vast buried treasure, was split into fragments and scattered across a secluded zone (linksnsec.stellasec.com) by a cunning old sea dog.

The fragments are concealed within the DNS, each leading to the next like a chain of clues on a treasure map. Our best guess is that the final piece of the puzzle, the one that reveals the treasure's location, will be the longest entry in the entire record, standing out from the rest.

Your mission: navigate the hidden paths within the pirate's domain. Follow the digital breadcrumbs to uncover every fragment. Find the single data record with the longest content to recover the complete log and claim the treasure.

The DNS server responds to TCP only, either query it over TCP or use a public recursive resolver (1.1.1.1, etc) to access it. This challenge is exclusively DNS and not web!
```

## 1. TL;DR

This was a DNS-only challenge where the hidden data lived inside a DNS zone. The zone was DNSSEC-signed, which let us walk the records through `NSEC` responses. By following the chain of next-domain pointers and querying every discovered name for `TXT` data, we found the single longest TXT record in the zone. That record contained the flag payload.

**Flag:** `RS{thebartentersawcaptainjackwalkintothebarwiththeshipswheelaroundhisnutsthebartenderaskedhimwhatwasgoingoncaptainjackrepliedyaaritsdrivingmenuts}`

---

## 2. What Data/File We Have and What Is Special

### What we had
- A challenge domain: `linksnsec.stellasec.com`
- A hint that the data was hidden in DNS, not in a website
- A note that the DNS server responds over TCP only
- A clue that the final piece would be the **longest entry** in the record

### What was special
- This was not a normal web or file-recovery challenge.
- The data was distributed across many DNS names inside a zone.
- The zone was DNSSEC-enabled, which exposed `NSEC` records.
- `NSEC` records reveal the next existing owner name in the zone, so they can be used to walk the record set.
- The challenge strongly implied that one `TXT` record would be longer than the others and would contain the final answer.

### Interactive behavior
There was no normal server-player interaction like:
- forms
- API calls
- uploads
- browsing pages

Instead, the only interaction was via DNS queries:
- `NS` and `SOA` queries to identify the authoritative zone
- `NSEC` queries to walk the zone
- `TXT` queries to extract the hidden content

---

## 3. Problem Analysis

The key observation was that the challenge was entirely DNS-based. That meant the answer would not come from page content or source code, but from records in the zone itself.

The first step was to identify the authoritative DNS server for the challenge domain. Querying the zone showed:

- `linksnsec.stellasec.com` had an `NS` record pointing to `linksnsecns.stellasec.com`
- That name resolved to `linksnsec.ctf.ritsec.club`
- The authoritative server was reachable at `129.21.21.95`

Once the zone was identified, the next useful clue came from DNSSEC:
- The zone returned `NSEC` records
- An `NSEC` record gives the next domain name in canonical order
- That makes it possible to walk the entire zone, even if names are not guessable

So the problem reduced to:
1. Discover all owner names in the zone by following `NSEC`
2. Query each name for `TXT`
3. Find the record with the longest content
4. Use that content as the flag payload

---

## 4. Initial Guesses / First Try

At first, it was tempting to treat this as a web challenge or a simple TXT lookup problem. That did not work because:
- the challenge explicitly said it was **not web**
- the DNS server only responded properly over TCP
- the data was not exposed through a single obvious record

The next instinct was to try:
- `ANY` queries
- standard lookups against the public resolver
- direct lookups of the zone apex

Those were not enough. The breakthrough came from querying `NSEC`, which showed that the zone was signed and walkable.

Example discovery:
- Querying `NSEC` at the apex returned a next name like `000n96.linksnsec.stellasec.com`
- Querying that next name returned the next owner, and so on

That confirmed the zone could be enumerated systematically.

---

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Find the authoritative server

We first queried the domain’s `NS` and `SOA` records:

```bash
Resolve-DnsName linksnsec.stellasec.com -Type NS -Tcp -Server 1.1.1.1
Resolve-DnsName linksnsec.stellasec.com -Type SOA -Tcp -Server 1.1.1.1
```

This revealed the authoritative nameserver chain and pointed us to the actual DNS host behind the challenge.

### Step 2: Confirm DNSSEC walking was possible

Querying `NSEC` showed a next-domain pointer:

```bash
Resolve-DnsName linksnsec.stellasec.com -Type NSEC -Tcp -Server 129.21.21.95
```

The response included a `NextDomainName`, which meant we could walk the zone record by record.

### Step 3: Automate the zone walk

A small TCP DNS client was used to:
- send `NSEC` queries
- read the `NextDomainName`
- continue to the next owner
- repeat until the chain looped back

This discovered over a thousand owner names in the zone.

### Step 4: Query `TXT` for every discovered name

After enumerating the names, each one was queried for `TXT` data over TCP.

The records were compared by content length, and the longest one stood out clearly.

The longest TXT record was found at:

- `67ljie.linksnsec.stellasec.com`

Its content was:

```text
thebartentersawcaptainjackwalkintothebarwiththeshipswheelaroundhisnutsthebartenderaskedhimwhatwasgoingoncaptainjackrepliedyaaritsdrivingmenuts
```

### Step 5: Recover the flag

Wrapping the longest TXT payload in the required flag format gave:

```text
RS{thebartentersawcaptainjackwalkintothebarwiththeshipswheelaroundhisnutsthebartenderaskedhimwhatwasgoingoncaptainjackrepliedyaaritsdrivingmenuts}
```

---

## 6. What We Learned

- DNS can be used as a data store, not just a naming system.
- DNSSEC `NSEC` records can expose the structure of a zone and allow full enumeration.
- When a challenge says “TCP only,” the server may intentionally be blocking or ignoring UDP.
- In DNS-heavy CTFs, the answer is often hidden in a record type rather than in a web response.
- The “longest record” clue was a strong hint that the flag would be the largest `TXT` payload in the zone.

