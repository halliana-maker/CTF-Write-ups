# Flags KashiCTF 2026 Write-Up

## 1. TL;DR

The challenge was a locked CTFd page protected by a server-side time check.  
The key flaw was that the server trusted a client-controlled request header, `X-Time`, as the current time. By sending a future GMT timestamp in that header, the lock was bypassed and the flag was returned directly.

**Flag:**

```text
kashiCTF{71m3_byp455_w45_fun_19_B6HVLLYY}
```

***

## 2. Challenge Files & Setup

**What was provided:**

- A live web instance:
  - `http://34.126.223.46:19201`
- No source code, no downloadable files, and no local artifact to analyze.

**What was special:**

- The homepage showed a countdown like:
  - `Challenge Locked`
  - `Opens in ~582 minutes`
- The `/flag` route existed, but instead of serving the flag it said:
  - `This page may have the flag, try asking a robot!`
- The site looked like a normal CTFd deployment, so the challenge was about finding a logic flaw in the web app rather than breaking crypto or parsing a file.

**Interaction model:**

- The player could only interact with the server through HTTP requests.
- There was no obvious form, upload, or input field on the page.
- The important part was to discover what part of the request the server trusted.

***

## 3. Problem Analysis

### First observation

The root page was not static.  
Its remaining time changed between requests, which meant the page was computing the lock condition dynamically.

That immediately suggested one of these:

- hidden route protection,
- a bot-only workflow,
- or a time-based access check using request metadata.

### The important clue

The challenge name was `Flags`, but the page itself said to “ask a robot”. That looked like a distraction.  
The actual issue was not the bot hint, but the time lock.

Because the page said `Opens in ~XXX minutes`, the server was clearly checking a “current time” value somewhere. If that value could be influenced by the client, the lock could be bypassed.

### What I checked

I tested the usual web bypasses:

- guessed routes like `/flag`, `/flags`, `/admin`, `/source`
- host header tricks like `Host: localhost`
- proxy headers like:
  - `X-Forwarded-For`
  - `X-Real-IP`
  - `Forwarded`
- standard date headers:
  - `Date`
  - `If-Modified-Since`
  - `Last-Modified`
  - `Expires`
- query parameters like `?time=`, `?flag=`, `?unlock=`

None of those changed the lock.

That meant the server was not using the usual headers or path tricks.

***

## 4. Initial Attempts

### Attempt 1: Route guessing

I tried a broad route sweep:

- `/flag`
- `/flags`
- `/admin`
- `/login`
- `/source`
- `/api`
- `/robots.txt`
- `/package.json`

Everything returned `404`, except the homepage and `/flag`.

This told me the solution was not exposed as a hidden route.

### Attempt 2: Proxy/header bypass

I tested the common IP-related headers:

- `X-Forwarded-For`
- `X-Real-IP`
- `Forwarded`
- `X-Original-URL`
- `X-Rewrite-URL`

No effect.

### Attempt 3: Time header probing

Since the page was time-locked, I tried several time-related headers.

Most had no effect, but one did:

- `X-Time`

This was the first header that changed the displayed countdown.

That was the breakthrough.

***

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Confirm `X-Time` is trusted

When I sent a future timestamp in `X-Time`, the countdown decreased dramatically.

Example:

```bash
curl -H "X-Time: Fri, 03 Apr 2026 18:00:00 GMT" http://34.126.223.46:19201/
```

This changed the countdown from a large value to something much smaller, proving the server was using the header as its clock source.

### Step 2: Push time past the unlock point

Once the page accepted `X-Time`, I set it to a timestamp beyond the unlock boundary:

```bash
curl -H "X-Time: Fri, 03 Apr 2026 23:59:59 GMT" http://34.126.223.46:19201/
```

At that point, the lock disappeared and the flag was returned directly in the response.

### Step 3: Recover the flag

The response contained:

```text
kashiCTF{71m3_byp455_w45_fun_19_B6HVLLYY}
```

***

## 6. What We Learned

| Concept | Takeaway |
| :-- | :-- |
| **Client-trusted time** | Never trust a request header as the source of truth for access control timing |
| **Hidden trust boundary** | A page can look like a simple countdown while actually depending on a security-sensitive server-side check |
| **Header fuzzing** | Nonstandard headers like `X-Time` are worth testing when standard headers fail |
| **CTFd distractions** | A hint like “ask a robot” may be a red herring if the real flaw is simpler |

If you want, I can also turn this into a more polished blog-post version with a slightly more narrative tone, while keeping the same structure.