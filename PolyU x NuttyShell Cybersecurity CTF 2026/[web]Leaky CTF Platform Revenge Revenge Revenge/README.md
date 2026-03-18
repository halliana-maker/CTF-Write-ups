# Leaky CTF Platform Revenge Revenge Revenge

**Event:** PolyU x NuttyShell Cybersecurity CTF 2026  
**Category:** Web  
**Author:** siunam  

## TL;DR

This challenge is an intended **XS-Leak timing attack** on an admin-only prefix oracle. The bot sets an `admin_secret` cookie for `localhost`, visits an attacker-controlled page, and that page can force top-level navigations to `http://localhost:5000/search?flag=...`, which includes the `SameSite=Lax` cookie on navigation requests. [web](https://web.dev/articles/samesite-cookies-explained)

The vulnerable endpoint checks `any(f for f in flags if f.startswith(flag))`, and because the real internal flag is stored before a huge list of spammed fake flags, a correct prefix returns much faster than a wrong prefix. By repeatedly measuring navigation timing, we can recover the internal flag `leakyctf{4c2c16f0}`, then submit it to `/submit_flag` to obtain the real flag.

***

## Problem Analysis

The application exposes several routes:

- `/search`
- `/spam_flags`
- `/submit_flag`
- `/report`

The key logic is in `/search`:

```python
@app.route('/search')
def search():
    if request.cookies.get('admin_secret', '') != config.ADMIN_SECRET:
        return 'Access denied. Only admin can access this endpoint.', 403

    flag = request.args.get('flag', '')
    if not flag:
        return 'Invalid flag', 400

    foundFlag = any(f for f in flags if f.startswith(flag))
    if not foundFlag:
        return 'Your flag was not found in our key-value store.', 200

    return 'Your flag was found in our key-value store!', 200
```

At first glance, `/search` looks unreachable because it requires the admin cookie.  
However, the bot visits any URL submitted to `/report`, and before visiting it, the bot sets:

```python
await context.add_cookies([{
    'name': 'admin_secret',
    'value': ADMIN_SECRET,
    'domain': BOT_CONFIG['APP_DOMAIN'],
    'path': '/',
    'httpOnly': True,
    'sameSite': 'Lax',
}])
```

Since `BOT_CONFIG['APP_DOMAIN'] = 'localhost'`, the bot holds the sensitive cookie for `localhost`.  
That means if our page can make the bot navigate to `http://localhost:5000/search?...`, the request will carry the admin cookie because `SameSite=Lax` cookies are sent on top-level navigations. [web](https://web.dev/articles/samesite-cookies-explained)

The second important point is the data structure:

```python
flags = [config.CORRECT_FLAG]
```

and later:

```python
for _ in range(size):
    flags.append(f'{config.SIMUATION_FLAG_PREFIX}{{{secrets.token_hex(config.RANDOM_HEX_LENGTH)}}}')
```

So the real internal flag is inserted first, and fake flags are appended afterward.  
This matters because `/search` uses:

```python
any(f for f in flags if f.startswith(flag))
```

If our prefix is correct, the generator matches immediately on the very first element.  
If our prefix is wrong, Python must scan through the whole list before returning false.

That creates a timing side channel.

### Why this is an XS-Leak

We still cannot directly read `/search` responses from our attacker origin because the page is cross-origin, and the browser’s same-origin policy prevents arbitrary cross-origin DOM/response access. [developer.mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy)
So the intended path is not “read the text and compare found/not found,” but to observe a side effect — in this case, how long it takes for a popup to become cross-origin after navigation.

### Why `/spam_flags` matters

The route `/spam_flags` lets us append up to nearly one million fake flags.  
That greatly increases the runtime difference between:

- **correct prefix** → immediate hit on the first element
- **wrong prefix** → full scan across a huge list

So `/spam_flags` is effectively the amplifier for the timing oracle.

***

## Early guesses

My first guesses were the usual web directions:

- maybe SSRF through `/report`
- maybe some way to read `localhost`
- maybe some template/client-side issue
- maybe a way to bypass Turnstile
- maybe some unintended local network trick

But the challenge author explicitly asked us not to use unintended solutions, and the bot even launches Chromium with `--disable-features=LocalNetworkAccessChecks`, suggesting that local-network-related weirdness had already been considered by the author.  
That pushed me back toward a more deliberate intended design: the bot has a `localhost` admin cookie, and `/search` is a prefix oracle.

Once I noticed `flags = [config.CORRECT_FLAG]` and `any(...startswith(...))`, the intended leak became much clearer.  
The route was not giving me a boolean directly, but it was definitely giving me a timing distinction.

***

## First try

My first attempt was too ambitious: I tried to recover the entire 8-hex internal flag in one bot visit.

The idea was:

1. Open a popup from my attacker page.
2. Repeatedly navigate that popup to:
   - a same-origin blank page
   - `http://localhost:5000/search?flag=<candidate>`
3. Measure how long it takes until access to `popup.location.href` throws, which indicates that the page has crossed origin.
4. Use that timing as the score for each candidate nibble.

The logic itself was correct, but the implementation failed in practice.

### What went wrong

A full round for one nibble already takes a lot of time:

- 16 candidate hex characters
- each candidate needs a hit/miss measurement
- some candidates need re-testing because of noise
- the bot only sleeps for about 60 seconds after `page.goto(...)`

So trying to brute-force all 8 nibbles in a single visit was simply too slow.  
I could see this from the logs: even the first nibble consumed almost the entire visit window.

I also briefly considered whether I could avoid per-nibble brute force by somehow reading the returned text from `/search`, for example distinguishing:

- `Your flag was found in our key-value store!`
- `Your flag was not found in our key-value store.`

But that path is blocked by the browser security model: cross-origin windows do not give arbitrary response-body access, and `fetch()`/XHR cannot read cross-origin bodies without permissive CORS headers. [developer.mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
So the challenge really does want the timing oracle.

***

## Flag Recovery

The successful approach was to turn the exploit into a **supervisor-style solver**:

1. Fill `flags` to the maximum using `/spam_flags`.
2. Submit an attacker page to `/report`.
3. Solve Turnstile once for that report.
4. Recover **one nibble only** during that bot visit.
5. Save the recovered prefix locally.
6. Repeat automatically in the same Python program until the internal flag is complete.
7. Submit the recovered internal flag to `/submit_flag`.

### Why multiple reports were necessary

Turnstile requires a token that is validated server-side, and the token is short-lived and single-use. [developers.cloudflare](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
That means each new `/report` request needs a fresh token, so fully unattended “one-click forever” automation is not realistic without outsourcing the CAPTCHA-solving step.

The compromise was still good enough: one Python process handled the whole workflow, while each round only needed me to solve one fresh Turnstile challenge.

### Timing strategy

For each position, I tested all 16 hex candidates:

```text
prefix + 0
prefix + 1
...
prefix + f
```

For each candidate, I measured:

- `hit = time(prefix)`
- `miss = time(prefix + "!")`
- `delta = miss - hit`

If the prefix is correct, `hit` should be much smaller because `/search` stops immediately at the first real flag.  
If the prefix is wrong, both timings are similar, or noise may even make the delta negative.

So the winning nibble is the one with the **largest positive delta**.

### Example from the solve

For the first nibble, I got:

```text
rank1 4:33.20, f:20.30, 9:4.60, 6:3.90, a:3.90, ...
winner nibble=4
```

That is a very strong signal.  
A delta of `33.20` is much larger than the rest, so `4` was the right first nibble.

The later rounds gave:

- `4`
- `c`
- `2`
- `c`
- `1`
- `6`
- `f`
- `0`

which recovered the internal flag:

```text
leakyctf{4c2c16f0}
```

Then I submitted:

```http
GET /submit_flag?flag=leakyctf{4c2c16f0}
```

and obtained the real flag:

```text
PUCTF26{Please_do_not_use_an_unintended_solution_to_solve_this_challenge_xddd_B4zcqTrZIbokHErpfzVtzUWw5d7we7NU}
```

***

## Result and what we learn

This challenge is a nice example of how “safe-looking” components can become dangerous when combined:

- an admin-only endpoint
- a bot that visits attacker-controlled pages
- a sensitive cookie bound to `localhost`
- `SameSite=Lax`
- a prefix check with short-circuit behavior
- an attacker-controlled way to massively amplify the slow path

Individually, each piece may look harmless.  
Together, they form a very clean intended XS-Leak.

### Main lessons

- **Timing differences are enough.**  
  You do not need direct response-body access if the target leaks via computation time.

- **Short-circuit checks are dangerous.**  
  `startswith()` plus `any()` on attacker-controlled input can become a prefix oracle immediately.

- **Bots are attack surfaces.**  
  If a bot has privileged state and can visit attacker pages, then browser behavior itself becomes part of the threat model.

- **SameSite is not a silver bullet.**  
  `SameSite=Lax` still allows cookies on top-level navigations, which is exactly what made this intended solve work. [web](https://web.dev/articles/samesite-cookies-explained)

- **Operational friction matters.**  
  Turnstile successfully prevented a trivial no-user-interaction exploit flow because every `/report` submission required a fresh validated token. [developers.cloudflare](https://developers.cloudflare.com/turnstile/turnstile-analytics/token-validation/)

***

## Minimal exploit idea

The core browser-side primitive was basically:

```javascript
const win = window.open("/blank", "probe");

async function probe(prefix) {
  win.location = "/blank";
  await waitAccessible(win);

  const t0 = performance.now();
  win.location = "http://localhost:5000/search?flag=" + encodeURIComponent(prefix);

  while (true) {
    try {
      void win.location.href;
    } catch (e) {
      return performance.now() - t0;
    }
    await sleep(1);
  }
}
```

The key observation is:

- while the popup is same-origin, I can read `win.location.href`
- once it finishes navigating to `http://localhost:5000/...`, it becomes cross-origin and property access throws
- the time until that transition correlates with how quickly `/search` answered

That single primitive is enough to build the whole solver.

***

## Short conclusion

The intended solution was an XS-Leak timing oracle against `/search`, amplified via `/spam_flags` and enabled by the bot’s `localhost` admin cookie.  
The recovered internal flag was `leakyctf{4c2c16f0}`, which led to the final flag `PUCTF26{Please_do_not_use_an_unintended_solution_to_solve_this_challenge_xddd_B4zcqTrZIbokHErpfzVtzUWw5d7we7NU}`.


## Notes
I didn't solve this challenge myself :(       
My teammate solved it at a terrifying speed  ￣へ￣

Well, I just wrote an automated script to solve it after the CTF ended.  
Automation is great!

You can check out my teammate's write-up; it is more detailed than mine   
[my teammate's write-up](https://github.com/TaokyleYT/CTF_Writeups/tree/main/PUCTF26-HelloWorld/Leaky_CTF_Platform_Revenge_Revenge_Revenge)