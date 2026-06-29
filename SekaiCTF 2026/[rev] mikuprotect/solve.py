#!/usr/bin/env python3
"""Automatic solver for SEKAI CTF 2026 `mikuprotect`.

Remote usage:
    python3 solve.py
    python3 solve.py mikuprotect.chals.sekai.team 1337

Local captured-round usage:
    python3 solve.py --local mikuprotect_capture.zip
"""
from __future__ import annotations

import argparse
import ast
import itertools
import math
import os
import re
import shlex
import socket
import struct
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def ensure_dependencies() -> None:
    try:
        import unicorn  # noqa: F401
        import pefile  # noqa: F401
        import capstone  # noqa: F401
        return
    except ImportError:
        pass

    print("[*] Installing Python dependencies: unicorn pefile capstone", flush=True)
    cmd = [sys.executable, "-m", "pip", "install", "-q", "unicorn", "pefile", "capstone"]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            "Dependency installation failed. Run:\n"
            f"  {shlex.join(cmd)}\n"
            "then rerun this solver."
        ) from exc


ensure_dependencies()

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MEM_READ,
    UC_MODE_64,
    UC_PROT_ALL,
)
from unicorn.x86_const import (
    UC_X86_REG_EFLAGS,
    UC_X86_REG_GS_BASE,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

DEFAULT_HOST = "mikuprotect.chals.sekai.team"
DEFAULT_PORT = 1337
STACK_TOP = 0x100000000
STACK_SIZE = 0x100000
STUB_BASE = 0x30000000
SENTINEL = 0x200000000
TEB_BASE = 0x7FFDE000
MASK64 = (1 << 64) - 1


class SolveError(RuntimeError):
    pass


def log(message: str) -> None:
    print(message, flush=True)


class Remote:
    def __init__(self, host: str, port: int, timeout: float = 25.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv_exact(self, count: int) -> bytes:
        while len(self.buf) < count:
            chunk = self.sock.recv(min(1 << 20, count - len(self.buf)))
            if not chunk:
                raise EOFError(f"connection closed with {count - len(self.buf)} bytes missing")
            self.buf.extend(chunk)
        out = bytes(self.buf[:count])
        del self.buf[:count]
        return out

    def recv_until(self, marker: bytes, max_bytes: int = 16 << 20) -> bytes:
        while True:
            pos = self.buf.find(marker)
            if pos >= 0:
                end = pos + len(marker)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if len(self.buf) > max_bytes:
                raise SolveError(f"receive buffer exceeded limit waiting for {marker!r}")
            chunk = self.sock.recv(65536)
            if not chunk:
                partial = bytes(self.buf)
                self.buf.clear()
                raise EOFError(
                    f"connection closed while waiting for {marker!r}; trailing data:\n"
                    + partial[-2000:].decode("utf-8", "replace")
                )
            self.buf.extend(chunk)

    def recv_to_eof(self, idle_timeout: float = 10.0) -> bytes:
        chunks = [bytes(self.buf)]
        self.buf.clear()
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(idle_timeout)
        try:
            while True:
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            self.sock.settimeout(old_timeout)
        return b"".join(chunks)


POW_TOKEN_RE = re.compile(rb"(?<!\S)(s\.[A-Za-z0-9_+/=-]+\.[A-Za-z0-9_+/=-]+)(?=\s|$)")


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def solve_pow(token: str) -> str:
    candidates: list[str] = []
    found = shutil_which("redpwnpow")
    if found:
        candidates.append(found)
    cache = Path.home() / ".cache" / "redpwnpow"
    if cache.is_dir():
        candidates.extend(str(p) for p in sorted(cache.glob("redpwnpow-*")) if os.access(p, os.X_OK))

    for exe in dict.fromkeys(candidates):
        try:
            proc = subprocess.run(
                [exe, token], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=240,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if proc.returncode == 0 and lines:
            return lines[-1]

    command = f"curl -sSfL https://pwn.red/pow | sh -s {shlex.quote(token)}"
    proc = subprocess.run(
        ["bash", "-lc", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=300,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if proc.returncode != 0 or not lines:
        raise SolveError("proof-of-work solver failed:\n" + proc.stderr[-2000:] + "\nCommand: " + command)
    return lines[-1]


GREGS = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
    "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
    "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9,
    "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
    "rip": UC_X86_REG_RIP, "eflags": UC_X86_REG_EFLAGS,
}

ALIASES: dict[str, str] = {}
for _family, _names in {
    "rax": ["rax", "eax", "ax", "al", "ah"],
    "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
    "rcx": ["rcx", "ecx", "cx", "cl", "ch"],
    "rdx": ["rdx", "edx", "dx", "dl", "dh"],
    "rsi": ["rsi", "esi", "si", "sil"],
    "rdi": ["rdi", "edi", "di", "dil"],
    "rbp": ["rbp", "ebp", "bp", "bpl"],
    "rsp": ["rsp", "esp", "sp", "spl"],
    "r8": ["r8", "r8d", "r8w", "r8b"],
    "r9": ["r9", "r9d", "r9w", "r9b"],
    "r10": ["r10", "r10d", "r10w", "r10b"],
    "r11": ["r11", "r11d", "r11w", "r11b"],
    "r12": ["r12", "r12d", "r12w", "r12b"],
    "r13": ["r13", "r13d", "r13w", "r13b"],
    "r14": ["r14", "r14d", "r14w", "r14b"],
    "r15": ["r15", "r15d", "r15w", "r15b"],
}.items():
    for _name in _names:
        ALIASES[_name] = _family


def family(name: str) -> str:
    return ALIASES.get(name, name)


def reg_snapshot(uc: Uc) -> dict[str, int]:
    return {name: uc.reg_read(reg) for name, reg in GREGS.items()}


def subreg_value(name: str, state: dict[str, int]) -> int:
    fam = family(name)
    value = state[fam]
    if name.startswith("e") or (name.startswith("r") and name.endswith("d")):
        return value & 0xFFFFFFFF
    if name in {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"} or name.endswith("w"):
        return value & 0xFFFF
    if name in {"al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl"} or name.endswith("b"):
        return value & 0xFF
    if name in {"ah", "bh", "ch", "dh"}:
        return (value >> 8) & 0xFF
    return value & MASK64


def map_engine(raw: bytes) -> tuple[pefile.PE, int, Uc, dict[int, str]]:
    pe = pefile.PE(data=raw, fast_load=False)
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    image_size = (int(pe.OPTIONAL_HEADER.SizeOfImage) + 0xFFF) & ~0xFFF

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, image_size, UC_PROT_ALL)
    headers = raw[: int(pe.OPTIONAL_HEADER.SizeOfHeaders)]
    uc.mem_write(base, headers)
    for section in pe.sections:
        data = section.get_data()
        if data:
            uc.mem_write(base + int(section.VirtualAddress), data)

    uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
    rsp = STACK_TOP - 0x1000
    uc.mem_map(SENTINEL, 0x1000, UC_PROT_ALL)
    uc.mem_write(SENTINEL, b"\xf4")
    uc.mem_write(rsp, struct.pack("<Q", SENTINEL))

    for reg, value in (
        (UC_X86_REG_RSP, rsp), (UC_X86_REG_RBP, 0),
        (UC_X86_REG_RCX, 1), (UC_X86_REG_RDX, 0),
        (UC_X86_REG_R8, 0), (UC_X86_REG_RIP, base + 0x1000),
    ):
        uc.reg_write(reg, value)

    uc.mem_map(TEB_BASE, 0x4000, UC_PROT_ALL)
    uc.mem_write(TEB_BASE + 0x30, struct.pack("<Q", TEB_BASE))
    uc.mem_write(TEB_BASE + 0x60, struct.pack("<Q", TEB_BASE + 0x2000))
    uc.reg_write(UC_X86_REG_GS_BASE, TEB_BASE)

    uc.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL)
    api: dict[int, str] = {}
    stub_index = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                address = STUB_BASE + stub_index * 0x10
                stub_index += 1
                name = imp.name.decode("ascii", "replace") if imp.name else str(imp.ordinal)
                api[address] = name
                uc.mem_write(address, b"\xc3")
                uc.mem_write(int(imp.address), struct.pack("<Q", address))
    return pe, base, uc, api


def return_api(uc: Uc, value: int = 0) -> None:
    uc.reg_write(UC_X86_REG_RAX, value & MASK64)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    return_address = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    uc.reg_write(UC_X86_REG_RIP, return_address)


def handle_api(uc: Uc, name: str, base: int) -> None:
    rcx = uc.reg_read(UC_X86_REG_RCX)
    if name in {"GetCurrentProcessId", "GetCurrentThreadId"}:
        return_api(uc, 1234)
    elif name == "GetModuleHandleW":
        return_api(uc, base)
    elif name == "GetSystemTimeAsFileTime":
        try:
            uc.mem_write(rcx, struct.pack("<Q", 0x01DC000000000000))
        except UcError:
            pass
        return_api(uc, 0)
    elif name == "QueryPerformanceCounter":
        try:
            uc.mem_write(rcx, struct.pack("<Q", 0x0123456789ABCDEF))
        except UcError:
            pass
        return_api(uc, 1)
    elif name == "InitializeSListHead":
        try:
            uc.mem_write(rcx, b"\0" * 16)
        except UcError:
            pass
        return_api(uc, 0)
    elif name in {"memcpy", "memmove"}:
        source = uc.reg_read(UC_X86_REG_RDX)
        count = uc.reg_read(UC_X86_REG_R8)
        uc.mem_write(rcx, bytes(uc.mem_read(source, count)))
        return_api(uc, rcx)
    elif name == "memset":
        byte = uc.reg_read(UC_X86_REG_RDX) & 0xFF
        count = uc.reg_read(UC_X86_REG_R8)
        uc.mem_write(rcx, bytes([byte]) * count)
        return_api(uc, rcx)
    elif name.startswith("__p__"):
        return_api(uc, STUB_BASE + 0xF000)
    else:
        return_api(uc, 0)


def vm_section(pe: pefile.PE) -> tuple[int, int]:
    section = max(pe.sections, key=lambda s: max(int(s.Misc_VirtualSize), int(s.SizeOfRawData)))
    start = int(section.VirtualAddress)
    end = start + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    return start, end


@dataclass
class InstructionState:
    address: int
    data: bytes
    before: dict[str, int]


@dataclass
class PcodeEvent:
    idx: int
    rva: int
    size: int
    raw: int
    read_rip: int
    instructions: list[InstructionState] = field(default_factory=list)
    writes: list[tuple[int, int, int, int]] = field(default_factory=list)
    after: dict[str, int] | None = None
    is_pcode: bool = False
    data_family: str | None = None
    key_family: str | None = None
    initial_xor_index: int = -1
    key_update_index: int = -1
    decoded: int | None = None
    old_key: int | None = None
    operations: list[tuple[str, Any]] = field(default_factory=list)


class BaselineTrace:
    def __init__(self, raw: bytes, output_length: int):
        self.raw = raw
        self.pe, self.base, self.uc, self.api = map_engine(raw)
        self.vm_lo, self.vm_hi = vm_section(self.pe)
        self.output_length = output_length
        self.events: list[PcodeEvent] = []
        self.full_reads: list[tuple[int, int, int]] = []
        self.current: PcodeEvent | None = None
        self.last_instruction: InstructionState | None = None
        self.output = bytearray()
        self.capture_lane = True
        self.error: Exception | None = None
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)

    def _code(self, uc: Uc, address: int, size: int, _: Any) -> None:
        state = InstructionState(address, bytes(uc.mem_read(address, min(size, 15))), reg_snapshot(uc))
        self.last_instruction = state
        if self.capture_lane and self.current is not None:
            self.current.instructions.append(state)

        name = self.api.get(address)
        if name is None:
            return
        try:
            if name == "putchar":
                if self.capture_lane:
                    self.capture_lane = False
                    if self.current is not None:
                        self.current.after = reg_snapshot(uc)
                        self.current = None
                self.output.append(uc.reg_read(UC_X86_REG_RCX) & 0xFF)
                if len(self.output) >= self.output_length:
                    uc.emu_stop()
                    return
                return_api(uc, self.output[-1])
            else:
                handle_api(uc, name, self.base)
        except Exception as exc:
            self.error = exc
            uc.emu_stop()

    def _read(self, uc: Uc, access: int, address: int, size: int, value: int, _: Any) -> None:
        if access != UC_MEM_READ or not (self.base + self.vm_lo <= address < self.base + self.vm_hi):
            return
        rip = uc.reg_read(UC_X86_REG_RIP) - self.base
        self.full_reads.append((address - self.base, size, rip))
        if not self.capture_lane:
            return
        state = self.last_instruction
        if state is None:
            raise SolveError("internal trace error: missing read instruction state")
        if self.current is not None:
            if self.current.instructions and self.current.instructions[-1] is state:
                self.current.instructions.pop()
            self.current.after = state.before
        event = PcodeEvent(
            idx=len(self.events), rva=address - self.base, size=size,
            raw=int.from_bytes(bytes(uc.mem_read(address, size)), "little"),
            read_rip=state.address - self.base, instructions=[state],
        )
        self.events.append(event)
        self.current = event

    def _write(self, uc: Uc, access: int, address: int, size: int, value: int, _: Any) -> None:
        if self.capture_lane and self.current is not None:
            mask = (1 << (8 * size)) - 1
            self.current.writes.append((address, size, value & mask, uc.reg_read(UC_X86_REG_RIP) - self.base))

    def run(self) -> bytes:
        try:
            self.uc.emu_start(self.base + 0x1000, SENTINEL, timeout=35_000_000, count=5_000_000)
        except UcError as exc:
            self.error = exc
        if self.error is not None:
            raise SolveError(f"baseline emulation failed: {self.error}")
        if len(self.output) != self.output_length:
            raise SolveError(f"baseline emitted {len(self.output)} bytes, expected {self.output_length}: {bytes(self.output)!r}")
        return bytes(self.output)


def decode_instruction(md: Cs, state: InstructionState):
    try:
        return next(md.disasm(state.data, state.address, count=1))
    except StopIteration as exc:
        raise SolveError(f"cannot disassemble instruction at {state.address:#x}") from exc


def analyze_event(event: PcodeEvent, md: Cs) -> bool:
    if len(event.instructions) < 3:
        return False
    instructions = [decode_instruction(md, state) for state in event.instructions]
    read = instructions[0]
    if len(read.operands) < 2 or read.operands[0].type != X86_OP_REG:
        return False
    data_family = family(read.reg_name(read.operands[0].reg))
    candidates: list[tuple[int, int, str]] = []
    for initial_index, ins in enumerate(instructions[1:], 1):
        if (
            ins.mnemonic != "xor" or len(ins.operands) != 2
            or ins.operands[0].type != X86_OP_REG or ins.operands[1].type != X86_OP_REG
        ):
            continue
        dst_family = family(ins.reg_name(ins.operands[0].reg))
        key_family = family(ins.reg_name(ins.operands[1].reg))
        if dst_family != data_family or key_family == data_family:
            continue
        for update_index, update in enumerate(instructions[initial_index + 1:], initial_index + 1):
            if (
                update.mnemonic == "xor" and len(update.operands) == 2
                and update.operands[0].type == X86_OP_REG and update.operands[1].type == X86_OP_REG
                and family(update.reg_name(update.operands[0].reg)) == key_family
                and family(update.reg_name(update.operands[1].reg)) == data_family
            ):
                candidates.append((initial_index, update_index, key_family))
                break

    width_mask = (1 << (8 * event.size)) - 1
    for initial_index, update_index, key_family in candidates:
        old_key = subreg_value(key_family, event.instructions[initial_index].before)
        decoded_name = instructions[update_index].reg_name(instructions[update_index].operands[1].reg)
        decoded = subreg_value(decoded_name, event.instructions[update_index].before) & width_mask
        after = event.instructions[update_index + 1].before if update_index + 1 < len(event.instructions) else event.after
        if after is None:
            continue
        new_key = subreg_value(key_family, after)
        if ((old_key ^ new_key) & width_mask) != decoded:
            continue
        event.is_pcode = True
        event.data_family = data_family
        event.key_family = key_family
        event.initial_xor_index = initial_index
        event.key_update_index = update_index
        event.decoded = decoded
        event.old_key = old_key
        return True
    return False


def rotate_left(value: int, count: int, width: int) -> int:
    count %= width
    mask = (1 << width) - 1
    if count == 0:
        return value & mask
    return ((value << count) | (value >> (width - count))) & mask


def rotate_right(value: int, count: int, width: int) -> int:
    return rotate_left(value, width - (count % width), width)


def operand_constant(ins, state: dict[str, int], operand, width: int) -> int:
    mask = (1 << width) - 1
    if operand.type == X86_OP_IMM:
        return int(operand.imm) & mask
    if operand.type == X86_OP_REG:
        return subreg_value(ins.reg_name(operand.reg), state) & mask
    raise SolveError(f"unsupported decoder operand in {ins.mnemonic} {ins.op_str}")


def apply_operations(value: int, operations: list[tuple[str, Any]], width: int) -> int:
    mask = (1 << width) - 1
    x = value & mask
    for operation, arg in operations:
        if operation == "xor": x ^= int(arg)
        elif operation == "add": x = (x + int(arg)) & mask
        elif operation == "sub": x = (x - int(arg)) & mask
        elif operation == "not": x = (~x) & mask
        elif operation == "neg": x = (-x) & mask
        elif operation == "rol": x = rotate_left(x, int(arg), width)
        elif operation == "ror": x = rotate_right(x, int(arg), width)
        elif operation == "bswap": x = int.from_bytes(x.to_bytes(width // 8, "little"), "big")
        elif operation == "affine":
            multiplier, constant = arg
            x = (int(multiplier) * x + int(constant)) & mask
        elif operation == "mul": x = (x * int(arg)) & mask
        else: raise SolveError(f"unknown decoder operation {operation}")
    return x & mask


def invert_operations(value: int, operations: list[tuple[str, Any]], width: int) -> int:
    mask = (1 << width) - 1
    modulus = 1 << width
    x = value & mask
    for operation, arg in reversed(operations):
        if operation == "xor": x ^= int(arg)
        elif operation == "add": x = (x - int(arg)) & mask
        elif operation == "sub": x = (x + int(arg)) & mask
        elif operation == "not": x = (~x) & mask
        elif operation == "neg": x = (-x) & mask
        elif operation == "rol": x = rotate_right(x, int(arg), width)
        elif operation == "ror": x = rotate_left(x, int(arg), width)
        elif operation == "bswap": x = int.from_bytes(x.to_bytes(width // 8, "little"), "big")
        elif operation == "affine":
            multiplier, constant = arg
            x = ((x - int(constant)) * pow(int(multiplier), -1, modulus)) & mask
        elif operation == "mul": x = (x * pow(int(arg), -1, modulus)) & mask
        else: raise SolveError(f"unknown decoder operation {operation}")
    return x & mask


def build_decoder_model(event: PcodeEvent, md: Cs) -> None:
    if not event.is_pcode or event.data_family is None or event.old_key is None or event.decoded is None:
        raise SolveError(f"event {event.idx} is not a recognized p-code operand")
    width = event.size * 8
    mask = (1 << width) - 1
    instructions = [decode_instruction(md, state) for state in event.instructions]
    operations: list[tuple[str, Any]] = []

    for index in range(event.initial_xor_index + 1, event.key_update_index):
        ins = instructions[index]
        state = event.instructions[index].before
        if not ins.operands or ins.operands[0].type != X86_OP_REG:
            continue
        destination_name = ins.reg_name(ins.operands[0].reg)
        if family(destination_name) != event.data_family:
            continue
        destination_width = int(ins.operands[0].size) * 8
        if destination_width != width:
            raise SolveError(f"unsupported sub-register transform at event {event.idx}: {ins.mnemonic} {ins.op_str}")
        mnemonic = ins.mnemonic
        if mnemonic in {"xor", "add", "sub", "adc", "sbb", "and", "or"}:
            if len(ins.operands) < 2:
                raise SolveError(f"missing operand in {mnemonic} at event {event.idx}")
            constant = operand_constant(ins, state, ins.operands[1], width)
            carry = state["eflags"] & 1
            if mnemonic == "xor": operations.append(("xor", constant))
            elif mnemonic == "add": operations.append(("add", constant))
            elif mnemonic == "sub": operations.append(("sub", constant))
            elif mnemonic == "adc": operations.append(("add", (constant + carry) & mask))
            elif mnemonic == "sbb": operations.append(("sub", (constant + carry) & mask))
            elif mnemonic == "and" and constant != mask:
                raise SolveError(f"non-bijective AND in event {event.idx}")
            elif mnemonic == "or" and constant != 0:
                raise SolveError(f"non-bijective OR in event {event.idx}")
        elif mnemonic == "inc": operations.append(("add", 1))
        elif mnemonic == "dec": operations.append(("sub", 1))
        elif mnemonic == "not": operations.append(("not", 0))
        elif mnemonic == "neg": operations.append(("neg", 0))
        elif mnemonic in {"rol", "ror"}:
            count = operand_constant(ins, state, ins.operands[1], width) & 0xFF
            operations.append((mnemonic, count))
        elif mnemonic == "bswap": operations.append(("bswap", 0))
        elif mnemonic == "btc":
            bit = operand_constant(ins, state, ins.operands[1], width) % width
            operations.append(("xor", 1 << bit))
        elif mnemonic == "lea":
            if len(ins.operands) < 2 or ins.operands[1].type != X86_OP_MEM:
                raise SolveError(f"unsupported LEA at event {event.idx}")
            mem = ins.operands[1].mem
            multiplier = 0
            constant = int(mem.disp)
            for reg_id, scale in ((mem.base, 1), (mem.index, int(mem.scale))):
                if reg_id == 0:
                    continue
                name = ins.reg_name(reg_id)
                if family(name) == event.data_family:
                    multiplier += scale
                else:
                    constant += subreg_value(name, state) * scale
            multiplier &= mask
            constant &= mask
            if math.gcd(multiplier, 1 << width) != 1:
                raise SolveError(f"non-invertible LEA multiplier {multiplier:#x} in event {event.idx}")
            operations.append(("affine", (multiplier, constant)))
        elif mnemonic == "imul":
            if (
                len(ins.operands) == 3 and ins.operands[1].type == X86_OP_REG
                and family(ins.reg_name(ins.operands[1].reg)) == event.data_family
            ):
                multiplier = operand_constant(ins, state, ins.operands[2], width)
            elif len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM:
                multiplier = operand_constant(ins, state, ins.operands[1], width)
            else:
                raise SolveError(f"unsupported IMUL form in event {event.idx}: {ins.op_str}")
            if multiplier % 2 == 0:
                raise SolveError(f"non-invertible IMUL in event {event.idx}")
            operations.append(("mul", multiplier))
        elif mnemonic in {"mov", "movzx", "movsx", "movsxd"}:
            if (
                len(ins.operands) >= 2 and ins.operands[1].type == X86_OP_REG
                and family(ins.reg_name(ins.operands[1].reg)) == event.data_family
            ):
                continue
            raise SolveError(f"decoder taint overwritten in event {event.idx}: {mnemonic} {ins.op_str}")
        else:
            raise SolveError(f"unsupported rotor decoder instruction in event {event.idx}: {mnemonic} {ins.op_str}")

    event.operations = operations
    baseline_input = (event.raw ^ event.old_key) & mask
    reconstructed = apply_operations(baseline_input, operations, width)
    if reconstructed != event.decoded:
        raise SolveError(f"decoder model mismatch at event {event.idx}: got {reconstructed:#x}, expected {event.decoded:#x}")
    if invert_operations(event.decoded, operations, width) != baseline_input:
        raise SolveError(f"decoder inverse mismatch at event {event.idx}")


def find_rotor_groups(events: list[PcodeEvent]) -> list[list[PcodeEvent]]:
    pushes: list[tuple[PcodeEvent, int]] = []
    for event in events:
        if not event.is_pcode or event.size != 4 or event.decoded is None:
            continue
        for address, size, value, _rip in event.writes:
            if size in {4, 8} and (value & 0xFFFFFFFF) == event.decoded:
                pushes.append((event, address))
                break
    by_address: dict[int, list[PcodeEvent]] = {}
    for event, address in pushes:
        by_address.setdefault(address, []).append(event)
    groups: list[list[PcodeEvent]] = []
    for same_address in by_address.values():
        same_address.sort(key=lambda event: event.idx)
        for start in range(len(same_address) - 3):
            group = same_address[start:start + 4]
            gaps = [group[i + 1].idx - group[i].idx for i in range(3)]
            values = [event.decoded or 0 for event in group]
            if (
                group[-1].idx - group[0].idx <= 48
                and all(1 <= gap <= 16 for gap in gaps)
                and all(value not in {0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000} for value in values)
                and len(set(values)) >= 3
            ):
                groups.append(group)
    groups.sort(key=lambda group: (group[0].idx, group[-1].idx - group[0].idx))
    return groups


class PatchedRun:
    def __init__(self, raw: bytes, baseline: BaselineTrace, replacements: dict[int, int], output_length: int):
        self.raw = raw
        self.baseline = baseline
        self.events = baseline.events
        self.replacements = replacements
        self.output_length = output_length
        self.pe, self.base, self.uc, self.api = map_engine(raw)
        self.vm_lo, self.vm_hi = vm_section(self.pe)
        self.event_index = 0
        self.output = bytearray()
        self.full_reads: list[tuple[int, int, int]] = []
        self.patched_values: dict[int, int] = {}
        self.error: Exception | None = None
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)

    def _code(self, uc: Uc, address: int, size: int, _: Any) -> None:
        if self.event_index < len(self.events):
            event = self.events[self.event_index]
            if address == self.base + event.read_rip:
                index = self.event_index
                self.event_index += 1
                if event.is_pcode:
                    if event.key_family is None or event.old_key is None:
                        self.error = SolveError(f"missing rolling-key model for event {event.idx}")
                        uc.emu_stop()
                        return
                    state = reg_snapshot(uc)
                    current_key = subreg_value(event.key_family, state)
                    mask = (1 << (8 * event.size)) - 1
                    if index in self.replacements:
                        if not event.operations:
                            self.error = SolveError(f"missing rotor decoder model for event {event.idx}")
                            uc.emu_stop()
                            return
                        desired_input = invert_operations(self.replacements[index], event.operations, event.size * 8)
                        new_raw = desired_input ^ (current_key & mask)
                    else:
                        new_raw = event.raw ^ ((event.old_key ^ current_key) & mask)
                    new_raw &= mask
                    uc.mem_write(self.base + event.rva, new_raw.to_bytes(event.size, "little"))
                    self.patched_values[event.idx] = new_raw

        name = self.api.get(address)
        if name is None:
            return
        try:
            if name == "putchar":
                self.output.append(uc.reg_read(UC_X86_REG_RCX) & 0xFF)
                if len(self.output) >= self.output_length:
                    uc.emu_stop()
                    return
                return_api(uc, self.output[-1])
            else:
                handle_api(uc, name, self.base)
        except Exception as exc:
            self.error = exc
            uc.emu_stop()

    def _read(self, uc: Uc, access: int, address: int, size: int, value: int, _: Any) -> None:
        if access == UC_MEM_READ and self.base + self.vm_lo <= address < self.base + self.vm_hi:
            self.full_reads.append((address - self.base, size, uc.reg_read(UC_X86_REG_RIP) - self.base))

    def run(self) -> bytes:
        try:
            self.uc.emu_start(self.base + 0x1000, SENTINEL, timeout=35_000_000, count=5_000_000)
        except UcError as exc:
            self.error = exc
        return bytes(self.output)

    def build_binary(self) -> bytes:
        patched = bytearray(self.raw)
        for event_index, value in self.patched_values.items():
            event = self.events[event_index]
            offset = int(self.pe.get_offset_from_rva(event.rva))
            patched[offset:offset + event.size] = value.to_bytes(event.size, "little")
        return bytes(patched)


class PlainRun:
    def __init__(self, raw: bytes, output_length: int):
        self.raw = raw
        self.output_length = output_length
        self.pe, self.base, self.uc, self.api = map_engine(raw)
        self.vm_lo, self.vm_hi = vm_section(self.pe)
        self.output = bytearray()
        self.full_reads: list[tuple[int, int, int]] = []
        self.error: Exception | None = None
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)

    def _code(self, uc: Uc, address: int, size: int, _: Any) -> None:
        name = self.api.get(address)
        if name is None:
            return
        try:
            if name == "putchar":
                self.output.append(uc.reg_read(UC_X86_REG_RCX) & 0xFF)
                if len(self.output) >= self.output_length:
                    uc.emu_stop()
                    return
                return_api(uc, self.output[-1])
            else:
                handle_api(uc, name, self.base)
        except Exception as exc:
            self.error = exc
            uc.emu_stop()

    def _read(self, uc: Uc, access: int, address: int, size: int, value: int, _: Any) -> None:
        if access == UC_MEM_READ and self.base + self.vm_lo <= address < self.base + self.vm_hi:
            self.full_reads.append((address - self.base, size, uc.reg_read(UC_X86_REG_RIP) - self.base))

    def run(self) -> bytes:
        try:
            self.uc.emu_start(self.base + 0x1000, SENTINEL, timeout=35_000_000, count=5_000_000)
        except UcError as exc:
            self.error = exc
        if self.error is not None:
            raise SolveError(f"static patched-file verification failed: {self.error}")
        return bytes(self.output)


def solve_sample(raw: bytes, target: bytes, rotors: tuple[int, int, int, int], verbose: bool = True) -> bytes:
    started = time.monotonic()
    baseline = BaselineTrace(raw, len(target))
    original_output = baseline.run()
    if verbose:
        log(f"    original={original_output!r}")
        log(f"    first lane: {len(baseline.events)} section reads; full trace: {len(baseline.full_reads)} reads")

    recognized = sum(1 for event in baseline.events if analyze_event(event, baseline.md))
    if recognized == 0:
        raise SolveError("no rolling-key p-code operands were recognized")
    if verbose:
        log(f"    recognized {recognized}/{len(baseline.events)} first-lane p-code operands")

    groups = find_rotor_groups(baseline.events)
    if not groups:
        raise SolveError("could not locate the four rotor PUSH-imm32 operands")

    prepared_groups: list[list[PcodeEvent]] = []
    model_errors: list[str] = []
    for group in groups:
        try:
            for event in group:
                build_decoder_model(event, baseline.md)
            prepared_groups.append(group)
        except SolveError as exc:
            model_errors.append(str(exc))
    if not prepared_groups:
        raise SolveError("rotor candidates were found, but their operand decoders could not be inverted:\n" + "\n".join(model_errors[:8]))

    orders: list[tuple[int, int, int, int]] = [rotors]
    orders.extend(order for order in itertools.permutations(rotors) if order != rotors)
    failures: list[str] = []

    for group_number, group in enumerate(prepared_groups, 1):
        if verbose:
            values = ", ".join(f"{event.decoded:#010x}" for event in group)
            indices = ",".join(str(event.idx) for event in group)
            log(f"    rotor candidate {group_number}: events [{indices}], current=[{values}]")
        for order_number, order in enumerate(orders):
            replacements = {event.idx: value for event, value in zip(group, order)}
            run = PatchedRun(raw, baseline, replacements, len(target))
            output = run.run()
            trace_equal = run.full_reads == baseline.full_reads
            lane_complete = run.event_index == len(baseline.events)
            if output == target and trace_equal and lane_complete and run.error is None:
                patched = run.build_binary()
                verify = PlainRun(patched, len(target))
                verify_output = verify.run()
                if verify_output != target:
                    failures.append(f"group {group_number}, order {order_number}: dynamic success but static output {verify_output!r}")
                    continue
                if verify.full_reads != baseline.full_reads:
                    failures.append(f"group {group_number}, order {order_number}: static VM trace changed")
                    continue
                vm_start = baseline.pe.get_offset_from_rva(baseline.vm_lo)
                vm_end_rva = baseline.vm_hi - 1
                vm_end = baseline.pe.get_offset_from_rva(vm_end_rva) + 1
                changed = [i for i, (old, new) in enumerate(zip(raw, patched)) if old != new]
                if any(not (vm_start <= index < vm_end) for index in changed):
                    raise SolveError("internal error: patch modified bytes outside the VM section")
                if len(patched) != len(raw):
                    raise SolveError("internal error: patched sample size changed")
                if verbose:
                    log(f"    solved: target={verify_output!r}, changed={len(changed)} bytes, trace unchanged, {time.monotonic() - started:.2f}s")
                return patched
            if order_number == 0:
                failures.append(f"group {group_number}: output={output!r}, lane={lane_complete}, trace_equal={trace_equal}, error={run.error!r}")
            if order_number == 0 and (not lane_complete or run.error is not None):
                break
    raise SolveError("no rotor candidate produced a valid patch:\n" + "\n".join(failures[-12:]))


SAMPLE_SIZE_RE = re.compile(rb"sample_size=(\d+)")
TARGET_RE = re.compile(rb"target=(b(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"))")
HINT_RE = re.compile(
    rb"rotors\s+a=(0x[0-9a-fA-F]+)\s+b=(0x[0-9a-fA-F]+)\s+"
    rb"c=(0x[0-9a-fA-F]+)\s+d=(0x[0-9a-fA-F]+)"
)
ROUND_RE = re.compile(rb"round\s+(\d+)/(\d+)")
FLAG_RE = re.compile(rb"SEKAI\{[^\r\n}]*\}")


def parse_round_metadata(metadata: bytes) -> tuple[int, int, bytes, tuple[int, int, int, int]]:
    round_match = ROUND_RE.search(metadata)
    target_match = TARGET_RE.search(metadata)
    hint_match = HINT_RE.search(metadata)
    if not round_match or not target_match or not hint_match:
        raise SolveError("could not parse round metadata:\n" + metadata.decode("utf-8", "replace"))
    try:
        target = ast.literal_eval(target_match.group(1).decode("ascii"))
    except (SyntaxError, ValueError) as exc:
        raise SolveError(f"invalid target literal: {target_match.group(1)!r}") from exc
    if not isinstance(target, bytes):
        raise SolveError("target literal is not bytes")
    rotors = tuple(int(value, 16) for value in hint_match.groups())
    return int(round_match.group(1)), int(round_match.group(2)), target, rotors  # type: ignore[return-value]


def receive_round(remote: Remote) -> tuple[bytes, bytes, int, int, bytes, tuple[int, int, int, int]]:
    header = remote.recv_until(b"sample_raw:\n")
    size_matches = SAMPLE_SIZE_RE.findall(header)
    if not size_matches:
        raise SolveError("missing sample_size before sample_raw")
    sample_size = int(size_matches[-1])
    sample = remote.recv_exact(sample_size)
    metadata = remote.recv_until(b"bytes):")
    try:
        metadata += remote.recv_until(b"\n", max_bytes=4096)
    except (EOFError, socket.timeout):
        pass
    round_index, round_total, target, rotors = parse_round_metadata(metadata)
    return header, sample, round_index, round_total, target, rotors


def run_remote(host: str, port: int) -> int:
    log(f"[*] Connecting to {host}:{port}")
    remote = Remote(host, port)
    try:
        pow_prompt = remote.recv_until(b"solution: ")
        sys.stdout.write(pow_prompt.decode("utf-8", "replace"))
        sys.stdout.flush()
        token_match = POW_TOKEN_RE.search(pow_prompt)
        if not token_match:
            raise SolveError("could not parse proof-of-work token")
        token = token_match.group(1).decode("ascii")
        log(f"[*] Solving PoW {token}")
        remote.sendline(solve_pow(token))
        log("[+] PoW accepted; receiving protected samples")
        total_rounds: int | None = None
        for _expected_round in range(1, 65):
            header, sample, round_index, round_total, target, rotors = receive_round(remote)
            prefix = header.decode("utf-8", "replace").strip("\x00\r\n")
            if prefix:
                printable_lines = [line for line in prefix.splitlines() if "sample_raw" not in line]
                if printable_lines:
                    log("\n".join(printable_lines[-6:]))
            total_rounds = round_total
            log(f"[*] Round {round_index}/{round_total}: sample={len(sample)} bytes, target={target!r}")
            log("    requested rotors: " + " ".join(f"{name}={value:#010x}" for name, value in zip("abcd", rotors)))
            patched = solve_sample(sample, target, rotors, verbose=True)
            remote.send(patched)
            log(f"[+] Round {round_index}/{round_total} submitted ({len(patched)} bytes)")
            if round_index >= round_total:
                final = remote.recv_to_eof(idle_timeout=15.0)
                text = final.decode("utf-8", "replace")
                if text:
                    print(text, end="" if text.endswith("\n") else "\n")
                flag = FLAG_RE.search(final)
                if flag:
                    log(f"[+] FLAG: {flag.group(0).decode()}")
                    return 0
                raise SolveError("all rounds were submitted, but no SEKAI{...} flag was received")
        raise SolveError(f"round loop exceeded limit; advertised total={total_rounds}")
    finally:
        remote.close()


def load_local_capture(path: Path) -> tuple[bytes, bytes, tuple[int, int, int, int]]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            candidates = [name for name in archive.namelist() if name.endswith("transcript.raw")]
            if not candidates:
                raise SolveError("capture ZIP has no transcript.raw")
            transcript = archive.read(candidates[0])
    else:
        transcript = path.read_bytes()
    marker = b"sample_raw:\n"
    start = transcript.find(marker)
    if start < 0:
        raise SolveError("capture has no sample_raw marker")
    header = transcript[:start + len(marker)]
    sizes = SAMPLE_SIZE_RE.findall(header)
    if not sizes:
        raise SolveError("capture has no sample_size")
    sample_size = int(sizes[-1])
    sample_start = start + len(marker)
    sample = transcript[sample_start:sample_start + sample_size]
    metadata = transcript[sample_start + sample_size:]
    _round_index, _round_total, target, rotors = parse_round_metadata(metadata)
    return sample, target, rotors


def run_local(path: Path, output: Path) -> int:
    sample, target, rotors = load_local_capture(path)
    log(f"[*] Local sample={len(sample)} bytes target={target!r}")
    patched = solve_sample(sample, target, rotors, verbose=True)
    output.write_bytes(patched)
    log(f"[+] Wrote {output} ({len(patched)} bytes)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatic mikuprotect 10-round solver")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--local", type=Path, help="solve a mikuprotect capture ZIP or transcript.raw locally")
    parser.add_argument("--output", type=Path, default=Path("mikuprotect_patched.exe"))
    args = parser.parse_args()
    try:
        if args.local is not None:
            return run_local(args.local, args.output)
        return run_remote(args.host, args.port)
    except KeyboardInterrupt:
        log("\n[-] Interrupted")
        return 130
    except (SolveError, EOFError, OSError, socket.timeout) as exc:
        log(f"[-] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
