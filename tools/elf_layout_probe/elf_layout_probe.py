#!/usr/bin/env python3
"""Offline ELF layout probe.

This is an *analysis-only* harness. It never writes to an ELF, never loads
shellcode, and is not linked into the DFRoot exploit. It exists to compare:

  * "current": a faithful re-implementation of find_hook_target() /
    find_code_cave() in app/src/main/jni/elf_parser.c, including its
    assumptions and bugs, and
  * "reference": a strict ELF64/AArch64 reader that validates the header,
    handles sectionless files and extended numbering, and only treats
    file-backed zero bytes inside an executable segment's last mapped page
    as a placement candidate.

The reference verdict is a *layout classification*, not proof that a given
offset is safe to use at runtime. It deliberately refuses to call arbitrary
zero runs inside a segment "free space".
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_DYNSYM = 11

DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_GNU_HASH = 0x6FFFFEF5

SHN_XINDEX = 0xFFFF
PN_XNUM = 0xFFFF

EM_AARCH64 = 183
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

EHDR_FMT = "<16sHHIQQQIHHHHHH"
EHDR_SIZE = struct.calcsize(EHDR_FMT)      # 64
PHDR_FMT = "<IIQQQQQQ"
PHDR_SIZE = struct.calcsize(PHDR_FMT)      # 56
SHDR_FMT = "<IIQQQQIIQQ"
SHDR_SIZE = struct.calcsize(SHDR_FMT)      # 64
SYM_FMT = "<IBBHQQ"
SYM_SIZE = struct.calcsize(SYM_FMT)        # 24
DYN_FMT = "<QQ"
DYN_SIZE = struct.calcsize(DYN_FMT)        # 16

TARGET_SYMBOL = (
    "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"
)


class ParseError(Exception):
    """Reference parser rejected the file."""


# ---------------------------------------------------------------------------
# Small read helpers (bytes, not file handles, so bounds are explicit)
# ---------------------------------------------------------------------------

def _slice(data: bytes, off: int, n: int) -> bytes:
    if off < 0 or off >= len(data):
        return b""
    return data[off:off + n]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


# ---------------------------------------------------------------------------
# Reference parser
# ---------------------------------------------------------------------------

@dataclass
class Segment:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    @property
    def exec(self) -> bool:
        return self.p_type == PT_LOAD and bool(self.p_flags & PF_X)

    def file_range(self) -> range:
        return range(self.p_offset, self.p_offset + self.p_filesz)


@dataclass
class Section:
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    name: str = ""

    def file_range(self) -> range:
        if self.sh_type == SHT_NOBITS:
            return range(0)
        return range(self.sh_offset, self.sh_offset + self.sh_size)


@dataclass
class ParsedELF:
    data: bytes
    pagesize: int
    e_machine: int
    e_type: int
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    dynamic: dict[int, int] = field(default_factory=dict)
    extended: dict[str, bool] = field(default_factory=dict)

    # -- helpers ---------------------------------------------------------

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.segments:
            if seg.p_type != PT_LOAD:
                continue
            if seg.p_vaddr <= vaddr < seg.p_vaddr + seg.p_filesz:
                return seg.p_offset + (vaddr - seg.p_vaddr)
        return None

    def exec_segments(self) -> list[Segment]:
        return [s for s in self.segments if s.exec]

    def claimed_ranges(self) -> list[range]:
        """File ranges that belong to some segment or non-NOBITS section."""
        ranges: list[range] = []
        for seg in self.segments:
            if seg.p_type in (PT_LOAD, PT_DYNAMIC) and seg.p_filesz:
                ranges.append(seg.file_range())
        for sec in self.sections:
            if sec.sh_size and sec.sh_type != SHT_NOBITS:
                ranges.append(sec.file_range())
        return ranges

    # -- symbol lookup ---------------------------------------------------

    def resolve_symbol(self, symname: str) -> Optional[int]:
        """Return st_value, searching .dynsym then PT_DYNAMIC."""
        st_value = self._resolve_from_sections(symname)
        if st_value is not None:
            return st_value
        return self._resolve_from_dynamic(symname)

    def _sym_name(self, strtab: bytes, st_name: int) -> Optional[str]:
        if st_name < 0 or st_name >= len(strtab):
            return None
        end = strtab.find(b"\0", st_name)
        if end < 0:
            return None
        return strtab[st_name:end].decode("latin-1")

    def _resolve_from_sections(self, symname: str) -> Optional[int]:
        dynsym = next((s for s in self.sections if s.sh_type == SHT_DYNSYM), None)
        if dynsym is None:
            return None
        if dynsym.sh_link >= len(self.sections):
            return None
        strtab_sh = self.sections[dynsym.sh_link]
        strtab = _slice(self.data, strtab_sh.sh_offset, strtab_sh.sh_size)
        entsize = dynsym.sh_entsize or SYM_SIZE
        if entsize < SYM_SIZE:
            return None
        count = dynsym.sh_size // entsize
        for i in range(count):
            off = dynsym.sh_offset + i * entsize
            raw = _slice(self.data, off, SYM_SIZE)
            if len(raw) < SYM_SIZE:
                return None
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(SYM_FMT, raw)
            if st_shndx == 0:
                continue  # SHN_UNDEF: import, not a definition
            if self._sym_name(strtab, st_name) == symname:
                return st_value
        return None

    def _resolve_from_dynamic(self, symname: str) -> Optional[int]:
        if not self.dynamic:
            return None
        sym_vaddr = self.dynamic.get(DT_SYMTAB)
        str_vaddr = self.dynamic.get(DT_STRTAB)
        if sym_vaddr is None or str_vaddr is None:
            return None
        sym_off = self.vaddr_to_offset(sym_vaddr)
        str_off = self.vaddr_to_offset(str_vaddr)
        if sym_off is None or str_off is None:
            return None
        str_size = self.dynamic.get(DT_STRSZ)
        if str_size is None:
            # Bound by the next mapped vaddr after strtab.
            str_size = len(self.data) - str_off
        strtab = _slice(self.data, str_off, str_size)

        count = None
        hash_vaddr = self.dynamic.get(DT_HASH)
        if hash_vaddr is not None:
            hash_off = self.vaddr_to_offset(hash_vaddr)
            if hash_off is not None and hash_off + 8 <= len(self.data):
                count = _u32(self.data, hash_off + 4)  # nchain
        if count is None and str_off > sym_off:
            count = (str_off - sym_off) // SYM_SIZE
        if count is None:
            return None
        for i in range(count):
            raw = _slice(self.data, sym_off + i * SYM_SIZE, SYM_SIZE)
            if len(raw) < SYM_SIZE:
                return None
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(SYM_FMT, raw)
            if st_shndx == 0:
                continue  # SHN_UNDEF: import, not a definition
            if self._sym_name(strtab, st_name) == symname:
                return st_value
        return None


def parse_reference(data: bytes, pagesize: int = 4096) -> ParsedELF:
    if len(data) < EHDR_SIZE:
        raise ParseError("file shorter than ELF64 header")
    if data[0:4] != b"\x7fELF":
        raise ParseError("bad ELF magic")
    ei_class = data[4]
    ei_data = data[5]
    ei_version = data[6]
    if ei_class != ELFCLASS64:
        raise ParseError(f"EI_CLASS={ei_class} (not ELF64)")
    if ei_data != ELFDATA2LSB:
        raise ParseError(f"EI_DATA={ei_data} (not little-endian)")
    if ei_version != EV_CURRENT:
        raise ParseError(f"EI_VERSION={ei_version} (not EV_CURRENT)")

    (ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from(EHDR_FMT, data, 0)

    if e_machine != EM_AARCH64:
        raise ParseError(f"e_machine={e_machine} (not AArch64)")
    if e_version != EV_CURRENT:
        raise ParseError(f"e_version={e_version} (not EV_CURRENT)")
    if e_ehsize != EHDR_SIZE:
        raise ParseError(f"e_ehsize={e_ehsize} (expected {EHDR_SIZE})")
    if e_phentsize != PHDR_SIZE:
        raise ParseError(f"e_phentsize={e_phentsize} (expected {PHDR_SIZE})")
    if e_shentsize not in (0, SHDR_SIZE):
        raise ParseError(f"e_shentsize={e_shentsize} (expected {SHDR_SIZE})")

    elf = ParsedELF(data=data, pagesize=pagesize, e_machine=e_machine, e_type=e_type)

    # --- section header 0 is needed for extended numbering -------------
    sh0: Optional[Section] = None
    sh_stride = e_shentsize or SHDR_SIZE
    if e_shoff:
        if e_shoff + sh_stride > len(data):
            raise ParseError("section header table starts past EOF")
        raw = data[e_shoff:e_shoff + SHDR_SIZE]
        sh0 = Section(*struct.unpack(SHDR_FMT, raw))

    real_phnum = e_phnum
    real_shnum = e_shnum
    real_shstrndx = e_shstrndx
    extended_phnum = False
    extended_shnum = False
    extended_shstr = False

    if e_phnum == PN_XNUM:
        if sh0 is None:
            raise ParseError("e_phnum=PN_XNUM but no section header 0")
        real_phnum = sh0.sh_info
        extended_phnum = True
    if e_shoff and e_shnum == 0:
        if sh0 is None:
            raise ParseError("e_shnum=0 with e_shoff set but no shdr0")
        real_shnum = sh0.sh_size
        extended_shnum = True
    if e_shstrndx == SHN_XINDEX:
        if sh0 is None:
            raise ParseError("e_shstrndx=SHN_XINDEX but no section header 0")
        real_shstrndx = sh0.sh_link
        extended_shstr = True

    # --- program headers ------------------------------------------------
    if real_phnum:
        if not e_phoff:
            raise ParseError("program headers present but e_phoff=0")
        if e_phoff + real_phnum * PHDR_SIZE > len(data):
            raise ParseError("program header table extends past EOF")
        for i in range(real_phnum):
            raw = data[e_phoff + i * PHDR_SIZE:e_phoff + (i + 1) * PHDR_SIZE]
            seg = Segment(*struct.unpack(PHDR_FMT, raw))
            if seg.p_type in (PT_LOAD, PT_DYNAMIC):
                if seg.p_offset + seg.p_filesz > len(data):
                    raise ParseError(
                        f"phdr[{i}] file range {seg.p_offset:#x}+{seg.p_filesz:#x} "
                        f"extends past EOF ({len(data):#x})")
                if seg.p_filesz > seg.p_memsz:
                    raise ParseError(
                        f"phdr[{i}] p_filesz > p_memsz")
            elf.segments.append(seg)

    # --- section headers ------------------------------------------------
    if e_shoff and real_shnum:
        if real_shnum > 1_000_000:
            raise ParseError(f"implausible section count {real_shnum}")
        if e_shoff + real_shnum * sh_stride > len(data):
            raise ParseError("section header table extends past EOF")
        if real_shstrndx >= real_shnum:
            raise ParseError(f"e_shstrndx={real_shstrndx} >= shnum={real_shnum}")
        shstr_sh = Section(*struct.unpack(
            SHDR_FMT,
            data[e_shoff + real_shstrndx * sh_stride:
                 e_shoff + real_shstrndx * sh_stride + SHDR_SIZE]))
        shstr = _slice(data, shstr_sh.sh_offset, shstr_sh.sh_size)
        for i in range(real_shnum):
            raw = data[e_shoff + i * sh_stride:e_shoff + (i + 1) * sh_stride]
            sec = Section(*struct.unpack(SHDR_FMT, raw))
            if sec.sh_type != SHT_NOBITS and sec.sh_size:
                if sec.sh_offset + sec.sh_size > len(data):
                    raise ParseError(
                        f"shdr[{i}] file range extends past EOF")
            if 0 <= sec.sh_name < len(shstr):
                end = shstr.find(b"\0", sec.sh_name)
                if end >= 0:
                    sec.name = shstr[sec.sh_name:end].decode("latin-1")
            elf.sections.append(sec)
        elf.extended = {
            "phnum": extended_phnum,
            "shnum": extended_shnum,
            "shstrndx": extended_shstr,
        }

    # --- PT_DYNAMIC -----------------------------------------------------
    for seg in elf.segments:
        if seg.p_type != PT_DYNAMIC:
            continue
        off = seg.p_offset
        end = off + seg.p_filesz
        while off + DYN_SIZE <= end:
            tag, val = struct.unpack_from(DYN_FMT, data, off)
            if tag == DT_NULL:
                break
            elf.dynamic.setdefault(tag, val)
            off += DYN_SIZE

    return elf


# ---------------------------------------------------------------------------
# Reference layout classification
# ---------------------------------------------------------------------------

@dataclass
class RefResult:
    status: str                     # PARSE_ERROR | SYMBOL_NOT_FOUND |
                                    # SYMBOL_NOT_FILE_BACKED | SAFE_TAIL |
                                    # AMBIGUOUS_ONLY | NO_SPACE
    reason: str = ""
    symbol_value: Optional[int] = None
    symbol_offset: Optional[int] = None
    safe_tails: list[dict] = field(default_factory=list)
    largest_zero_run: int = 0
    largest_zero_run_offset: Optional[int] = None
    exec_segments: list[dict] = field(default_factory=list)
    extended: dict = field(default_factory=dict)


def _largest_zero_run(data: bytes, start: int, end: int) -> tuple[int, Optional[int]]:
    best = 0
    best_start = None
    run = 0
    run_start = 0
    for i in range(start, min(end, len(data))):
        if data[i] == 0:
            if run == 0:
                run_start = i
            run += 1
            if run > best:
                best = run
                best_start = run_start
        else:
            run = 0
    return best, best_start


def _safe_tails(elf: ParsedELF, size: int) -> list[dict]:
    """File-backed zero tails inside each executable segment's last page.

    A candidate is only accepted when every byte from p_offset+p_filesz up to
    the mapping's page boundary (or the first byte claimed by another segment
    or section) is zero and present in the file.
    """
    page = elf.pagesize
    claims = elf.claimed_ranges()
    out: list[dict] = []
    for idx, seg in enumerate(elf.exec_segments()):
        tail_start = seg.p_offset + seg.p_filesz
        rem = tail_start % page
        slack = page - rem if rem else 0
        if slack <= 0:
            continue
        limit = min(tail_start + slack, len(elf.data))
        for rng in claims:
            s = rng.start
            if tail_start <= s < limit:
                limit = s
        # Require an unbroken zero prefix.
        z = tail_start
        while z < limit and elf.data[z] == 0:
            z += 1
        length = z - tail_start
        if length:
            out.append({
                "segment": idx,
                "offset": tail_start,
                "length": length,
                "fits": length >= size,
            })
    return out


def reference_analysis(data: bytes, symname: str, size: int,
                       pagesize: int = 4096) -> RefResult:
    try:
        elf = parse_reference(data, pagesize)
    except ParseError as exc:
        return RefResult("PARSE_ERROR", str(exc))

    exec_segs = [
        {
            "offset": s.p_offset,
            "vaddr": s.p_vaddr,
            "filesz": s.p_filesz,
            "memsz": s.p_memsz,
            "flags": s.p_flags,
        }
        for s in elf.exec_segments()
    ]
    tails = _safe_tails(elf, size)
    ext = dict(elf.extended)

    if not elf.exec_segments():
        return RefResult("PARSE_ERROR", "no executable PT_LOAD segment",
                         safe_tails=tails, exec_segments=exec_segs, extended=ext)

    st_value = elf.resolve_symbol(symname)
    if st_value is None:
        return RefResult("SYMBOL_NOT_FOUND", f"{symname} not in dynsym",
                         safe_tails=tails, exec_segments=exec_segs, extended=ext)

    # The symbol's instruction must live in a *file-backed* executable range:
    # bytes in p_memsz but beyond p_filesz are BSS and cannot be patched by a
    # file write.
    sym_off = None
    for seg in elf.exec_segments():
        if seg.p_vaddr <= st_value < seg.p_vaddr + seg.p_filesz:
            sym_off = seg.p_offset + (st_value - seg.p_vaddr)
            break
    if sym_off is None:
        return RefResult("SYMBOL_NOT_FILE_BACKED",
                         f"{symname} st_value={st_value:#x} is not in a "
                         f"file-backed executable range",
                         symbol_value=st_value, safe_tails=tails,
                         exec_segments=exec_segs, extended=ext)

    largest, largest_off = _largest_zero_run(
        data,
        min(s.p_offset for s in elf.exec_segments()),
        max(s.p_offset + s.p_filesz for s in elf.exec_segments()))

    fitting = [t for t in tails if t["fits"]]
    if fitting:
        return RefResult("SAFE_TAIL", "file-backed zero tail large enough",
                         symbol_value=st_value, symbol_offset=sym_off,
                         safe_tails=tails, largest_zero_run=largest,
                         largest_zero_run_offset=largest_off,
                         exec_segments=exec_segs, extended=ext)
    if largest >= size:
        return RefResult("AMBIGUOUS_ONLY",
                         "only an in-segment zero run large enough; may be data",
                         symbol_value=st_value, symbol_offset=sym_off,
                         safe_tails=tails, largest_zero_run=largest,
                         largest_zero_run_offset=largest_off,
                         exec_segments=exec_segs, extended=ext)
    return RefResult("NO_SPACE", "no file-backed tail and no ambiguous run large enough",
                     symbol_value=st_value, symbol_offset=sym_off,
                     safe_tails=tails, largest_zero_run=largest,
                     largest_zero_run_offset=largest_off,
                     exec_segments=exec_segs, extended=ext)


# ---------------------------------------------------------------------------
# Faithful re-implementation of the current scanner
# ---------------------------------------------------------------------------

def _c_read(data: bytes, off: int, n: int) -> bytes:
    """Emulate read(). A short read is not an error in the C code."""
    return _slice(data, off, n)


def _c_str(buf: bytes, maxlen: int) -> str:
    """Emulate read() into a fixed buffer followed by forced NUL."""
    if len(buf) > maxlen:
        buf = buf[:maxlen]
    if len(buf) < maxlen:
        buf = buf + b"\0" * (maxlen - len(buf))
    nul = buf.find(b"\0")
    if nul >= 0:
        buf = buf[:nul]
    return buf.decode("latin-1")


@dataclass
class CurrentResult:
    status: str                     # ACCEPT | REJECT
    offset: Optional[int] = None
    reason: str = ""
    messages: list[str] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    exec_offset: Optional[int] = None
    exec_filesz: Optional[int] = None
    slack: Optional[int] = None
    largest_zero_run: Optional[int] = None


def current_scan(data: bytes, symname: str, size: int,
                 pagesize: int = 4096) -> CurrentResult:
    """Mirror find_hook_target()/find_code_cave() from elf_parser.c."""
    res = CurrentResult("REJECT")
    msgs = res.messages
    defects = res.defects

    if len(data) < EHDR_SIZE:
        res.reason = "read ELF header failed"
        msgs.append(res.reason)
        return res

    hdr = struct.unpack_from(EHDR_FMT, data, 0)
    (ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = hdr

    if data[0:4] != b"\x7fELF":
        res.reason = "invalid ELF"
        msgs.append(res.reason)
        return res
    if data[4] != ELFCLASS64:
        defects.append("does not validate EI_CLASS")
    if data[5] != ELFDATA2LSB:
        defects.append("does not validate EI_DATA")
    if data[6] != EV_CURRENT:
        defects.append("does not validate EI_VERSION")
    if e_machine != EM_AARCH64:
        defects.append(f"does not validate e_machine (saw {e_machine})")
    if e_ehsize != EHDR_SIZE:
        defects.append(f"does not validate e_ehsize (saw {e_ehsize})")
    if e_shentsize not in (0, SHDR_SIZE):
        defects.append(f"uses sizeof(Elf64_Shdr), not e_shentsize ({e_shentsize})")

    if e_phentsize != PHDR_SIZE:
        res.reason = f"invalid phentsize: {e_phentsize}"
        msgs.append(res.reason)
        return res

    exec_off = None
    exec_filesz = 0
    exec_vaddr = 0
    first_exec = None
    extra_exec = 0
    for i in range(e_phnum):
        raw = _c_read(data, e_phoff + i * PHDR_SIZE, PHDR_SIZE)
        if len(raw) < PHDR_SIZE:
            defects.append(f"phdr[{i}] short read not detected")
            raw = raw + b"\0" * (PHDR_SIZE - len(raw))
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack(PHDR_FMT, raw)
        if p_type == PT_LOAD and (p_flags & PF_X):
            exec_off = p_offset
            exec_filesz = p_filesz
            exec_vaddr = p_vaddr
            first_exec = i
            break

    # Count later executable segments for diagnostic purposes only. The C
    # scanner stops at the first one, so these reads are not part of its
    # success path.
    if first_exec is not None:
        for i in range(first_exec + 1, e_phnum):
            raw = _c_read(data, e_phoff + i * PHDR_SIZE, PHDR_SIZE)
            if len(raw) < PHDR_SIZE:
                break
            p_type, p_flags = struct.unpack_from("<II", raw, 0)
            if p_type == PT_LOAD and (p_flags & PF_X):
                extra_exec += 1
        if extra_exec:
            defects.append(
                f"stops at the first of {extra_exec + 1} executable PT_LOAD "
                f"segments")

    res.exec_offset = exec_off
    res.exec_filesz = exec_filesz

    if exec_off == 0 and exec_vaddr == 0:
        res.reason = "no executable PT_LOAD segment found"
        msgs.append(res.reason)
        return res

    # --- section table (uses sizeof(Elf64_Shdr) as stride) --------------
    raw = _c_read(data, e_shoff + e_shstrndx * SHDR_SIZE, SHDR_SIZE)
    if len(raw) < SHDR_SIZE:
        defects.append("short read of shstrndx section header not detected")
        raw = raw + b"\0" * (SHDR_SIZE - len(raw))
    str_shdr = Section(*struct.unpack(SHDR_FMT, raw))

    dynstr = 0
    dynsym_offset = 0
    dynsym_size = 0
    for i in range(min(e_shnum, 1_000_000)):
        raw = _c_read(data, e_shoff + i * SHDR_SIZE, SHDR_SIZE)
        if len(raw) < SHDR_SIZE:
            defects.append(f"shdr[{i}] short read not detected")
            raw = raw + b"\0" * (SHDR_SIZE - len(raw))
        shdr = Section(*struct.unpack(SHDR_FMT, raw))
        name = _c_str(_c_read(data, shdr.sh_name + str_shdr.sh_offset, 99), 99)
        if name == ".dynstr":
            dynstr = shdr.sh_offset
        if name == ".dynsym":
            dynsym_offset = shdr.sh_offset
            dynsym_size = shdr.sh_size

    if dynstr == 0 or dynsym_offset == 0:
        res.reason = ".dynstr or .dynsym not found"
        msgs.append(res.reason)
        return res

    # --- dynsym scan ----------------------------------------------------
    hook_target = 0
    count = int(dynsym_size // SYM_SIZE)
    for i in range(count):
        raw = _c_read(data, dynsym_offset + i * SYM_SIZE, SYM_SIZE)
        if len(raw) < SYM_SIZE:
            defects.append(f"dynsym[{i}] short read not detected")
            raw = raw + b"\0" * (SYM_SIZE - len(raw))
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack(SYM_FMT, raw)
        name = _c_str(_c_read(data, dynstr + st_name, 199), 199)
        if name == symname:
            hook_target = (st_value - exec_vaddr + exec_off) & 0xFFFFFFFFFFFFFFFF
            if not (exec_vaddr <= st_value < exec_vaddr + exec_filesz):
                defects.append("does not check that the symbol is file-backed")
            break

    if hook_target == 0:
        res.reason = f"symbol {symname} not found"
        msgs.append(res.reason)
        return res

    first = _c_read(data, hook_target, 4)
    if len(first) < 4:
        defects.append("short read of hook instruction not detected")
        first = first + b"\0" * (4 - len(first))
    first_insn = struct.unpack("<I", first)[0]

    for _ in range(2):
        if first_insn in (0xD503233F, 0xD503237F, 0xD503241F,
                          0xD503245F, 0xD503249F, 0xD50324DF):
            hook_target += 4
            first = _c_read(data, hook_target, 4)
            if len(first) < 4:
                first = first + b"\0" * (4 - len(first))
            first_insn = struct.unpack("<I", first)[0]
            continue
        break

    # --- find_code_cave -------------------------------------------------
    tail_off = exec_off + exec_filesz
    page_off = tail_off % pagesize
    slack = pagesize - page_off if page_off else 0
    res.slack = slack
    if size <= slack:
        res.status = "ACCEPT"
        res.offset = tail_off
        msgs.append(f"tail slack {slack} >= {size}")
        if not (tail_off + size <= len(data)):
            defects.append("accepts a tail offset past EOF")
        return res

    msgs.append(f"shellcode ({size}) exceeds tail-page slack ({slack} bytes)")

    run_start = 0
    run_len = 0
    max_run_len = 0
    max_run_start = None
    lo = exec_off
    hi = min(exec_off + exec_filesz, len(data))
    if hi < exec_off + exec_filesz:
        defects.append("does not check executable segment file bounds")
    for i in range(lo, hi):
        if data[i] == 0:
            if not run_len:
                run_start = i
            run_len += 1
            if run_len > max_run_len:
                max_run_len = run_len
                max_run_start = run_start
            if run_len >= size:
                res.status = "ACCEPT"
                res.offset = run_start
                res.largest_zero_run = max_run_len
                msgs.append(f"using code cave at {run_start:#x}")
                return res
        else:
            run_len = 0

    res.largest_zero_run = max_run_len
    res.largest_zero_run_offset = max_run_start  # type: ignore[attr-defined]
    res.reason = (f"no code cave large enough (need {size}, "
                  f"largest found {max_run_len})")
    msgs.append(res.reason)
    return res


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare(ref: RefResult, cur: CurrentResult, size: int) -> tuple[str, str]:
    if ref.status in ("PARSE_ERROR", "SYMBOL_NOT_FOUND", "SYMBOL_NOT_FILE_BACKED"):
        if cur.status == "ACCEPT":
            return ("FALSE_POSITIVE",
                    f"current accepted but reference rejected: {ref.reason}")
        return ("UNSUPPORTED_AGREE",
                f"both reject; reference: {ref.reason}")

    if cur.status == "ACCEPT":
        if ref.status == "SAFE_TAIL":
            off = cur.offset
            for tail in ref.safe_tails:
                if (tail["fits"] and off is not None and
                        tail["offset"] <= off and
                        off + size <= tail["offset"] + tail["length"]):
                    return ("AGREE_ACCEPT", "both accept a file-backed zero tail")
            return ("AGREE_ACCEPT",
                    "both accept, but offsets differ (current uses another region)")
        if ref.status == "AMBIGUOUS_ONLY":
            return ("FALSE_POSITIVE",
                    "current used an in-segment zero run that may be real data")
        return ("FALSE_POSITIVE",
                f"current accepted but reference found no space ({ref.status})")

    # current rejected
    if ref.status == "SAFE_TAIL":
        return ("FALSE_NEGATIVE",
                "reference found a file-backed zero tail the current scanner missed")
    if ref.status == "AMBIGUOUS_ONLY":
        return ("AGREE_REJECT_CAUTIOUS",
                "both refuse; an ambiguous zero run exists but is not safe to use")
    return ("AGREE_REJECT", f"both reject; reference: {ref.reason}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyse_file(path: str, symname: str, size: int,
                 pagesize: int = 4096) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    ref = reference_analysis(data, symname, size, pagesize)
    cur = current_scan(data, symname, size, pagesize)
    verdict, explanation = compare(ref, cur, size)
    return {
        "path": path,
        "size": len(data),
        "symbol": symname,
        "payload": size,
        "pagesize": pagesize,
        "reference": {
            "status": ref.status,
            "reason": ref.reason,
            "symbol_value": ref.symbol_value,
            "symbol_offset": ref.symbol_offset,
            "safe_tails": ref.safe_tails,
            "largest_zero_run": ref.largest_zero_run,
            "largest_zero_run_offset": ref.largest_zero_run_offset,
            "exec_segments": ref.exec_segments,
            "extended": ref.extended,
        },
        "current": {
            "status": cur.status,
            "offset": cur.offset,
            "reason": cur.reason,
            "messages": cur.messages,
            "defects": cur.defects,
            "exec_offset": cur.exec_offset,
            "exec_filesz": cur.exec_filesz,
            "slack": cur.slack,
            "largest_zero_run": cur.largest_zero_run,
        },
        "verdict": verdict,
        "explanation": explanation,
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="ELF files to analyse (read-only)")
    ap.add_argument("--symbol", default=TARGET_SYMBOL,
                    help="dynamic symbol to resolve")
    ap.add_argument("--size", type=int, default=464,
                    help="payload size in bytes (default: 464)")
    ap.add_argument("--pagesize", type=int, default=4096,
                    help="target page size (default: 4096)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    results = []
    for path in args.paths:
        try:
            results.append(analyse_file(path, args.symbol, args.size,
                                        args.pagesize))
        except OSError as exc:
            results.append({"path": path, "error": str(exc)})

    if args.json:
        json.dump(results, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    for r in results:
        print("=" * 78)
        if "error" in r:
            print(f"{r['path']}: {r['error']}")
            continue
        print(f"{r['path']}  ({r['size']} bytes, payload {r['payload']})")
        print(f"  reference : {r['reference']['status']} - {r['reference']['reason']}")
        c = r["current"]
        print(f"  current   : {c['status']}"
              + (f" @ {c['offset']:#x}" if c["offset"] is not None else "")
              + f" - {c['reason'] or 'accepted'}")
        print(f"  verdict   : {r['verdict']} - {r['explanation']}")
        if r["reference"]["safe_tails"]:
            for t in r["reference"]["safe_tails"]:
                print(f"    safe tail: seg {t['segment']} off {t['offset']:#x} "
                      f"len {t['length']} fits={t['fits']}")
        if c["defects"]:
            print(f"    current defects: {', '.join(c['defects'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
