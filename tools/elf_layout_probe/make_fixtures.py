#!/usr/bin/env python3
"""Generate synthetic ELF64/AArch64 fixtures for the offline layout probe.

Every fixture is fabricated here; none is copied from a device. The one real
inputs used by the experiment are the host's own /system/lib64/libc++.so and
libbase.so, read-only, when present.

The fixtures exercise the categories the diagnosis calls out:

  ordinary section table, sectionless, extended numbering, multiple executable
  segments, tight space (the reported Nokia G22 shape), non-zero tail, zero run
  inside data, symbol in BSS, segment past EOF, foreign machine, ELF32 claim,
  big-endian claim.
"""

from __future__ import annotations

import os
import struct
import sys

from elf_layout_probe import (
    EHDR_FMT, EHDR_SIZE, PHDR_FMT, PHDR_SIZE, SHDR_FMT, SHDR_SIZE,
    SYM_FMT, SYM_SIZE, DYN_FMT, DYN_SIZE,
    PT_LOAD, PT_DYNAMIC, PF_R, PF_W, PF_X,
    SHT_NULL, SHT_PROGBITS, SHT_STRTAB, SHT_HASH, SHT_DYNAMIC, SHT_DYNSYM,
    DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT,
    SHN_XINDEX, PN_XNUM, EM_AARCH64, TARGET_SYMBOL,
)

PAGE = 0x1000
TEXT_OFF = 0x1000
TEXT_VADDR = 0x10000
META_OFF = 0x2000
RW_VADDR = 0x30000
SECOND_OFF = 0x3000
SECOND_VADDR = 0x20000

STB_GLOBAL = 1
STT_FUNC = 2


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _shdr(name: str, sh_type: int, flags: int, addr: int, off: int,
          size: int, *, link: int = 0, info: int = 0,
          align: int = 1, entsize: int = 0) -> dict:
    return dict(name=name, sh_type=sh_type, sh_flags=flags, sh_addr=addr,
                sh_offset=off, sh_size=size, sh_link=link, sh_info=info,
                sh_addralign=align, sh_entsize=entsize)


def _phdr(p_type: int, flags: int, off: int, vaddr: int,
          filesz: int, memsz: int, align: int = PAGE) -> dict:
    return dict(p_type=p_type, p_flags=flags, p_offset=off, p_vaddr=vaddr,
                p_filesz=filesz, p_memsz=memsz, p_align=align)


def _emit(buf: bytearray, segments: list[dict], sections: list[dict], *,
          e_machine: int = EM_AARCH64, ei_class: int = 2,
          ei_data: int = 1, extended: bool = False) -> bytes:
    """Write ehdr/phdrs/shdrs and the shstrtab into buf; return bytes."""
    used = 0
    for seg in segments:
        used = max(used, seg["p_offset"] + seg["p_filesz"])
    for sec in sections:
        if sec["sh_type"] != 8 and sec["sh_size"]:
            used = max(used, sec["sh_offset"] + sec["sh_size"])

    if sections:
        # Build shstrtab. Section 0 keeps name offset 0.
        blob = bytearray(b"\0")
        name_off = {"": 0}
        for sec in sections:
            nm = sec["name"]
            if nm not in name_off:
                name_off[nm] = len(blob)
                blob += nm.encode("latin-1") + b"\0"
        shstr_name_off = name_off.setdefault(".shstrtab", len(blob))
        if shstr_name_off == len(blob):
            blob += b".shstrtab\0"

        shstr_off = _align(used, PAGE)
        need = shstr_off + len(blob)
        if len(buf) < need:
            buf.extend(b"\0" * (need - len(buf)))
        buf[shstr_off:shstr_off + len(blob)] = blob

        shstr_index = len(sections)
        sections = sections + [_shdr(".shstrtab", SHT_STRTAB, 0, 0,
                                     shstr_off, len(blob))]
        shoff = _align(shstr_off + len(blob), 8)
        need = shoff + len(sections) * SHDR_SIZE
        if len(buf) < need:
            buf.extend(b"\0" * (need - len(buf)))

        for i, sec in enumerate(sections):
            vals = (name_off[sec["name"]], sec["sh_type"], sec["sh_flags"],
                    sec["sh_addr"], sec["sh_offset"], sec["sh_size"],
                    sec["sh_link"], sec["sh_info"], sec["sh_addralign"],
                    sec["sh_entsize"])
            if i == 0 and extended:
                # sh_size / sh_link / sh_info carry the real counts.
                vals = (0, SHT_NULL, 0, 0, 0, len(sections),
                        shstr_index, len(segments), 0, 0)
            struct.pack_into(SHDR_FMT, buf, shoff + i * SHDR_SIZE, *vals)
        e_shoff = shoff
        e_shnum = 0 if extended else len(sections)
        e_shstrndx = SHN_XINDEX if extended else shstr_index
        total = max(used, shoff + len(sections) * SHDR_SIZE,
                    shstr_off + len(blob))
    else:
        e_shoff = 0
        e_shnum = 0
        e_shstrndx = 0
        total = used

    phoff = 64
    for i, seg in enumerate(segments):
        struct.pack_into(PHDR_FMT, buf, phoff + i * PHDR_SIZE,
                         seg["p_type"], seg["p_flags"], seg["p_offset"],
                         seg["p_vaddr"], seg["p_vaddr"], seg["p_filesz"],
                         seg["p_memsz"], seg["p_align"])

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = ei_class
    ident[5] = ei_data
    ident[6] = 1
    struct.pack_into(EHDR_FMT, buf, 0, bytes(ident), 3, e_machine, 1, 0,
                     phoff, e_shoff, 0, EHDR_SIZE, PHDR_SIZE,
                     PN_XNUM if extended else len(segments),
                     SHDR_SIZE, e_shnum, e_shstrndx)
    return bytes(buf[:total])


def build_library(*, text_len: int = 0xE00, second_len: int = 0xE00,
                  sym_off: int = 0x20, zero_run: int | None = None,
                  zero_run_at: int | None = None, tail_byte: int = 0,
                  multi_exec: bool = False, sections: bool = True,
                  extended: bool = False, machine: int = EM_AARCH64,
                  ei_class: int = 2, ei_data: int = 1,
                  sym_in_bss: bool = False,
                  break_segment_bounds: bool = False,
                  dynamic: bool = False,
                  symname: str = TARGET_SYMBOL) -> bytes:
    buf = bytearray(b"\0" * 0x8000)

    # --- executable text -------------------------------------------------
    text = bytearray(b"\x01" * text_len)
    if zero_run:
        at = zero_run_at if zero_run_at is not None else sym_off + 0x10
        if at < 0 or at + zero_run > text_len:
            raise ValueError("zero run does not fit in text")
        text[at:at + zero_run] = b"\0" * zero_run
    buf[TEXT_OFF:TEXT_OFF + text_len] = text

    slack_end = _align(TEXT_OFF + text_len, PAGE)
    if tail_byte:
        buf[TEXT_OFF + text_len:slack_end] = \
            bytes([tail_byte]) * (slack_end - (TEXT_OFF + text_len))

    # --- metadata in the RW segment -------------------------------------
    dynstr = b"\0" + symname.encode("latin-1") + b"\0"
    dynstr_off = META_OFF
    buf[dynstr_off:dynstr_off + len(dynstr)] = dynstr

    dynsym_off = _align(dynstr_off + len(dynstr), 8)
    if sym_in_bss:
        st_value = TEXT_VADDR + text_len + 0x10
    else:
        st_value = TEXT_VADDR + sym_off
    entry0 = b"\0" * SYM_SIZE
    entry1 = struct.pack(SYM_FMT, 1, (STB_GLOBAL << 4) | STT_FUNC, 0, 1,
                         st_value, 4)
    buf[dynsym_off:dynsym_off + SYM_SIZE * 2] = entry0 + entry1
    meta_end = dynsym_off + SYM_SIZE * 2

    segments = [
        _phdr(PT_LOAD, PF_R | PF_X, TEXT_OFF, TEXT_VADDR, text_len,
              text_len + (0x2000 if sym_in_bss else 0)),
    ]

    if multi_exec:
        second = bytearray(b"\x02" * second_len)
        buf[SECOND_OFF:SECOND_OFF + second_len] = second
        seg = _phdr(PT_LOAD, PF_R | PF_X, SECOND_OFF, SECOND_VADDR,
                    second_len, second_len)
        segments.append(seg)

    dyn_off = hash_off = None
    if dynamic:
        dyn_off = _align(meta_end, 8)
        hash_off = dyn_off + 6 * DYN_SIZE
        # hash: nbucket=1, nchain=2, one bucket, two chains
        hash_bytes = struct.pack("<IIII I", 1, 2, 0, 0, 0)
        buf[hash_off:hash_off + len(hash_bytes)] = hash_bytes
        # vaddrs inside the RW segment
        rw_base = RW_VADDR - META_OFF
        entries = [
            (DT_HASH, rw_base + hash_off),
            (DT_STRTAB, rw_base + dynstr_off),
            (DT_SYMTAB, rw_base + dynsym_off),
            (DT_STRSZ, len(dynstr)),
            (DT_SYMENT, SYM_SIZE),
            (DT_NULL, 0),
        ]
        for i, (tag, val) in enumerate(entries):
            struct.pack_into(DYN_FMT, buf, dyn_off + i * DYN_SIZE, tag, val)
        meta_end = hash_off + len(hash_bytes)

    rw_filesz = meta_end - META_OFF
    segments.append(_phdr(PT_LOAD, PF_R | PF_W, META_OFF, RW_VADDR,
                          rw_filesz, rw_filesz))
    if dynamic:
        segments.append(_phdr(PT_DYNAMIC, PF_R | PF_W, dyn_off,
                              RW_VADDR + (dyn_off - META_OFF),
                              6 * DYN_SIZE, 6 * DYN_SIZE))

    # --- section table ---------------------------------------------------
    secs: list[dict] = []
    if sections:
        secs = [
            _shdr("", SHT_NULL, 0, 0, 0, 0),
            _shdr(".text", SHT_PROGBITS, 0x6, TEXT_VADDR, TEXT_OFF,
                  text_len, align=4),
            _shdr(".dynsym", SHT_DYNSYM, 0x2, RW_VADDR + (dynsym_off - META_OFF),
                  dynsym_off, SYM_SIZE * 2, link=3, info=1,
                  align=8, entsize=SYM_SIZE),
            _shdr(".dynstr", SHT_STRTAB, 0x2, RW_VADDR + (dynstr_off - META_OFF),
                  dynstr_off, len(dynstr), align=1),
        ]
        if multi_exec:
            secs.append(_shdr(".text2", SHT_PROGBITS, 0x6, SECOND_VADDR,
                              SECOND_OFF, second_len, align=4))
        if dynamic:
            secs.append(_shdr(".dynamic", SHT_DYNAMIC, 0x3,
                              RW_VADDR + (dyn_off - META_OFF), dyn_off,
                              6 * DYN_SIZE, link=3, align=8, entsize=DYN_SIZE))
            secs.append(_shdr(".hash", SHT_HASH, 0x2,
                              RW_VADDR + (hash_off - META_OFF), hash_off,
                              20, link=2, align=8, entsize=4))
        if zero_run:
            at = zero_run_at if zero_run_at is not None else sym_off + 0x10
            secs.append(_shdr(".probe_pad", SHT_PROGBITS, 0x2,
                              TEXT_VADDR + at, TEXT_OFF + at, zero_run,
                              align=1))

    data = _emit(buf, segments, secs, e_machine=machine,
                 ei_class=ei_class, ei_data=ei_data, extended=extended)

    if break_segment_bounds:
        # Rewrite phdr[0].p_filesz/p_memsz *after* layout so the declared
        # segment ends past EOF while the tail-slack arithmetic still lands
        # on a 512-byte page remainder.
        end = 0x4E00
        filesz = end - TEXT_OFF
        data = bytearray(data)
        struct.pack_into("<Q", data, 64 + 32, filesz)
        struct.pack_into("<Q", data, 64 + 40, filesz)
        data = bytes(data)

    return data


# ---------------------------------------------------------------------------
# Fixture catalogue
# ---------------------------------------------------------------------------

def fixtures() -> dict[str, bytes]:
    out: dict[str, bytes] = {}

    # 1. Baseline: valid sections, 512 bytes of page slack, dense text.
    out["aarch64_ordinary.elf"] = build_library()

    # 2. The reported Nokia G22 shape: 112 bytes slack, 14-byte zero run.
    out["aarch64_tight_g22.elf"] = build_library(text_len=0xF90, zero_run=14)

    # 3. Sectionless: only PT_DYNAMIC, no section table at all.
    out["aarch64_no_sections.elf"] = build_library(sections=False, dynamic=True)

    # 4. Extended numbering: e_phnum=PN_XNUM, e_shnum=0, e_shstrndx=SHN_XINDEX.
    out["aarch64_extended_numbering.elf"] = build_library(extended=True)

    # 5. Two executable segments; only the second has room.
    out["aarch64_multi_exec.elf"] = build_library(
        text_len=0xF90, multi_exec=True, second_len=0xE00)

    # 6. Page slack exists but is non-zero (belongs to real content).
    out["aarch64_tail_nonzero.elf"] = build_library(tail_byte=0xAA)

    # 7. Large zero run inside .text that is declared as data.
    out["aarch64_zero_run_in_data.elf"] = build_library(
        text_len=0xF90, zero_run=600, zero_run_at=0x40)

    # 8. Symbol st_value lands in p_memsz beyond p_filesz (BSS).
    out["aarch64_symbol_in_bss.elf"] = build_library(sym_in_bss=True)

    # 9. Executable segment declares a file range beyond EOF.
    out["aarch64_segment_past_eof.elf"] = build_library(
        break_segment_bounds=True)

    # 10-12. Header-validation gaps: foreign machine, wrong class, wrong endian.
    x86 = bytearray(build_library())
    struct.pack_into("<H", x86, 18, 62)          # EM_X86_64
    out["x86_64_ordinary.elf"] = bytes(x86)

    elf32 = bytearray(build_library())
    elf32[4] = 1                                  # EI_CLASS = ELFCLASS32
    out["elf32_claim.elf"] = bytes(elf32)

    be = bytearray(build_library())
    be[5] = 2                                     # EI_DATA = ELFDATA2MSB
    out["big_endian_claim.elf"] = bytes(be)

    return out


def write_fixtures(outdir: str) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    written = []
    for name, blob in fixtures().items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        written.append(path)
    return written


def main() -> int:
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
    paths = write_fixtures(outdir)
    for p in paths:
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
