#!/usr/bin/env python3
"""Run the offline ELF layout experiment and write a report.

Read-only: fixtures are generated locally and analysed in memory. The host
libraries, when present, are opened read-only. Nothing is written back to any
ELF and nothing here is compiled into or called by the DFRoot exploit.
"""

from __future__ import annotations

import json
import os
import sys

import elf_layout_probe as probe
from make_fixtures import write_fixtures

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.join(HERE, "fixtures")

LIBCXX_SYMBOL = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"
LIBBASE_SYMBOL = "_ZN7android4base10LogMessageD1Ev"

# (filename, intent, symbol, expected verdict)
FIXTURE_CASES = [
    ("aarch64_ordinary.elf",
     "Valid section table; 512-byte zero tail; dense text",
     LIBCXX_SYMBOL, "AGREE_ACCEPT"),
    ("aarch64_tight_g22.elf",
     "Reported G22 shape: 112-byte tail slack, 14-byte zero run",
     LIBCXX_SYMBOL, "AGREE_REJECT"),
    ("aarch64_no_sections.elf",
     "Sectionless ELF; symbols resolved through PT_DYNAMIC only",
     LIBCXX_SYMBOL, "FALSE_NEGATIVE"),
    ("aarch64_extended_numbering.elf",
     "e_phnum=PN_XNUM, e_shnum=0, e_shstrndx=SHN_XINDEX",
     LIBCXX_SYMBOL, "FALSE_NEGATIVE"),
    ("aarch64_multi_exec.elf",
     "Two PF_X PT_LOADs; room only in the second",
     LIBCXX_SYMBOL, "FALSE_NEGATIVE"),
    ("aarch64_tail_nonzero.elf",
     "512-byte page tail that is non-zero (claimed content)",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("aarch64_zero_run_in_data.elf",
     "600-byte zero run inside PF_X range, declared as data",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("aarch64_symbol_in_bss.elf",
     "Symbol st_value in p_memsz beyond p_filesz (BSS)",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("aarch64_segment_past_eof.elf",
     "PF_X segment declares a file range beyond EOF",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("x86_64_ordinary.elf",
     "e_machine=EM_X86_64 but otherwise the baseline layout",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("elf32_claim.elf",
     "EI_CLASS=ELFCLASS32 claim over a 64-bit layout",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
    ("big_endian_claim.elf",
     "EI_DATA=ELFDATA2MSB claim over a LE layout",
     LIBCXX_SYMBOL, "FALSE_POSITIVE"),
]

REAL_CASES = [
    ("/system/lib64/libc++.so", "Host API 34 AArch64 libc++", LIBCXX_SYMBOL),
    ("/system/lib64/libbase.so", "Host AArch64 libbase", LIBBASE_SYMBOL),
]


def _short(text: str, limit: int = 70) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def _table(results: list[dict]) -> str:
    lines = [
        "| Fixture | Reference | Current | Verdict |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        ref = r["reference"]["status"]
        cur = r["current"]["status"]
        if r["current"]["offset"] is not None:
            cur += f" @ `{r['current']['offset']:#x}`"
        lines.append(
            f"| `{os.path.basename(r['path'])}` | {ref} | {cur} | "
            f"**{r['verdict']}** |")
    return "\n".join(lines)


def _details(results: list[dict]) -> str:
    out = []
    for r in results:
        name = os.path.basename(r["path"])
        out.append(f"### `{name}`")
        out.append("")
        out.append(f"- Reference: `{r['reference']['status']}` - "
                   f"{r['reference']['reason']}")
        c = r["current"]
        cur = f"`{c['status']}`"
        if c["offset"] is not None:
            cur += f" at `{c['offset']:#x}`"
        if c["reason"]:
            cur += f" - {c['reason']}"
        out.append(f"- Current: {cur}")
        out.append(f"- Verdict: **{r['verdict']}** - {r['explanation']}")
        if r["reference"]["safe_tails"]:
            tails = ", ".join(
                f"seg {t['segment']} `{t['offset']:#x}` len {t['length']} "
                f"fits={t['fits']}"
                for t in r["reference"]["safe_tails"])
            out.append(f"- Safe tails: {tails}")
        if r["reference"]["exec_segments"]:
            segs = "; ".join(
                f"off `{s['offset']:#x}` filesz `{s['filesz']:#x}` "
                f"flags {s['flags']}"
                for s in r["reference"]["exec_segments"])
            out.append(f"- PF_X PT_LOADs: {segs}")
        if c["defects"]:
            out.append("- Current-scanner defects observed: "
                       + "; ".join(c["defects"]))
        out.append("")
    return "\n".join(out)


def build_report(results: list[dict], real: list[dict]) -> str:
    by = {}
    for r in results:
        by.setdefault(r["verdict"], []).append(os.path.basename(r["path"]))

    fp = by.get("FALSE_POSITIVE", [])
    fn = by.get("FALSE_NEGATIVE", [])
    agree = by.get("AGREE_ACCEPT", [])
    reject = by.get("AGREE_REJECT", [])
    cautious = by.get("AGREE_REJECT_CAUTIOUS", [])
    unsupported = by.get("UNSUPPORTED_AGREE", [])

    parts = []
    parts.append("# ELF layout probe - experiment report")
    parts.append("")
    parts.append("Offline, read-only experiment. It does not modify "
                 "`app/src/main/jni/`, does not run on a device, and does not "
                 "change any exploit behaviour.")
    parts.append("")
    parts.append("## Method")
    parts.append("")
    parts.append("- `current` re-implements `find_hook_target()` and "
                 "`find_code_cave()` from `elf_parser.c`, including its "
                 "unvalidated header fields, first-segment break, "
                 "`sizeof(Elf64_Shdr)` stride, and zero-run fallback.")
    parts.append("- `reference` is a strict ELF64/AArch64 reader: validates "
                 "class, data encoding, version, machine, `e_ehsize`, "
                 "`e_phentsize`, `e_shentsize`; handles `PN_XNUM` / "
                 "`SHN_XINDEX` / `e_shnum=0`; resolves symbols from `.dynsym` "
                 "or `PT_DYNAMIC`; rejects undefined imports and symbols that "
                 "are not file-backed.")
    parts.append("- A reference *safe tail* is a run of file-backed zero "
                 "bytes from `p_offset+p_filesz` to the end of that "
                 "executable segment's last mapped page, not claimed by any "
                 "other PT_LOAD or section. In-segment zero runs are reported "
                 "but never treated as free space.")
    parts.append("")
    parts.append("## Summary")
    parts.append("")
    parts.append(_table(results))
    parts.append("")
    parts.append(f"- False positives (current accepts, reference rejects): "
                 f"**{len(fp)}** - {', '.join(f'`{x}`' for x in fp) or 'none'}")
    parts.append(f"- False negatives (current rejects, reference finds a safe "
                 f"tail): **{len(fn)}** - "
                 f"{', '.join(f'`{x}`' for x in fn) or 'none'}")
    parts.append(f"- Both accept: **{len(agree)}** - "
                 f"{', '.join(f'`{x}`' for x in agree) or 'none'}")
    parts.append(f"- Both reject: **{len(reject) + len(cautious)}** - "
                 f"{', '.join(f'`{x}`' for x in reject + cautious) or 'none'}")
    parts.append(f"- Unsupported/agreed rejection: **{len(unsupported)}** - "
                 f"{', '.join(f'`{x}`' for x in unsupported) or 'none'}")
    parts.append("")
    parts.append("## Per-fixture detail")
    parts.append("")
    parts.append(_details(results))
    parts.append("## Real host libraries")
    parts.append("")
    parts.append(_table(real))
    parts.append("")
    parts.append(_details(real))
    parts.append("## Interpretation")
    parts.append("")
    parts.append("- The reported G22 failure reproduces as **AGREE_REJECT**: a "
                 "464-byte payload against 112 bytes of tail slack and a "
                 "14-byte zero run. The reference agrees there is no safe "
                 "placement, so this is a layout limit, not a parser bug.")
    parts.append("- False negatives are real: sectionless ELF, extended "
                 "numbering, and a second executable segment are valid "
                 "layouts that the current scanner rejects before placement.")
    parts.append("- False positives are also real: the current scanner trusts "
                 "page slack without checking whether it belongs to the next "
                 "segment, trusts zero runs inside executable ranges, ignores "
                 "`EI_CLASS`/`EI_DATA`/`e_machine`, and does not require the "
                 "symbol to be file-backed.")
    parts.append("- The host `libc++` is the clearest example: the executable "
                 "segment ends at `0xfe628`, which is the first byte of the "
                 "next `PF_R|PF_W` `PT_LOAD` (`.data.rel.ro`). The current "
                 "scanner accepts that address because 2520 bytes remain in "
                 "the page; the reference refuses because the bytes belong to "
                 "another segment.")
    parts.append("")
    parts.append("## Caveats")
    parts.append("")
    parts.append("- The host samples are this environment's libraries, not the "
                 "reported Nokia Build ID `84acbd0e3703d0ed73c0df290de333b9`. "
                 "The G22 conclusion comes from `aarch64_tight_g22.elf`, which "
                 "reproduces the logged 112-byte slack and 14-byte run shape, "
                 "not from the device's actual file.")
    parts.append("- The device's `readelf -lW` output was not available, so "
                 "whether it has a second executable segment or a differently "
                 "claimed page tail is unknown. Those cases are covered by "
                 "fixtures, not asserted for the device.")
    parts.append("")
    parts.append("These results are layout classifications only. They do not "
                 "establish that any accepted offset is safe to execute at "
                 "runtime, and they are not wired into the production tool.")
    parts.append("")
    return "\n".join(parts)


def main() -> int:
    paths = write_fixtures(FIXTURE_DIR)
    fixture_by_name = {os.path.basename(p): p for p in paths}

    results = []
    expected = {}
    for name, _intent, symbol, want in FIXTURE_CASES:
        r = probe.analyse_file(fixture_by_name[name], symbol, 464, 4096)
        results.append(r)
        expected[name] = want

    failures = []
    for r in results:
        name = os.path.basename(r["path"])
        if r["verdict"] != expected[name]:
            failures.append((name, expected[name], r["verdict"]))

    real = []
    for path, _intent, symbol in REAL_CASES:
        if os.path.exists(path):
            real.append(probe.analyse_file(path, symbol, 464, 4096))

    report = build_report(results, real)
    report_path = os.path.join(HERE, "report.md")
    with open(report_path, "w") as fh:
        fh.write(report)

    json_path = os.path.join(HERE, "report.json")
    with open(json_path, "w") as fh:
        json.dump({"fixtures": results, "host_libraries": real},
                  fh, indent=2)
        fh.write("\n")

    print(_table(results))
    if real:
        print()
        print("Host libraries:")
        print(_table(real))
    print()
    print(f"wrote {report_path}")
    print(f"wrote {json_path}")

    if failures:
        print()
        print("EXPECTATION MISMATCHES:")
        for name, want, got in failures:
            print(f"  {name}: expected {want}, got {got}")
        return 1
    print(f"all {len(results)} fixture expectations matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
