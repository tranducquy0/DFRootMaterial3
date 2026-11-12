# ELF layout probe (offline experiment)

Read-only, offline analysis of ELF64/AArch64 layouts. It exists to answer a
narrow question: **which of the reported failures are parser/symbol problems
and which are genuine layout constraints?**

It is deliberately isolated from the production tool:

- nothing here is compiled into or called by `app/src/main/jni/`;
- no ELF is opened for writing, patched, or executed;
- generated fixtures are synthetic and local;
- the reference reader classifies layouts; it does not claim an offset is safe
  to execute at runtime.

## Run

```sh
cd tools/elf_layout_probe
python3 run_experiment.py
```

This regenerates `fixtures/`, analyses them, and writes `report.md` and
`report.json`. The run fails if any fixture's classification differs from its
expected verdict. Individual files can be inspected with:

```sh
python3 elf_layout_probe.py [--symbol NAME] [--size 464] [--pagesize 4096] FILE...
python3 elf_layout_probe.py --json FILE...
```

If `/system/lib64/libc++.so` and `/system/lib64/libbase.so` exist, the runner
also includes them as read-only "real host library" samples.

## What is compared

Two independent readers run over the same bytes:

| Reader | Behaviour |
| --- | --- |
| `current` | Faithful re-implementation of `find_hook_target()` / `find_code_cave()` from `app/src/main/jni/elf_parser.c` |
| `reference` | Strict ELF64/AArch64 parser with validation, sectionless and extended-numbering support, `PT_DYNAMIC` symbol lookup, and file-backed placement rules |

The reference only treats as a *safe tail* the zero bytes between
`p_offset + p_filesz` and the end of that executable segment's last mapped
page, provided no other `PT_LOAD`/section claims them. Zero runs **inside** an
executable range are reported but never accepted.

## Fixtures

| Fixture | Exercises |
| --- | --- |
| `aarch64_ordinary.elf` | valid section table, 512-byte zero tail |
| `aarch64_tight_g22.elf` | reported G22 shape: 112-byte slack, 14-byte run |
| `aarch64_no_sections.elf` | no section table, `PT_DYNAMIC` only |
| `aarch64_extended_numbering.elf` | `PN_XNUM`, `e_shnum=0`, `SHN_XINDEX` |
| `aarch64_multi_exec.elf` | two `PF_X` `PT_LOAD`s, room only in the second |
| `aarch64_tail_nonzero.elf` | page tail exists but is non-zero |
| `aarch64_zero_run_in_data.elf` | large zero run inside declared data |
| `aarch64_symbol_in_bss.elf` | symbol in `p_memsz` beyond `p_filesz` |
| `aarch64_segment_past_eof.elf` | segment file range beyond EOF |
| `x86_64_ordinary.elf` | foreign `e_machine` |
| `elf32_claim.elf` | `EI_CLASS=ELFCLASS32` claim |
| `big_endian_claim.elf` | `EI_DATA=ELFDATA2MSB` claim |

## Findings (see `report.md`)

- The reported G22 failure reproduces as **AGREE_REJECT**: 464 bytes against
  112 bytes of tail slack and a 14-byte zero run. The reference agrees no safe
  placement exists, so this specific failure is a layout limit, not a parser
  bug.
- **False negatives**: sectionless ELF, extended numbering, and a second
  executable segment are valid layouts the current scanner rejects before it
  ever reaches placement.
- **False positives**: the current scanner accepts non-zero page tails, data
  zero runs, symbols in BSS, out-of-bounds segments, and foreign
  class/endianness/machine values.
- The host `libc++.so` is the sharpest example. Its executable segment ends at
  the first byte of the following `PF_R|PF_W` `PT_LOAD` (`.data.rel.ro`). The
  current scanner accepts that address because the page still has 2520 bytes;
  the reference refuses because those bytes belong to another segment.

## Emulation caveats

`current` is a re-implementation, not a build of the C file. It mirrors the
control flow and checks, including short-read handling: the C code tests some
reads only with `< 0`, so the emulation zero-pads and records a `short read`
defect instead of reproducing indeterminate stack contents. Page size defaults
to 4096; pass `--pagesize` for 16 KiB targets.

## Non-goals

This tool does not select a placement for the exploit, does not write an ELF,
and does not validate that a chosen offset is safe to execute. It is a
classification harness for the compatibility logic.
