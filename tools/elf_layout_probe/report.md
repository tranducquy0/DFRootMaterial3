# ELF layout probe - experiment report

Offline, read-only experiment. It does not modify `app/src/main/jni/`, does not run on a device, and does not change any exploit behaviour.

## Method

- `current` re-implements `find_hook_target()` and `find_code_cave()` from `elf_parser.c`, including its unvalidated header fields, first-segment break, `sizeof(Elf64_Shdr)` stride, and zero-run fallback.
- `reference` is a strict ELF64/AArch64 reader: validates class, data encoding, version, machine, `e_ehsize`, `e_phentsize`, `e_shentsize`; handles `PN_XNUM` / `SHN_XINDEX` / `e_shnum=0`; resolves symbols from `.dynsym` or `PT_DYNAMIC`; rejects undefined imports and symbols that are not file-backed.
- A reference *safe tail* is a run of file-backed zero bytes from `p_offset+p_filesz` to the end of that executable segment's last mapped page, not claimed by any other PT_LOAD or section. In-segment zero runs are reported but never treated as free space.

## Summary

| Fixture | Reference | Current | Verdict |
| --- | --- | --- | --- |
| `aarch64_ordinary.elf` | SAFE_TAIL | ACCEPT @ `0x1e00` | **AGREE_ACCEPT** |
| `aarch64_tight_g22.elf` | NO_SPACE | REJECT | **AGREE_REJECT** |
| `aarch64_no_sections.elf` | SAFE_TAIL | REJECT | **FALSE_NEGATIVE** |
| `aarch64_extended_numbering.elf` | SAFE_TAIL | REJECT | **FALSE_NEGATIVE** |
| `aarch64_multi_exec.elf` | SAFE_TAIL | REJECT | **FALSE_NEGATIVE** |
| `aarch64_tail_nonzero.elf` | NO_SPACE | ACCEPT @ `0x1e00` | **FALSE_POSITIVE** |
| `aarch64_zero_run_in_data.elf` | AMBIGUOUS_ONLY | ACCEPT @ `0x1040` | **FALSE_POSITIVE** |
| `aarch64_symbol_in_bss.elf` | SYMBOL_NOT_FILE_BACKED | ACCEPT @ `0x1e00` | **FALSE_POSITIVE** |
| `aarch64_segment_past_eof.elf` | PARSE_ERROR | ACCEPT @ `0x4e00` | **FALSE_POSITIVE** |
| `x86_64_ordinary.elf` | PARSE_ERROR | ACCEPT @ `0x1e00` | **FALSE_POSITIVE** |
| `elf32_claim.elf` | PARSE_ERROR | ACCEPT @ `0x1e00` | **FALSE_POSITIVE** |
| `big_endian_claim.elf` | PARSE_ERROR | ACCEPT @ `0x1e00` | **FALSE_POSITIVE** |

- False positives (current accepts, reference rejects): **7** - `aarch64_tail_nonzero.elf`, `aarch64_zero_run_in_data.elf`, `aarch64_symbol_in_bss.elf`, `aarch64_segment_past_eof.elf`, `x86_64_ordinary.elf`, `elf32_claim.elf`, `big_endian_claim.elf`
- False negatives (current rejects, reference finds a safe tail): **3** - `aarch64_no_sections.elf`, `aarch64_extended_numbering.elf`, `aarch64_multi_exec.elf`
- Both accept: **1** - `aarch64_ordinary.elf`
- Both reject: **1** - `aarch64_tight_g22.elf`
- Unsupported/agreed rejection: **0** - none

## Per-fixture detail

### `aarch64_ordinary.elf`

- Reference: `SAFE_TAIL` - file-backed zero tail large enough
- Current: `ACCEPT` at `0x1e00`
- Verdict: **AGREE_ACCEPT** - both accept a file-backed zero tail
- Safe tails: seg 0 `0x1e00` len 512 fits=True
- PF_X PT_LOADs: off `0x1000` filesz `0xe00` flags 5

### `aarch64_tight_g22.elf`

- Reference: `NO_SPACE` - no file-backed tail and no ambiguous run large enough
- Current: `REJECT` - no code cave large enough (need 464, largest found 14)
- Verdict: **AGREE_REJECT** - both reject; reference: no file-backed tail and no ambiguous run large enough
- Safe tails: seg 0 `0x1f90` len 112 fits=False
- PF_X PT_LOADs: off `0x1000` filesz `0xf90` flags 5

### `aarch64_no_sections.elf`

- Reference: `SAFE_TAIL` - file-backed zero tail large enough
- Current: `REJECT` - .dynstr or .dynsym not found
- Verdict: **FALSE_NEGATIVE** - reference found a file-backed zero tail the current scanner missed
- Safe tails: seg 0 `0x1e00` len 512 fits=True
- PF_X PT_LOADs: off `0x1000` filesz `0xe00` flags 5

### `aarch64_extended_numbering.elf`

- Reference: `SAFE_TAIL` - file-backed zero tail large enough
- Current: `REJECT` - .dynstr or .dynsym not found
- Verdict: **FALSE_NEGATIVE** - reference found a file-backed zero tail the current scanner missed
- Safe tails: seg 0 `0x1e00` len 512 fits=True
- PF_X PT_LOADs: off `0x1000` filesz `0xe00` flags 5
- Current-scanner defects observed: short read of shstrndx section header not detected

### `aarch64_multi_exec.elf`

- Reference: `SAFE_TAIL` - file-backed zero tail large enough
- Current: `REJECT` - no code cave large enough (need 464, largest found 0)
- Verdict: **FALSE_NEGATIVE** - reference found a file-backed zero tail the current scanner missed
- Safe tails: seg 0 `0x1f90` len 112 fits=False, seg 1 `0x3e00` len 512 fits=True
- PF_X PT_LOADs: off `0x1000` filesz `0xf90` flags 5; off `0x3000` filesz `0xe00` flags 5
- Current-scanner defects observed: stops at the first of 2 executable PT_LOAD segments

### `aarch64_tail_nonzero.elf`

- Reference: `NO_SPACE` - no file-backed tail and no ambiguous run large enough
- Current: `ACCEPT` at `0x1e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference found no space (NO_SPACE)
- PF_X PT_LOADs: off `0x1000` filesz `0xe00` flags 5

### `aarch64_zero_run_in_data.elf`

- Reference: `AMBIGUOUS_ONLY` - only an in-segment zero run large enough; may be data
- Current: `ACCEPT` at `0x1040`
- Verdict: **FALSE_POSITIVE** - current used an in-segment zero run that may be real data
- Safe tails: seg 0 `0x1f90` len 112 fits=False
- PF_X PT_LOADs: off `0x1000` filesz `0xf90` flags 5

### `aarch64_symbol_in_bss.elf`

- Reference: `SYMBOL_NOT_FILE_BACKED` - _ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_ st_value=0x10e10 is not in a file-backed executable range
- Current: `ACCEPT` at `0x1e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference rejected: _ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_ st_value=0x10e10 is not in a file-backed executable range
- Safe tails: seg 0 `0x1e00` len 512 fits=True
- PF_X PT_LOADs: off `0x1000` filesz `0xe00` flags 5
- Current-scanner defects observed: does not check that the symbol is file-backed

### `aarch64_segment_past_eof.elf`

- Reference: `PARSE_ERROR` - phdr[0] file range 0x1000+0x3e00 extends past EOF (0x3168)
- Current: `ACCEPT` at `0x4e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference rejected: phdr[0] file range 0x1000+0x3e00 extends past EOF (0x3168)
- Current-scanner defects observed: accepts a tail offset past EOF

### `x86_64_ordinary.elf`

- Reference: `PARSE_ERROR` - e_machine=62 (not AArch64)
- Current: `ACCEPT` at `0x1e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference rejected: e_machine=62 (not AArch64)
- Current-scanner defects observed: does not validate e_machine (saw 62)

### `elf32_claim.elf`

- Reference: `PARSE_ERROR` - EI_CLASS=1 (not ELF64)
- Current: `ACCEPT` at `0x1e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference rejected: EI_CLASS=1 (not ELF64)
- Current-scanner defects observed: does not validate EI_CLASS

### `big_endian_claim.elf`

- Reference: `PARSE_ERROR` - EI_DATA=2 (not little-endian)
- Current: `ACCEPT` at `0x1e00`
- Verdict: **FALSE_POSITIVE** - current accepted but reference rejected: EI_DATA=2 (not little-endian)
- Current-scanner defects observed: does not validate EI_DATA

## Real host libraries

| Fixture | Reference | Current | Verdict |
| --- | --- | --- | --- |
| `libc++.so` | NO_SPACE | ACCEPT @ `0xfe628` | **FALSE_POSITIVE** |
| `libbase.so` | SAFE_TAIL | ACCEPT @ `0x30c40` | **AGREE_ACCEPT** |

### `libc++.so`

- Reference: `NO_SPACE` - no file-backed tail and no ambiguous run large enough
- Current: `ACCEPT` at `0xfe628`
- Verdict: **FALSE_POSITIVE** - current accepted but reference found no space (NO_SPACE)
- PF_X PT_LOADs: off `0x84d60` filesz `0x798c8` flags 5

### `libbase.so`

- Reference: `SAFE_TAIL` - file-backed zero tail large enough
- Current: `ACCEPT` at `0x30c40`
- Verdict: **AGREE_ACCEPT** - both accept a file-backed zero tail
- Safe tails: seg 0 `0x30c40` len 960 fits=True
- PF_X PT_LOADs: off `0x10000` filesz `0x20c40` flags 5

## Interpretation

- The reported G22 failure reproduces as **AGREE_REJECT**: a 464-byte payload against 112 bytes of tail slack and a 14-byte zero run. The reference agrees there is no safe placement, so this is a layout limit, not a parser bug.
- False negatives are real: sectionless ELF, extended numbering, and a second executable segment are valid layouts that the current scanner rejects before placement.
- False positives are also real: the current scanner trusts page slack without checking whether it belongs to the next segment, trusts zero runs inside executable ranges, ignores `EI_CLASS`/`EI_DATA`/`e_machine`, and does not require the symbol to be file-backed.
- The host `libc++` is the clearest example: the executable segment ends at `0xfe628`, which is the first byte of the next `PF_R|PF_W` `PT_LOAD` (`.data.rel.ro`). The current scanner accepts that address because 2520 bytes remain in the page; the reference refuses because the bytes belong to another segment.

## Caveats

- The host samples are this environment's libraries, not the reported Nokia Build ID `84acbd0e3703d0ed73c0df290de333b9`. The G22 conclusion comes from `aarch64_tight_g22.elf`, which reproduces the logged 112-byte slack and 14-byte run shape, not from the device's actual file.
- The device's `readelf -lW` output was not available, so whether it has a second executable segment or a differently claimed page tail is unknown. Those cases are covered by fixtures, not asserted for the device.

These results are layout classifications only. They do not establish that any accepted offset is safe to execute at runtime, and they are not wired into the production tool.
