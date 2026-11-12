# ELF compatibility diagnosis

## Nokia G22 (HMD Sunfire) report

Reported environment: Android 14 (API 34), firmware `00WW_3_61J`, AArch64,
kernel `5.15.189-android13-8-gda0f9c88f088`, KMI `android13-5.15`, and
`libc++.so` Build ID `84acbd0e3703d0ed73c0df290de333b9`.

The reported failure is:

```text
shellcode (464) exceeds tail-page slack (112 bytes)
no code cave large enough (need 464, largest found 14)
failed to find offsets for /system/lib64/libc++.so
```

## What the log establishes

`patch_hook()` calls `find_hook_target()`. The ELF reader finds an executable
`PT_LOAD` and resolves the requested dynamic symbol before calling
`find_code_cave()`. The log therefore indicates that the current placement
search failed: the segment tail has less slack than the payload requires, and
the scan found no sufficiently long zero-filled run in the selected segment.

This is evidence of an unsupported layout for the current placement algorithm.
It is not, by itself, evidence that the ELF is malformed or that symbol lookup
failed. The log does not contain enough information to independently verify
the library's program-header layout.

## Current ELF assumptions and limitations

The current reader checks the ELF magic but does not validate ELF class, byte
order, ELF version, or machine type before reading native `Elf64_*` structs.
It requires section headers and section names to find `.dynsym` and `.dynstr`,
so sectionless ELF files and extended section numbering are unsupported. It
stops at the first executable `PT_LOAD` and searches only that segment for a
zero-filled run. It also does not consistently validate table bounds or
complete reads, and its fixed-size name buffers can truncate long names.

These limitations mean valid ELF64/AArch64 files can be rejected, while
malformed input is not always rejected with a sufficiently precise diagnostic.
They do not establish that any alternative placement is safe.

## Fail-closed support statement

DFRoot's current compatibility check supports only binaries for which its ELF
reader can locate the requested symbol and its existing placement search finds
enough space under the implementation's assumptions. If those conditions are
not met, the tool reports failure. A successful ELF parse or symbol lookup
alone does not establish that a binary is compatible.

No larger payload threshold or bypass of the compatibility check is an
acceptable workaround. Broader ELF support requires a separately reviewed
parser and a proof that any chosen location satisfies the runtime mapping and
placement requirements. Until then, the Nokia G22 configuration above should
be treated as unsupported by the current placement algorithm.

## Regression coverage needed before changing support

An offline parser test suite should include representative ELF64/AArch64
fixtures with ordinary section tables, no section table, extended numbering,
multiple executable load segments, truncated tables, invalid offsets, and
insufficient candidate space. It should verify precise parse outcomes and
fail-closed compatibility decisions. These fixtures must not patch device
libraries or infer that arbitrary zero-filled bytes are safe placement space.
