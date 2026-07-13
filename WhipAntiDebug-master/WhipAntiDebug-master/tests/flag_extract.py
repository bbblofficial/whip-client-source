#!/usr/bin/env python3
"""
flag_extract.py — extract the flag statically from the binary.

Knowledge used (from the source):
  - Flag is encoded by AD_BUILD_FLAG_ON_STACK at line 648 of main_example.c
  - Key derivation: AD_STR_KEY(0xE7) = (0xE7 ^ 0x5A ^ (__LINE__*131+17)) & 0xFF
  - Each byte is XOR-encoded once at compile time as a MOV imm8 operand
  - The flag is 35 chars: FLAG{...} (terminator at index 35)
  - First 5 chars are known: "FLAG{"

We brute-force all 256 keys and slide a 35-byte window across the binary
looking for any window that XOR-decrypts to a "FLAG{" prefix.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXE  = REPO / "cmake-build-release" / "WhipAntiDebugger_Example.exe"

def main():
    data = EXE.read_bytes()
    print(f"binary: {EXE}  ({len(data)} bytes)")

    # 1. Compute the expected key from the source.
    line = 648
    expected_key = ((0xE7 ^ 0x5A ^ (line * 131 + 17)) & 0xFF)
    print(f"expected key for line {line}: 0x{expected_key:02X}")

    target_prefix = b"FLAG{"
    flag_len = 35

    # 2. Sliding XOR scan with the expected key first.
    print("\n[1] direct slide with expected key 0xD4:")
    found = []
    for offset in range(0, len(data) - flag_len):
        chunk = data[offset:offset+5]
        decoded = bytes(c ^ expected_key for c in chunk)
        if decoded == target_prefix:
            full = bytes(c ^ expected_key for c in data[offset:offset+flag_len])
            try:
                full_text = full.decode("ascii")
            except UnicodeDecodeError:
                full_text = repr(full)
            found.append((offset, full_text))
            if len(found) >= 5:
                break
    if found:
        print(f"  HITS: {len(found)}")
        for off, txt in found:
            print(f"    @ 0x{off:08X}: {txt!r}")
    else:
        print(f"  no contiguous 5-byte run decrypts to 'FLAG{{' with key 0x{expected_key:02X}")

    # 3. The compiler probably merged the immediate stores into wider
    #    forms. Try EVERY key 0..255 for completeness.
    print("\n[2] brute-force all 256 keys for 'FLAG{' prefix:")
    any_hit = False
    for key in range(256):
        for offset in range(0, len(data) - flag_len):
            chunk = data[offset:offset+5]
            decoded = bytes(c ^ key for c in chunk)
            if decoded == target_prefix:
                full = bytes(c ^ key for c in data[offset:offset+flag_len])
                try:
                    full_text = full.decode("ascii", errors="replace")
                except UnicodeDecodeError:
                    full_text = repr(full)
                print(f"  key=0x{key:02X} @ 0x{offset:08X}: {full_text!r}")
                any_hit = True
                break  # only first match per key
    if not any_hit:
        print("  no XOR-decoded 'FLAG{' found anywhere with any key")
        print("  -> compiler probably merged stores into wider MOVs or split with other instructions")

    # 4. Strided scan: maybe the encoded bytes are interleaved with
    #    instruction prefixes. Try a stride of 4 (mov dword imm32 form).
    print("\n[3] stride-4 scan (skip 3 bytes between samples):")
    for key in range(256):
        for stride in (4, 5, 6, 7, 8):
            for start in range(0, len(data) - flag_len * stride):
                ok = True
                for i in range(5):
                    if (data[start + i*stride] ^ key) != target_prefix[i]:
                        ok = False
                        break
                if ok:
                    full_bytes = bytes(data[start + i*stride] ^ key for i in range(flag_len))
                    try:
                        full_text = full_bytes.decode("ascii", errors="replace")
                    except UnicodeDecodeError:
                        full_text = repr(full_bytes)
                    if "FLAG{" in full_text:
                        print(f"  key=0x{key:02X} stride={stride} @ 0x{start:08X}: {full_text!r}")
                        return  # found

    print("\n[done] static extraction failed for the simple patterns above.")
    print("       Likely: MSVC merged the 35 mov-byte stores into wider")
    print("       SSE/AVX immediate stores OR scattered them with non-flag")
    print("       fill bytes. Real bypass requires disassembly + extraction.")

if __name__ == "__main__":
    main()
