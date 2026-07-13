#!/usr/bin/env python3
"""
flag_extract2.py — second-stage bypass using full source knowledge.

Round 1 (flag_extract.py) found only the page_guard_trap honeypot bait.
This script uses tighter source knowledge:

  - Real flag = "FLAG{Wh1p_4nt1D3bug_Unr3v3rs4bl3!}"
  - Key for line 648 invocation = 0x14
  - Each char is stored XOR'd with 0x14 as a MOV imm8 operand

Strategy:
  1. XOR-encode the known flag with 0x14 → encrypted_target
  2. Search for the encrypted bytes anywhere in .text/.rdata as a
     contiguous run (compiler may have folded them into MOVDQA/MOVAPS)
  3. Search for them with a stride (compiler emitted individual MOVs
     each interleaved with stack offsets / opcodes)
  4. Search for any 4-byte run that XOR-decodes to "Wh1p" (which is
     unique enough that any false-positive rate is acceptable)
  5. Try the SAME with plaintext "Wh1p" (no XOR) — if found, the
     compiler folded the macro back to plaintext
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXE  = REPO / "cmake-build-release" / "WhipAntiDebugger_Example.exe"

REAL_FLAG = b"FLAG{Wh1p_4nt1D3bug_Unr3v3rs4bl3!}"
KEY       = 0x14
ENCRYPTED = bytes(c ^ KEY for c in REAL_FLAG)

def hexstr(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def main():
    data = EXE.read_bytes()
    print(f"binary: {EXE.name}  ({len(data)} bytes)")
    print(f"key   : 0x{KEY:02X}")
    print(f"plain : {REAL_FLAG.decode()}")
    print(f"encryp: {hexstr(ENCRYPTED)}")
    print()

    # ── 1. Encrypted contiguous run ─────────────────────────────────────
    idx = data.find(ENCRYPTED)
    print(f"[1] contiguous encrypted run search: ", end="")
    print(f"@ 0x{idx:08X}" if idx >= 0 else "NOT FOUND")

    # Also try shorter prefixes
    for n in (35, 20, 16, 12, 8, 5):
        idx = data.find(ENCRYPTED[:n])
        print(f"    [first {n:2d} bytes] {'@ 0x' + format(idx, '08X') if idx >= 0 else 'NOT FOUND'}")

    # ── 2. Plaintext contiguous run (compiler folded) ───────────────────
    print()
    idx = data.find(REAL_FLAG)
    print(f"[2] contiguous PLAINTEXT search: ", end="")
    print(f"@ 0x{idx:08X}" if idx >= 0 else "NOT FOUND")
    for prefix in (b"Wh1p_4nt1D3bug", b"Wh1p_4nt1", b"Wh1p"):
        idx = data.find(prefix)
        print(f"    [{prefix.decode():14s}] {'@ 0x' + format(idx, '08X') if idx >= 0 else 'NOT FOUND'}")

    # ── 3. Single encrypted byte: 'F' ^ 0x14 = 0x52 ─────────────────────
    enc_F = ord('F') ^ KEY
    print(f"\n[3] single 'F' encrypted (0x{enc_F:02X}) occurrences in binary: {data.count(bytes([enc_F]))}")

    # ── 4. Strided search — every Nth byte from a base ──────────────────
    print(f"\n[4] strided encrypted-flag search (compiler interleaving):")
    target = ENCRYPTED[:8]  # 8 bytes is enough to be unique
    found_stride = None
    for stride in range(1, 32):
        for start in range(0, len(data) - len(target) * stride):
            ok = True
            for i in range(len(target)):
                if data[start + i*stride] != target[i]:
                    ok = False
                    break
            if ok:
                print(f"    stride={stride} start=0x{start:08X}")
                found_stride = (stride, start)
                break
        if found_stride:
            break
    if not found_stride:
        print("    no strided pattern found up to stride 31")

    # ── 5. Direct search for the bait we already know about ────────────
    print(f"\n[5] sanity: page_guard_trap bait still present?")
    bait = b"FLAG{fake_bait_key=DEADBEEFCAFEBABE9999}"
    idx = data.find(bait)
    print(f"    bait @ 0x{idx:08X}" if idx >= 0 else "    bait NOT FOUND")

    # ── 6. The killer test: how MANY 35-byte windows decrypt to ─────────
    #      printable ASCII with key 0x14? (Lots of false positives ok.)
    print(f"\n[6] count windows that XOR-decrypt to all-printable (key 0x14):")
    count = 0
    samples = []
    for off in range(len(data) - 35):
        decoded = bytes(c ^ KEY for c in data[off:off+35])
        if all(32 <= b < 127 for b in decoded):
            count += 1
            if len(samples) < 5:
                samples.append((off, decoded.decode("ascii", errors="replace")))
    print(f"    {count} all-printable 35-byte XOR-windows found")
    for off, txt in samples[:5]:
        print(f"    @ 0x{off:08X}: {txt!r}")

    print()
    print("=" * 70)
    if data.find(REAL_FLAG) >= 0:
        print("  STATIC EXTRACTION : SUCCESS — flag was in plaintext")
    elif data.find(ENCRYPTED) >= 0:
        print("  STATIC EXTRACTION : SUCCESS — encrypted run found, decrypt OK")
    else:
        print("  STATIC EXTRACTION : FAILED — flag is not contiguous in the binary")
        print("  framework defense worked: flag exists only at runtime on the stack")
    print("=" * 70)

if __name__ == "__main__":
    main()
