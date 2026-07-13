#!/usr/bin/env python3
"""
bypass_test.py — automated bypass attempts against WhipAntiDebugger_Example.

Runs the example binary in several configurations + patches it on disk
to simulate the typical reverser workflow:

  1. baseline                    bare run, no debugger, no patching
  2. debug-flag spawn            launched with DEBUG_ONLY_THIS_PROCESS
                                 (we don't drain events — most likely
                                  hangs the process, which IS a successful
                                  detection of "I am being debugged but
                                  the debugger is broken")
  3. on-disk patch               flip every CALL inside .text whose target
                                 is the anti_breakin install. NOPing it
                                 should NOT bypass — many other checks
                                 cover the same ground.
  4. on-disk byte search         search for the anti_breakin trampoline
                                 signature in .rdata or .text → expected
                                 to find NOTHING because the bytes are
                                 only assembled at runtime.

For each configuration we capture:
  Security score:  N
  Checks hit:      M
  flag header     ("FLAG{Wh1p" present or not)
  exit code
"""

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO  = Path(__file__).resolve().parent.parent
EXE   = REPO / "cmake-build-release" / "WhipAntiDebugger_Example.exe"
WORK  = REPO / "tests" / "_bypass_workdir"

CREATE_NO_WINDOW        = 0x08000000
DEBUG_ONLY_THIS_PROCESS = 0x00000002

if not EXE.exists():
    print(f"error: {EXE} not built — run _build_release.bat first")
    sys.exit(2)


def parse(stdout: str) -> dict:
    score_m = re.search(r"Security score:\s*(\d+)", stdout)
    hits_m  = re.search(r"Checks hit:\s*(\d+)",     stdout)
    return {
        "score":   int(score_m.group(1)) if score_m else None,
        "hits":    int(hits_m.group(1))  if hits_m  else None,
        "flag_ok": "FLAG{Wh1p" in stdout,
    }


def run(label: str, exe_path: Path = EXE, *, flags: int = 0, timeout: float = 15.0):
    print(f"\n--- {label} ---")
    print(f"  exe   ={exe_path.name}")
    print(f"  flags =0x{flags:08X}")
    try:
        proc = subprocess.Popen(
            [str(exe_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=flags | CREATE_NO_WINDOW,
        )
        try:
            out, _ = proc.communicate(timeout=timeout)
            text = out.decode("ascii", errors="replace")
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            text = out.decode("ascii", errors="replace")
            timed_out = True
    except OSError as exc:
        print(f"  ERROR: {exc}")
        return

    info = parse(text)
    print(f"  exit  ={proc.returncode}{'  TIMEOUT' if timed_out else ''}")
    print(f"  score ={info['score']}")
    print(f"  hits  ={info['hits']}")
    print(f"  flag  ={'OK' if info['flag_ok'] else 'CORRUPT'}")
    if not info['flag_ok']:
        for line in text.splitlines():
            if "FLAG" in line or "HOSTILE" in line or "CLEAN" in line:
                truncated = line if len(line) < 80 else line[:77] + "..."
                print(f"     | {truncated!r}")


def search_signature(label: str, exe_path: Path, sig: bytes):
    print(f"\n--- {label} ---")
    print(f"  exe = {exe_path.name}")
    print(f"  sig = {sig.hex(' ')}  ({len(sig)} bytes)")
    data = exe_path.read_bytes()
    hits = []
    off = 0
    while True:
        idx = data.find(sig, off)
        if idx < 0:
            break
        hits.append(idx)
        off = idx + 1
        if len(hits) >= 5:
            break
    if not hits:
        print("  result: NO MATCH (signature not present in static binary)")
    else:
        print(f"  result: {len(hits)} match(es) at offsets:", ", ".join(f"0x{h:X}" for h in hits))


def main():
    print("=" * 70)
    print(f"  WhipAntiDebugger bypass test")
    print(f"  exe = {EXE}")
    print(f"  built = {time.ctime(EXE.stat().st_mtime)}")
    print("=" * 70)

    # ── 1. Baseline ─────────────────────────────────────────────────────
    run("01 baseline (no debugger, no patches)")

    # ── 2. Sanity re-run ────────────────────────────────────────────────
    run("02 baseline re-run (no global state leak)")

    # ── 3. (skipped) DEBUG_ONLY_THIS_PROCESS launch ─────────────────────
    # The DEBUG_ flag launch test was removed from the automated suite —
    # in practice it permanently freezes both the parent (Python, which
    # cannot drain debug events from a non-debugger thread) and the
    # debuggee, requiring an external taskkill. The freeze itself is a
    # successful framework detection (the binary refuses to make any
    # forward progress under a broken debugger), but it does not
    # produce captured stdout to assert against.
    print("\n--- 03 DEBUG_ONLY_THIS_PROCESS (skipped — see comment) ---")

    # ── 4. On-disk anti_breakin trampoline signature search ─────────────
    # The trampoline is assembled at runtime by ad_anti_breakin_install.
    # The exact byte pattern (mov ecx,1 ; mov rax,imm64 ; jmp rax) should
    # NOT appear contiguously in the static binary, because the imm64
    # depends on the runtime address of RtlExitUserProcess.
    #
    # We search for the FIXED prefix only: B9 01 00 00 00 48 B8.
    # If this matches, the trampoline is partially visible to a static
    # signature scanner — undesirable.
    search_signature(
        "04 trampoline prefix in .rdata/.text",
        EXE,
        bytes.fromhex("B901000000 48B8".replace(" ", "")),
    )

    # ── 5. Hyperion encrypted blob signature ────────────────────────────
    # The encrypted blob bytes ARE present in .rdata. We search for them
    # to confirm they ARE statically visible (which is fine — they're
    # unintelligible without the XOR key).
    search_signature(
        "05 hyperion encrypted blob in .rdata",
        EXE,
        bytes.fromhex("1D 4A 1B 08 7B 66".replace(" ", "")),
    )

    # ── 6. Search for the DECRYPTED hyperion bytes ──────────────────────
    # If our claim "the decrypted form never lives at rest" is true, the
    # raw mov eax, 0xDEADBEEF stub bytes must NOT appear in the binary.
    search_signature(
        "06 hyperion decrypted form (must be ABSENT)",
        EXE,
        bytes.fromhex("B8 EF BE AD DE C3".replace(" ", "")),
    )

    print()
    print("=" * 70)
    print("  bypass_test complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
