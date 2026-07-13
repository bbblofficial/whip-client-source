#!/usr/bin/env python3
"""
runtime_bypass.py — runtime bypass attempt via WriteProcessMemory.

Strategy
--------
1. CreateProcess(suspended, NO debug flag) so the binary doesn't trip
   PEB.BeingDebugged.
2. Snapshot main module bytes BEFORE resume — we know the binary has
   final_score on the stack so we can't patch a fixed VA, but we CAN
   patch the .text section to neutralise vm_derive_and_decrypt_flag.
3. Specifically: patch the function so it copies encrypted_flag directly
   to vm_output (i.e. the VM becomes a no-op and the AD_BUILD_FLAG_ON_STACK
   buffer that was XOR'd with correct_key gets XOR'd again with the same
   key by the inverse of the no-op... no wait that doesn't work.

Better: patch the SCORE PASSED to vm_derive_and_decrypt_flag. The
calling convention is rcx=score on x64. The instruction sequence is
typically:
    mov ecx, dword ptr [rsp+OFFSET]   ; 8B 4C 24 OFF   (4 bytes)
    call vm_derive_and_decrypt_flag

We patch the mov to:
    xor ecx, ecx                       ; 33 C9 (2 bytes)
    nop                                ; 90
    nop                                ; 90

Finding the right mov requires either symbols or scanning. We try a
heuristic: there should be EXACTLY ONE call to vm_derive_and_decrypt_flag
in the binary. We use Capstone if available; otherwise fall back to a
byte pattern scan.

This script does NOT use DEBUG_PROCESS — the binary is launched normally
and we simply read its memory afterwards (or before it spawns) via the
process handle returned from CreateProcess.

If neither approach finds the call site, we report failure honestly.
"""

import ctypes
import ctypes.wintypes as wt
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXE  = REPO / "cmake-build-release" / "WhipAntiDebugger_Example.exe"

CREATE_SUSPENDED        = 0x00000004
CREATE_NO_WINDOW        = 0x08000000
PROCESS_ALL_ACCESS      = 0x1F0FFF
PAGE_EXECUTE_READWRITE  = 0x40

def main():
    print(f"runtime bypass test against {EXE.name}")
    if not EXE.exists():
        print("error: build first")
        sys.exit(2)

    # ── Step 1: read the binary ─────────────────────────────────────────
    binary = EXE.read_bytes()
    print(f"  binary size: {len(binary)} bytes")

    # ── Step 2: try to find the score-load instruction ─────────────────
    #
    # We look for the byte sequence that loads ECX from a stack offset
    # immediately followed by a CALL rel32 (E8). The score is a u32 so
    # the load is 'mov ecx, dword ptr [rsp+disp]':
    #   8B 4C 24 disp8     (4 bytes)
    # or
    #   8B 8C 24 disp32    (7 bytes)
    #
    # There are HUNDREDS of such loads in the binary; we can't reliably
    # pick the right one without symbols.
    #
    # Try a different signature: the constant 0xE7 used in derive_key_stream
    # via the FNV1a hash inside it. Or scan for the unique PRNG constant
    # 0xCBF29CE484222325 (FNV-1a offset basis) which is used by
    # derive_key_stream's hash.
    print()
    print("  [pattern] FNV-1a offset basis 0xCBF29CE484222325 in binary:")
    fnv_basis = struct.pack("<Q", 0xCBF29CE484222325)
    print(f"     bytes: {fnv_basis.hex(' ')}")
    occurrences = []
    off = 0
    while True:
        idx = binary.find(fnv_basis, off)
        if idx < 0:
            break
        occurrences.append(idx)
        off = idx + 1
        if len(occurrences) >= 10:
            break
    print(f"     count: {len(occurrences)} occurrences")
    for o in occurrences[:5]:
        print(f"       @ 0x{o:08X}")

    # ── Step 3: search for the FNV1a prime 0x100000001B3 ────────────────
    print()
    print("  [pattern] FNV-1a prime 0x100000001B3 in binary:")
    fnv_prime = struct.pack("<Q", 0x100000001B3)
    occurrences2 = []
    off = 0
    while True:
        idx = binary.find(fnv_prime, off)
        if idx < 0:
            break
        occurrences2.append(idx)
        off = idx + 1
        if len(occurrences2) >= 10:
            break
    print(f"     count: {len(occurrences2)}")
    for o in occurrences2[:5]:
        print(f"       @ 0x{o:08X}")

    # ── Step 4: launch SUSPENDED via CreateProcessW so we get a handle ──
    print()
    print("  [launch] CreateProcessW + CREATE_SUSPENDED")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb",              wt.DWORD),
            ("lpReserved",      wt.LPWSTR),
            ("lpDesktop",       wt.LPWSTR),
            ("lpTitle",         wt.LPWSTR),
            ("dwX",             wt.DWORD),
            ("dwY",             wt.DWORD),
            ("dwXSize",         wt.DWORD),
            ("dwYSize",         wt.DWORD),
            ("dwXCountChars",   wt.DWORD),
            ("dwYCountChars",   wt.DWORD),
            ("dwFillAttribute", wt.DWORD),
            ("dwFlags",         wt.DWORD),
            ("wShowWindow",     wt.WORD),
            ("cbReserved2",     wt.WORD),
            ("lpReserved2",     wt.LPVOID),
            ("hStdInput",       wt.HANDLE),
            ("hStdOutput",      wt.HANDLE),
            ("hStdError",       wt.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess",    wt.HANDLE),
            ("hThread",     wt.HANDLE),
            ("dwProcessId", wt.DWORD),
            ("dwThreadId",  wt.DWORD),
        ]

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    ok = k32.CreateProcessW(
        wt.LPCWSTR(str(EXE)),
        None, None, None, False,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        None, None,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        print(f"     CreateProcessW failed: {ctypes.get_last_error()}")
        return
    print(f"     pid={pi.dwProcessId}  tid={pi.dwThreadId}")

    # ── Step 5: enumerate the loaded modules to find the main image base
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    # We need to give the loader a chance to map ntdll. CREATE_SUSPENDED
    # leaves the main thread suspended but ntdll IS already mapped
    # (the kernel does this before user mode runs).
    hmods = (wt.HMODULE * 256)()
    cb_needed = wt.DWORD()
    psapi.EnumProcessModules.argtypes = [
        wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD)
    ]
    psapi.EnumProcessModules.restype = wt.BOOL
    if not psapi.EnumProcessModules(pi.hProcess, hmods, ctypes.sizeof(hmods), ctypes.byref(cb_needed)):
        print(f"     EnumProcessModules failed: {ctypes.get_last_error()}")
    else:
        n = cb_needed.value // ctypes.sizeof(wt.HMODULE)
        print(f"     {n} modules mapped (suspended state)")
        if n > 0:
            print(f"     image base: 0x{hmods[0]:016X}")

    # ── Step 6: kill — we're not going to do the runtime patch here
    #            because reliably finding the score load without symbols
    #            requires a real disassembler. Document the result.
    k32.TerminateProcess(pi.hProcess, 1)
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)

    print()
    print("  [conclusion] runtime bypass without symbols requires:")
    print("     - a disassembler (capstone) to walk the .text section")
    print("     - identification of vm_derive_and_decrypt_flag's call site")
    print("     - a precise patch of the ECX-loading mov instruction")
    print("     none of which is feasible from this script in a")
    print("     single shot. Real-world bypass would use IDA + ScyllaHide")
    print("     + manual patches over multiple hours of analysis.")

if __name__ == "__main__":
    main()
