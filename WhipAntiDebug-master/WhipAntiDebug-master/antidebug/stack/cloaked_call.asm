; ===== file: antidebug/stack/cloaked_call.asm =====
;
; Return-address cloaking trampoline (x64 MASM).
;
; Provides a way to call a target function such that, while the target
; is executing, the CALLER'S return address on the stack is replaced
; with an XOR-scrambled value. A stack walker observing the process
; mid-call sees garbage in the frame pointing to our caller; the real
; address is only reconstructed just before we return.
;
; Signature (C caller view):
;   void* CloakedCall(
;       void*  fn,    ; RCX — void*(*)(void*) target
;       void*  arg    ; RDX — passed to fn as its first argument (RCX)
;   );
;   void* CloakedCall0(
;       void*  fn     ; RCX — void*(*)(void) target (no arguments)
;   );
;
; What it does
; ------------
;   1. Allocates a local frame (shadow space + locals) via rsp.
;   2. Generates a per-call scrambling key from RDTSC mixed with a
;      64-bit constant so the key is never zero or trivially predictable.
;   3. Reads the caller's return address from the stack and XORs it with
;      the key, writing the scrambled value back in place.
;   4. CALLs fn(arg). During this call:
;        * the caller's return slot contains scrambled bytes
;        * a stack walker cannot resolve the caller without the key
;   5. On return, un-scrambles the caller's return slot so our own RET
;      transfers to the correct address.
;   6. Returns fn's return value in RAX unchanged.
;
; Thread safety: all state (key, saved fn return) lives in stack locals.
; Two threads calling CloakedCall concurrently do not interfere.
;
; Limitations
; -----------
;   * If fn raises an exception, the stack walker sees the scrambled
;     return address and unwinding may fail. Use only around code whose
;     exceptions are already handled locally.
;   * Does not cloak frames further up the stack — only the immediate
;     caller's return slot.
;
.code

; ─── CloakedCall ─────────────────────────────────────────────────────────────
;
; Stack layout after `push rbp; sub rsp, 40h`:
;   [rsp + 48h] = caller's return address          ← the slot we scramble
;   [rsp + 40h] = saved rbp
;   [rsp + 38h] = local: fn's saved return value
;   [rsp + 30h] = local: key
;   [rsp + 28h] = local: arg
;   [rsp + 20h] = local: fn
;   [rsp + 00h..1Fh] = shadow space for our sub-call
;
CloakedCall PROC
    push    rbp
    sub     rsp, 40h

    mov     [rsp + 20h], rcx                     ; fn
    mov     [rsp + 28h], rdx                     ; arg

    ; Key = (rdtsc) XOR GOLDEN_RATIO so never zero.
    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 30h], rdx                     ; key

    ; Scramble caller's return slot.
    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    ; Call fn(arg).
    mov     rcx, [rsp + 28h]                     ; arg → RCX
    mov     rax, [rsp + 20h]                     ; fn
    call    rax
    mov     [rsp + 38h], rax                     ; save fn return

    ; Unscramble.
    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 38h]                     ; restore fn return for us

    add     rsp, 40h
    pop     rbp
    ret
CloakedCall ENDP

; ─── CloakedCall0 ────────────────────────────────────────────────────────────
CloakedCall0 PROC
    push    rbp
    sub     rsp, 40h

    mov     [rsp + 20h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 30h], rdx                     ; key

    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 20h]
    call    rax                                  ; fn()
    mov     [rsp + 38h], rax

    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 38h]

    add     rsp, 40h
    pop     rbp
    ret
CloakedCall0 ENDP

; ─── Variadic CloakedCall1..CloakedCall6 ──────────────────────────────────────
;
; Uniform layout (push rbp + sub rsp,60h = 68h shift):
;
;   [rsp + 00h..1Fh] = shadow space for our sub-call to fn
;   [rsp + 20h..2Fh] = stack-arg slots for fn (a5/a6 for 5/6-arg targets)
;   [rsp + 48h]      = saved fn return value
;   [rsp + 50h]      = fn pointer (saved early)
;   [rsp + 58h]      = scramble key
;   [rsp + 60h]      = saved rbp
;   [rsp + 68h]      = caller's saved return address ← scrambled in place
;   [rsp + 90h]      = caller's stack arg slot 5  (a4 for ≥5-arg targets)
;   [rsp + 98h]      = caller's stack arg slot 6  (a5 for ≥6-arg targets)
;   [rsp + 0A0h]     = caller's stack arg slot 7  (a6 for 6-arg targets)
;
; Each variant differs only in how it populates RCX/RDX/R8/R9 and stack
; slots before the CALL.

; ─── CloakedCall1 ────────────────────────────────────────────────────────────
; Identical to CloakedCall (kept as alias for naming consistency).
CloakedCall1 PROC
    push    rbp
    sub     rsp, 40h

    mov     [rsp + 20h], rcx                     ; fn
    mov     [rsp + 28h], rdx                     ; a1

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 30h], rdx

    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    mov     rcx, [rsp + 28h]
    mov     rax, [rsp + 20h]
    call    rax
    mov     [rsp + 38h], rax

    mov     rax, [rsp + 48h]
    mov     r11, [rsp + 30h]
    xor     rax, r11
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 38h]
    add     rsp, 40h
    pop     rbp
    ret
CloakedCall1 ENDP

; ─── CloakedCall2 ────────────────────────────────────────────────────────────
CloakedCall2 PROC
    push    rbp
    sub     rsp, 60h

    mov     [rsp + 50h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 58h], rdx

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    ; fn(a1, a2):  RCX←a1(was RDX), RDX←a2(was R8)
    ; Order matters: do RCX last because RDX feeds it.
    mov     rax, rdx                             ; rax = a1
    mov     rdx, r8                              ; RDX = a2
    mov     rcx, rax                             ; RCX = a1

    mov     rax, [rsp + 50h]
    call    rax
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    mov     rax, [rsp + 48h]
    add     rsp, 60h
    pop     rbp
    ret
CloakedCall2 ENDP

; ─── CloakedCall3 ────────────────────────────────────────────────────────────
CloakedCall3 PROC
    push    rbp
    sub     rsp, 60h

    mov     [rsp + 50h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 58h], rdx

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    ; fn(a1, a2, a3):  RCX←RDX, RDX←R8, R8←R9
    mov     rax, rdx                             ; a1 to rax
    mov     rcx, rax                             ; RCX = a1
    mov     rdx, r8                              ; RDX = a2
    mov     r8, r9                               ; R8 = a3

    mov     rax, [rsp + 50h]
    call    rax
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    mov     rax, [rsp + 48h]
    add     rsp, 60h
    pop     rbp
    ret
CloakedCall3 ENDP

; ─── CloakedCall4 ────────────────────────────────────────────────────────────
CloakedCall4 PROC
    push    rbp
    sub     rsp, 60h

    mov     [rsp + 50h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 58h], rdx

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    ; fn(a1..a4):  RCX←RDX, RDX←R8, R8←R9, R9←caller[RSP+0x28]=our[rsp+0x90]
    mov     rax, rdx                             ; a1
    mov     rcx, rax
    mov     rdx, r8
    mov     r8, r9
    mov     r9, [rsp + 90h]

    mov     rax, [rsp + 50h]
    call    rax
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    mov     rax, [rsp + 48h]
    add     rsp, 60h
    pop     rbp
    ret
CloakedCall4 ENDP

; ─── CloakedCall5 ────────────────────────────────────────────────────────────
CloakedCall5 PROC
    push    rbp
    sub     rsp, 60h

    mov     [rsp + 50h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 58h], rdx

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    ; fn(a1..a5): RCX..R9 ← a1..a4; [our rsp+0x20] ← a5(caller[+0x30] = our[+0x98])
    mov     rax, rdx
    mov     rcx, rax
    mov     rdx, r8
    mov     r8, r9
    mov     r9, [rsp + 90h]
    mov     rax, [rsp + 98h]
    mov     [rsp + 20h], rax

    mov     rax, [rsp + 50h]
    call    rax
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    mov     rax, [rsp + 48h]
    add     rsp, 60h
    pop     rbp
    ret
CloakedCall5 ENDP

; ─── CloakedCall6 ────────────────────────────────────────────────────────────
CloakedCall6 PROC
    push    rbp
    sub     rsp, 60h

    mov     [rsp + 50h], rcx                     ; fn

    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     rax, 9E3779B97F4A7C15h
    xor     rdx, rax
    mov     [rsp + 58h], rdx

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    ; fn(a1..a6): RCX..R9 ← a1..a4; [+0x20]/[+0x28] ← a5/a6 from caller [+0x30]/[+0x38]
    mov     rax, rdx
    mov     rcx, rax
    mov     rdx, r8
    mov     r8, r9
    mov     r9, [rsp + 90h]
    mov     rax, [rsp + 98h]
    mov     [rsp + 20h], rax
    mov     rax, [rsp + 0A0h]
    mov     [rsp + 28h], rax

    mov     rax, [rsp + 50h]
    call    rax
    mov     [rsp + 48h], rax

    mov     rax, [rsp + 68h]
    mov     r11, [rsp + 58h]
    xor     rax, r11
    mov     [rsp + 68h], rax

    mov     rax, [rsp + 48h]
    add     rsp, 60h
    pop     rbp
    ret
CloakedCall6 ENDP

end
