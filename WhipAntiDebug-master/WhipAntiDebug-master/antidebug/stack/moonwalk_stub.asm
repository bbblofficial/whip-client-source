; ===== file: antidebug/stack/moonwalk_stub.asm =====
;
; Stack moonwalk ASM trampoline (x64 MASM).
;
; Provides a frame-pointer-independent way to spoof the call stack before
; invoking a sensitive function. Does not rely on /Oy- being disabled.
;
; ─── MoonwalkCall ────────────────────────────────────────────────────────────
;
; Signature (C caller view):
;   void MoonwalkCall(
;       void*  fn,           ; RCX — function to call
;       void** decoy_table,  ; RDX — array of N decoy addresses
;       DWORD  n_decoys,     ; R8  — number of frames to spoof (≤ 8)
;       void*  arg           ; R9  — argument passed to fn(arg)
;   );
;
; What it does:
;   1. Walks N slots above RSP (the N return addresses on the stack above us)
;   2. Saves them in a local buffer
;   3. Overwrites them with decoy_table[0..N-1]
;   4. Calls fn(arg)
;   5. Restores all return addresses before returning to OUR caller
;
; After step 3, any debugger inspecting the call stack while fn() runs sees:
;   fn()              ← called from
;   decoy_table[0]    (e.g. ntdll!RtlpAllocateHeap+0x4A)
;   decoy_table[1]    (e.g. ntdll!RtlAllocateHeap+0x12)
;   ...               (e.g. kernel32!BaseThreadInitThunk)
;
; ─── MoonwalkStomp ───────────────────────────────────────────────────────────
;
; Signature:
;   void MoonwalkStomp(void** decoy_table, DWORD n_decoys);
;
; Simpler version: just overwrites N stack slots above the caller.
; No save/restore — permanently burns those frames until they're unwound.
; Use when you do NOT need to return cleanly through the spoofed frames
; (e.g., before a NtTerminateProcess call).
;
.code

; ─── MoonwalkCall ─────────────────────────────────────────────────────────────
; Stack frame layout when MoonwalkCall is entered:
;
;  RSP+00h  → return address to MoonwalkCall's caller           ← slot 0
;  RSP+08h  → [shadow space / stack args begin for our caller]
;  RSP+10h  → return address of caller's caller                 ← slot 1
;  ...
;
; We spoof slots 0..(N-1) then call fn(arg).
;
; Register usage inside this proc:
;   RBX = fn
;   RSI = decoy_table
;   RDI = n_decoys (clamped to 8)
;   R12 = arg
;   R13 = save area base (stack local)
;

MoonwalkCall PROC
    ; Standard prologue — save non-volatile registers
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14

    ; Allocate local area: 8 * 8 = 64 bytes for saved return addresses
    ; + 32 bytes shadow space for our sub-calls
    ; Align RSP to 16 bytes
    sub     rsp, 80h        ; 128 bytes: 64 (save buf) + 32 (shadow) + 16 (align)

    ; Save parameters
    mov     rbx, rcx        ; fn
    mov     rsi, rdx        ; decoy_table
    mov     rdi, r8         ; n_decoys
    mov     r12, r9         ; arg

    ; Clamp n_decoys to 8
    cmp     rdi, 8
    jbe     @clamp_ok
    mov     rdi, 8
@clamp_ok:

    ; Compute where the return-address slots start.
    ; After our prologue, the original RSP (before our push/sub) lives at RBP.
    ; [RBP+00h] = saved old RBP
    ; [RBP+08h] = return address to MoonwalkCall's caller  ← slot 0
    ; [RBP+10h] = return addr of caller's caller           ← slot 1
    ; ...

    lea     r13, [rbp + 8]   ; r13 = address of slot 0 (first ret addr to spoof)

    ; Loop: save original, write decoy
    xor     r14, r14        ; loop index = 0
@spoof_loop:
    cmp     r14, rdi
    jge     @spoof_done

    ; Load current slot's real return address
    mov     rax, qword ptr [r13 + r14*8]

    ; Save it in our local buffer (RSP+20h is safe beyond shadow space)
    mov     qword ptr [rsp + 20h + r14*8], rax

    ; Load decoy[i] and write it into the slot
    ; Check decoy_table != NULL and decoy != NULL before writing
    test    rsi, rsi
    jz      @no_decoy
    mov     rax, qword ptr [rsi + r14*8]
    test    rax, rax
    jz      @no_decoy
    mov     qword ptr [r13 + r14*8], rax
    jmp     @next_iter

@no_decoy:
    ; No decoy: leave original in place (don't spoof this frame)
@next_iter:
    inc     r14
    jmp     @spoof_loop
@spoof_done:

    ; Call fn(arg)
    ; fn signature: void fn(void* arg)
    mov     rcx, r12        ; arg
    call    rbx             ; fn(arg)

    ; Restore original return addresses
    xor     r14, r14
@restore_loop:
    cmp     r14, rdi
    jge     @restore_done
    mov     rax, qword ptr [rsp + 20h + r14*8]
    mov     qword ptr [r13 + r14*8], rax
    inc     r14
    jmp     @restore_loop
@restore_done:

    ; Epilogue
    add     rsp, 80h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

MoonwalkCall ENDP


; ─── MoonwalkStomp ────────────────────────────────────────────────────────────
; Permanently overwrites N stack slots above the caller.
; No save/restore. Use only when you will NOT return through those frames
; (e.g., right before calling NtTerminateProcess or RtlExitUserProcess).
;
; Signature: void MoonwalkStomp(void** decoy_table, DWORD n_decoys)
;   RCX = decoy_table
;   RDX = n_decoys
;

MoonwalkStomp PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi

    sub     rsp, 20h        ; shadow space

    mov     rbx, rcx        ; decoy_table
    mov     rsi, rdx        ; n_decoys

    ; Clamp to 8
    cmp     rsi, 8
    jbe     @stomp_clamp_ok
    mov     rsi, 8
@stomp_clamp_ok:

    ; Slot 0 is at [RBP+8]
    lea     rcx, [rbp + 8]  ; rcx = first slot address

    xor     rax, rax        ; loop index
@stomp_loop:
    cmp     rax, rsi
    jge     @stomp_done

    test    rbx, rbx
    jz      @stomp_done

    mov     rdx, qword ptr [rbx + rax*8]
    test    rdx, rdx
    jz      @stomp_next

    mov     qword ptr [rcx + rax*8], rdx

@stomp_next:
    inc     rax
    jmp     @stomp_loop
@stomp_done:

    add     rsp, 20h
    pop     rsi
    pop     rbx
    pop     rbp
    ret

MoonwalkStomp ENDP

END
