.code

; NTSTATUS SyscallStub(WORD ssn, PVOID arg1, ..., PVOID arg10)
; Convention x64 Windows : RCX=ssn, RDX=arg1, R8=arg2, R9=arg3, stack=arg4+
; Pour syscall : R10=RCX, RDX, R8, R9, stack+0x28=arg5+
; SSN dans EAX

SyscallStub PROC
    mov eax, ecx            ; SSN dans EAX (lower 16 bits de RCX)

    ; Shift arguments registres: RDX→RCX, R8→RDX, R9→R8
    mov rcx, rdx            ; arg1 → RCX
    mov rdx, r8             ; arg2 → RDX
    mov r8, r9              ; arg3 → R8

    ; arg4 est sur stack à [RSP+0x28], le mettre dans R9
    mov r9, [rsp + 28h]     ; arg4 → R9

    ; arg5 est à [RSP+0x30], doit être à [RSP+0x28]
    ; arg6 est à [RSP+0x38], doit être à [RSP+0x30]
    ; Décaler arg5+ de 8 bytes vers le bas
    mov r10, [rsp + 30h]
    mov [rsp + 28h], r10    ; arg5 → RSP+0x28

    mov r10, [rsp + 38h]
    mov [rsp + 30h], r10    ; arg6 → RSP+0x30

    mov r10, [rsp + 40h]
    mov [rsp + 38h], r10    ; arg7 → RSP+0x38

    mov r10, [rsp + 48h]
    mov [rsp + 40h], r10    ; arg8 → RSP+0x40

    mov r10, [rsp + 50h]
    mov [rsp + 48h], r10    ; arg9 → RSP+0x48

    mov r10, [rsp + 58h]
    mov [rsp + 50h], r10    ; arg10 → RSP+0x50

    mov r10, [rsp + 60h]
    mov [rsp + 58h], r10    ; arg11 → RSP+0x58

    ; Faire le syscall
    mov r10, rcx            ; R10 = RCX (requis par convention syscall)
    syscall

    ret
SyscallStub ENDP

END