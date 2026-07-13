#ifndef WHIPSYSCALL_TYPES_H
#define WHIPSYSCALL_TYPES_H

// Types de base Windows
using BYTE = unsigned char;
using WORD = unsigned short;
using DWORD = unsigned long;
using QWORD = unsigned long long;
using PVOID = void*;
using SIZE_T = unsigned long long;
using LONG = long;
using ULONG = unsigned long;
using HANDLE = void*;
using NTSTATUS = long;
using BOOL = int;

#ifdef _WIN64
using LONG_PTR = long long;
using ULONG_PTR = unsigned long long;
#else
using LONG_PTR = long;
using ULONG_PTR = unsigned long;
#endif

// Calling convention
#define NTAPI __stdcall

// Status codes NT
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#endif // WHIPSYSCALL_TYPES_H