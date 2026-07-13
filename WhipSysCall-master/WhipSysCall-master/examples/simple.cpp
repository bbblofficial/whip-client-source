/*
 * WhipSysCall - Exemple Simple
 *
 * Cet exemple montre comment utiliser WhipSysCall pour:
 * - Résoudre des syscalls depuis ntdll.dll
 * - Allouer/libérer de la mémoire via syscall direct
 * - Obtenir des informations système
 */

#include "whipsyscall/WhipSysCall.h"
#include <stdio.h>

int main() {
    printf("\n=== WhipSysCall - Exemple Simple ===\n\n");

    // ========================================
    // 1. Initialiser le resolver
    // ========================================
    printf("[1] Initialisation...\n");

    SyscallResolver resolver;
    if (!resolver.Init()) {
        printf("    ERREUR: Impossible d'initialiser le resolver!\n");
        return 1;
    }

    printf("    OK: %d syscalls resolus\n\n", resolver.GetCount());

    // ========================================
    // 2. Créer les wrappers
    // ========================================
    SyscallWrappers wrappers(&resolver);

    // ========================================
    // 3. Informations processus
    // ========================================
    printf("[2] Informations processus:\n");

    DWORD pid = wrappers.GetCurrentProcessId();
    DWORD tid = wrappers.GetCurrentThreadId();
    QWORD timestamp = wrappers.GetSystemTime();

    printf("    PID: %lu\n", pid);
    printf("    TID: %lu\n", tid);
    printf("    Timestamp Unix: %llu\n\n", timestamp);

    // ========================================
    // 4. Allocation mémoire
    // ========================================
    printf("[3] Allocation memoire (8192 bytes):\n");

    PVOID memory = wrappers.HeapAlloc(8192);
    if (!memory) {
        printf("    ERREUR: Allocation echouee!\n");
        return 1;
    }

    printf("    OK: Memoire allouee a 0x%p\n", memory);

    // Utiliser la mémoire
    BYTE* buffer = static_cast<BYTE*>(memory);
    for (int i = 0; i < 8192; i++) {
        buffer[i] = static_cast<BYTE>(i % 256);
    }
    printf("    OK: Donnees ecrites\n");

    // Libérer
    if (wrappers.HeapFree(memory)) {
        printf("    OK: Memoire liberee\n\n");
    }

    // ========================================
    // 5. Résolution directe d'un syscall
    // ========================================
    printf("[4] Resolution directe de NtAllocateVirtualMemory:\n");

    WORD ssn = 0;
    PVOID address = nullptr;

    if (resolver.ResolveByName("NtAllocateVirtualMemory", ssn, address)) {
        printf("    SSN: 0x%04X\n", ssn);
        printf("    Adresse: 0x%p\n\n", address);
    }

    // ========================================
    // 5. AfdSocket::Create - test variations
    // ========================================

    // Helper lambda : ferme un handle via NtClose
    auto closeHandle = [&](HANDLE h) {
        WORD cSSN = 0; PVOID cAddr = nullptr;
        if (resolver.ResolveByName("NtClose", cSSN, cAddr))
            SyscallInvoker::Invoke(cSSN, h);
    };

    // --- Variation 0: appel DIRECT via pointeur ntdll (sans SyscallStub) ---
    printf("[5x] NtCreateFile via ntdll ptr        : ");
    {
        WORD ntcfSSN = 0; PVOID ntcfAddr = nullptr;
        if (!resolver.ResolveByName("NtCreateFile", ntcfSSN, ntcfAddr)) {
            printf("NOT FOUND\n");
        } else {
            typedef NTSTATUS (NTAPI *NtCreateFileT)(
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
            NtCreateFileT pNtCF = reinterpret_cast<NtCreateFileT>(ntcfAddr);

            const WCHAR pathX[] = {
                L'\\',L'D',L'e',L'v',L'i',L'c',L'e',L'\\',
                L'A',L'f',L'd',L'\\',L'E',L'n',L'd',L'p',L'o',L'i',L'n',L't',0
            };
            UNICODE_STRING uX; uX.Length = 20*sizeof(WCHAR); uX.MaximumLength = uX.Length+2; uX.Buffer = const_cast<PWSTR>(pathX);
            OBJECT_ATTRIBUTES oaX = {}; oaX.Length = sizeof(OBJECT_ATTRIBUTES); oaX.ObjectName = &uX; oaX.Attributes = 0x40;
            IO_STATUS_BLOCK iosX = {};
            HANDLE hX = nullptr;

            AfdCreateEa eaX = {};
            const char eanX[] = "AfdOpenPacket\x58\x58";
            for (int i=0;i<16;++i) eaX.EaName[i]=eanX[i];
            eaX.EaNameLength=15; eaX.AddressFamily=2; eaX.SocketType=1; eaX.Protocol=6;
            eaX.TransportLength=0; eaX.EaValueLength=30;
            eaX.EaEntrySize=8u+15u+1u+30u; eaX.Reserved=0;
            ULONG eaLenX = 8u + eaX.EaNameLength + 1u + eaX.EaValueLength; // 54

            NTSTATUS sX = pNtCF(
                &hX,
                GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
                &oaX, &iosX, nullptr, 0,
                FILE_SHARE_READ|FILE_SHARE_WRITE,
                FILE_CREATE,  // 2
                FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,  // 0x60
                &eaX, eaLenX
            );
            if (NT_SUCCESS(sX)) { printf("OK handle=0x%p\n", hX); closeHandle(hX); }
            else                 printf("FAIL status=0x%08X\n", (unsigned)sX);
        }
    }

    // --- Variation 1: chemin \Device\Afd\Endpoint (actuel) ---
    printf("[5a] NtCreateFile \\Device\\Afd\\Endpoint : ");
    {
        HANDLE h = AfdSocket::Create(&resolver);
        if (h) { printf("OK handle=0x%p\n", h); closeHandle(h); }
        else     printf("FAIL\n");
    }

    // --- Variation 2: chemin \Device\Afd (sans \Endpoint) ---
    printf("[5b] NtCreateFile \\Device\\Afd          : ");
    {
        WORD ssn2 = 0; PVOID addr2 = nullptr;
        if (!resolver.ResolveByName("NtCreateFile", ssn2, addr2)) {
            printf("SSN NOT FOUND\n");
        } else {
            const WCHAR path2[] = {
                L'\\',L'D',L'e',L'v',L'i',L'c',L'e',L'\\',L'A',L'f',L'd',0
            };
            UNICODE_STRING uPath2;
            uPath2.Length        = 11 * sizeof(WCHAR);
            uPath2.MaximumLength = uPath2.Length + sizeof(WCHAR);
            uPath2.Buffer        = const_cast<PWSTR>(path2);

            OBJECT_ATTRIBUTES oa2 = {};
            oa2.Length    = sizeof(OBJECT_ATTRIBUTES);
            oa2.ObjectName= &uPath2;
            oa2.Attributes= 0x00000040; // OBJ_CASE_INSENSITIVE

            // reuse same EA as AfdSocket::Create (Win11 24H2 format)
            AfdCreateEa ea2 = {};
            const char ean[] = "AfdOpenPacket\x58\x58";
            for (int i = 0; i < 16; ++i) ea2.EaName[i] = ean[i];
            ea2.EaNameLength   = 15;
            ea2.AddressFamily  = 2; ea2.SocketType = 1; ea2.Protocol = 6;
            ea2.TransportLength= 0; ea2.EaValueLength = 30;
            ea2.EaEntrySize    = 8u+15u+1u+30u; ea2.Reserved = 0;
            ULONG eaLen2       = 8u + ea2.EaNameLength + 1u + ea2.EaValueLength; // 54

            IO_STATUS_BLOCK ios2 = {};
            HANDLE h2 = nullptr;
            NTSTATUS s2 = SyscallInvoker::Invoke(
                ssn2,
                &h2,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE)),
                &oa2,
                &ios2,
                nullptr,
                reinterpret_cast<PVOID>(0ULL),
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(FILE_SHARE_READ|FILE_SHARE_WRITE)),
                reinterpret_cast<PVOID>(2ULL),   // FILE_CREATE
                reinterpret_cast<PVOID>(0x60ULL), // SYNC|NON_DIR
                &ea2,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(eaLen2))
            );
            char hx[16]; const char* hh="0123456789ABCDEF";
            hx[0]='0';hx[1]='x';
            unsigned long sv=(unsigned long)s2;
            for(int b=28,i=2;b>=0;b-=4,i++) hx[i]=hh[(sv>>b)&0xF];
            hx[10]='\n';hx[11]=0;
            if (NT_SUCCESS(s2)) { printf("OK handle=0x%p\n", h2); closeHandle(h2); }
            else                { printf("FAIL status="); OutputDebugStringA(hx); printf("%s",hx); }
        }
    }

    printf("\n=== Termine! ===\n\n");
    return 0;
}