// ===== file: antidebug/checks/debug/remote_debug.h =====
//
// Detect remote debuggers by scanning TCP listening ports.
//
// Purpose
// -------
// WinDbg remote, IDA remote debug server, Frida, and similar tools expose
// well-known TCP ports. We resolve GetTcpTable2 from iphlpapi.dll at runtime
// via PEB walk (no IAT entry, no plaintext string) and scan for any local
// socket in LISTEN state on a known debugging port.
//
// Detected ports:
//   23946  — IDA remote debug server (ida_remote.exe / linux_server64)
//   4444   — WinDbg default remote pipe / Metasploit default
//   5555   — WinDbg alternate / ADB-over-TCP (used by some RE setups)
//   27042  — Frida default listening port
//   1337   — Common reverse-engineering / CTF backdoor port
//
// Returns 1 if any known debug port is in LISTEN state, 0 otherwise.
//
#ifndef ANTIDEBUG_REMOTE_DEBUG_H
#define ANTIDEBUG_REMOTE_DEBUG_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/api_guard.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// MIB_TCP_STATE — values from iprtrmib.h (no SDK include)
// ---------------------------------------------------------------------------
#define AD_MIB_TCP_STATE_LISTEN  2

// ---------------------------------------------------------------------------
// MIB_TCP6ROW2 is larger but we only need IPv4. MIB_TCPROW2 layout:
//   u32 dwState;            // +0
//   u32 dwLocalAddr;        // +4
//   u32 dwLocalPort;        // +8   (network byte order)
//   u32 dwRemoteAddr;       // +12
//   u32 dwRemotePort;       // +16  (network byte order)
//   u32 dwOwningPid;        // +20
//   u32 dwOffloadState;     // +24  (TCP_CONNECTION_OFFLOAD_STATE, Win Vista+)
// sizeof = 28 bytes
// ---------------------------------------------------------------------------
typedef struct {
    u32 dwState;
    u32 dwLocalAddr;
    u32 dwLocalPort;
    u32 dwRemoteAddr;
    u32 dwRemotePort;
    u32 dwOwningPid;
    u32 dwOffloadState;
} AD_MIB_TCPROW2;

// MIB_TCPTABLE2:
//   u32 dwNumEntries;
//   MIB_TCPROW2 table[1];
typedef struct {
    u32           dwNumEntries;
    AD_MIB_TCPROW2 table[1];
} AD_MIB_TCPTABLE2;

// GetTcpTable2 signature:
//   ULONG GetTcpTable2(PMIB_TCPTABLE2 TcpTable, PULONG SizePointer, BOOL bOrder);
typedef u32 (__stdcall *fn_GetTcpTable2)(AD_MIB_TCPTABLE2* TcpTable, u32* SizePointer, b32 bOrder);

// HeapAlloc / HeapFree / GetProcessHeap — for dynamic buffer
typedef void* (__stdcall *fn_GetProcessHeap)(void);
typedef void* (__stdcall *fn_HeapAlloc)(void* hHeap, u32 dwFlags, u64 dwBytes);
typedef b32   (__stdcall *fn_HeapFree)(void* hHeap, u32 dwFlags, void* lpMem);

// ---------------------------------------------------------------------------
// Module hash helper: "iphlpapi.dll" built on the stack (12 chars)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_hash_module_iphlpapi(void) {
    static u32 h = 0;
    if (!h) {
        u16 w[13];
        w[0]='i'; w[1]='p'; w[2]='h'; w[3]='l'; w[4]='p';
        w[5]='a'; w[6]='p'; w[7]='i'; w[8]='.'; w[9]='d';
        w[10]='l'; w[11]='l'; w[12]=0;
        h = ad_hash_wstr(w, 12);
    }
    return h;
}
#define AD_HASH_IPHLPAPI  ad_hash_module_iphlpapi()

// ---------------------------------------------------------------------------
// Network byte order port conversion (big-endian u16 in low word of DWORD).
// dwLocalPort stores the port in network byte order in the low 16 bits.
// We extract the low word and byte-swap to get the host-order port number.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u16 ad_ntohs_port(u32 raw) {
    u16 net = (u16)(raw & 0xFFFFu);
    return (u16)((net >> 8) | (net << 8));
}

// ---------------------------------------------------------------------------
// Known debug ports
// ---------------------------------------------------------------------------
static const u16 ad_debug_ports[] = {
    23946,  // IDA remote debug server
    4444,   // WinDbg / Metasploit
    5555,   // WinDbg alternate / ADB
    27042,  // Frida
    1337,   // Common RE backdoor
};
#define AD_NUM_DEBUG_PORTS  (sizeof(ad_debug_ports) / sizeof(ad_debug_ports[0]))

ANTIDEBUG_INLINE b32 ad_is_debug_port(u16 port) {
    u32 i;
    for (i = 0; i < AD_NUM_DEBUG_PORTS; i++) {
        if (port == ad_debug_ports[i]) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Main check: scan TCP table for listening debug ports
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_remote_debug_check(void) {
    // iphlpapi.dll may not be loaded yet. We need to load it.
    // Resolve LoadLibraryA from kernel32 to force-load iphlpapi.dll.
    typedef void* (__stdcall *fn_LoadLibraryA)(const char*);
    fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("LoadLibraryA"));

    if (pLoadLib) {
        // Build "iphlpapi.dll" on the stack (no string literal in .rdata)
        char lib_name[13];
        lib_name[0]  = 'i'; lib_name[1]  = 'p'; lib_name[2]  = 'h';
        lib_name[3]  = 'l'; lib_name[4]  = 'p'; lib_name[5]  = 'a';
        lib_name[6]  = 'p'; lib_name[7]  = 'i'; lib_name[8]  = '.';
        lib_name[9]  = 'd'; lib_name[10] = 'l'; lib_name[11] = 'l';
        lib_name[12] = '\0';
        pLoadLib(lib_name);
        AD_BARRIER();
    }

    // Resolve GetTcpTable2 from iphlpapi.dll (with hook check)
    fn_GetTcpTable2 pGetTcpTable2 = (fn_GetTcpTable2)
        ad_resolve_api_safe(AD_HASH_IPHLPAPI, AD_HASH("GetTcpTable2"));
    if (!pGetTcpTable2) return 0;

    // Resolve heap functions from kernel32 for buffer allocation
    fn_GetProcessHeap pGetHeap = (fn_GetProcessHeap)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetProcessHeap"));
    fn_HeapAlloc pHeapAlloc = (fn_HeapAlloc)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapAlloc"));
    fn_HeapFree pHeapFree = (fn_HeapFree)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapFree"));

    if (!pGetHeap || !pHeapAlloc || !pHeapFree) return 0;

    void* heap = pGetHeap();
    if (!heap) return 0;

    // Query required buffer size
    u32 table_size = 0;
    u32 ret = pGetTcpTable2(0, &table_size, 0);

    // ERROR_INSUFFICIENT_BUFFER = 122
    if (ret != 122u || table_size == 0) return 0;

    // Allocate buffer (HEAP_ZERO_MEMORY = 0x08)
    AD_MIB_TCPTABLE2* table = (AD_MIB_TCPTABLE2*)
        pHeapAlloc(heap, 0x08u, (u64)table_size);
    if (!table) return 0;

    ret = pGetTcpTable2(table, &table_size, 0);
    if (ret != 0) {
        pHeapFree(heap, 0, table);
        return 0;
    }

    AD_BARRIER();

    // Scan for listening debug ports
    b32 found = 0;
    u32 i;
    for (i = 0; i < table->dwNumEntries && !found; i++) {
        AD_MIB_TCPROW2* row = &table->table[i];
        if (row->dwState != AD_MIB_TCP_STATE_LISTEN) continue;

        u16 port = ad_ntohs_port(row->dwLocalPort);
        if (ad_is_debug_port(port)) {
            found = 1;
        }
    }

    pHeapFree(heap, 0, table);

    AD_BARRIER();
    return found;
}

// ---------------------------------------------------------------------------
// ATTACK 2 FIX: Port-independent remote debugger detection
//
// Problem: ad_remote_debug_check only scans 5 hardcoded ports. Changing
// Frida's or IDA's listening port (10 sec bypass) defeats it entirely.
//
// Solution: snapshot all localhost (127.0.0.1) TCP LISTEN sockets on high
// ports (> 10000) at init time. On each check cycle, compare against the
// baseline. New localhost listeners that appeared after init are potential
// debug servers started post-launch.
// ---------------------------------------------------------------------------

// Maximum number of baseline entries we track
#define AD_REMOTE_SNAP_MAX  128

typedef struct {
    u16 ports[AD_REMOTE_SNAP_MAX];   // baseline localhost high-port listeners
    u32 count;                        // number of entries in baseline
    b32 initialized;                  // set after first snapshot
} ad_remote_snap_t;

// File-scope baseline state
static volatile ad_remote_snap_t g_ad_remote_snap = {0};

// ---------------------------------------------------------------------------
// ad_remote_debug_snapshot_init
//
// Call once during init. Captures all localhost TCP LISTEN sockets on ports
// > 10000 as a baseline. Must be called BEFORE any ad_remote_debug_delta()
// checks.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_remote_debug_snapshot_init(void) {
    typedef void* (__stdcall *fn_LoadLibraryA)(const char*);
    fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("LoadLibraryA"));

    if (pLoadLib) {
        char lib_name[13];
        lib_name[0]  = 'i'; lib_name[1]  = 'p'; lib_name[2]  = 'h';
        lib_name[3]  = 'l'; lib_name[4]  = 'p'; lib_name[5]  = 'a';
        lib_name[6]  = 'p'; lib_name[7]  = 'i'; lib_name[8]  = '.';
        lib_name[9]  = 'd'; lib_name[10] = 'l'; lib_name[11] = 'l';
        lib_name[12] = '\0';
        pLoadLib(lib_name);
        AD_BARRIER();
    }

    fn_GetTcpTable2 pGetTcpTable2 = (fn_GetTcpTable2)
        ad_resolve_api(AD_HASH_IPHLPAPI, AD_HASH("GetTcpTable2"));
    if (!pGetTcpTable2) return;

    fn_GetProcessHeap pGetHeap = (fn_GetProcessHeap)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetProcessHeap"));
    fn_HeapAlloc pHeapAlloc = (fn_HeapAlloc)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapAlloc"));
    fn_HeapFree pHeapFree = (fn_HeapFree)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapFree"));
    if (!pGetHeap || !pHeapAlloc || !pHeapFree) return;

    void* heap = pGetHeap();
    if (!heap) return;

    u32 table_size = 0;
    u32 ret = pGetTcpTable2(0, &table_size, 0);
    if (ret != 122u || table_size == 0) return;

    AD_MIB_TCPTABLE2* table = (AD_MIB_TCPTABLE2*)
        pHeapAlloc(heap, 0x08u, (u64)table_size);
    if (!table) return;

    ret = pGetTcpTable2(table, &table_size, 0);
    if (ret != 0) {
        pHeapFree(heap, 0, table);
        return;
    }

    AD_BARRIER();

    // 127.0.0.1 in network byte order = 0x0100007F
    u32 localhost_nbo = 0x0100007Fu;
    u32 snap_count = 0u;

    u32 i;
    for (i = 0; i < table->dwNumEntries && snap_count < AD_REMOTE_SNAP_MAX; i++) {
        AD_MIB_TCPROW2* row = &table->table[i];
        if (row->dwState != AD_MIB_TCP_STATE_LISTEN) continue;
        if (row->dwLocalAddr != localhost_nbo) continue;

        u16 port = ad_ntohs_port(row->dwLocalPort);
        if (port > 1024u) {
            g_ad_remote_snap.ports[snap_count] = port;
            snap_count++;
        }
    }

    g_ad_remote_snap.count       = snap_count;
    g_ad_remote_snap.initialized = 1;

    pHeapFree(heap, 0, table);
    AD_BARRIER();
}

// ---------------------------------------------------------------------------
// ad_remote_debug_delta
//
// Returns 1 if NEW localhost high-port TCP listeners appeared since init.
// A new localhost listener on a high port is a strong indicator of a debug
// server (Frida, IDA remote, custom gdbserver) started after our process.
// This check is port-number-independent: it detects ANY new listener.
// ------------------           ---------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_remote_debug_delta(void) {
    if (!g_ad_remote_snap.initialized) return 0;

    fn_GetTcpTable2 pGetTcpTable2 = (fn_GetTcpTable2)
        ad_resolve_api(AD_HASH_IPHLPAPI, AD_HASH("GetTcpTable2"));
    if (!pGetTcpTable2) return 0;

    fn_GetProcessHeap pGetHeap = (fn_GetProcessHeap)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetProcessHeap"));
    fn_HeapAlloc pHeapAlloc = (fn_HeapAlloc)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapAlloc"));
    fn_HeapFree pHeapFree = (fn_HeapFree)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("HeapFree"));
    if (!pGetHeap || !pHeapAlloc || !pHeapFree) return 0;

    void* heap = pGetHeap();
    if (!heap) return 0;

    u32 table_size = 0;
    u32 ret = pGetTcpTable2(0, &table_size, 0);
    if (ret != 122u || table_size == 0) return 0;

    AD_MIB_TCPTABLE2* table = (AD_MIB_TCPTABLE2*)
        pHeapAlloc(heap, 0x08u, (u64)table_size);
    if (!table) return 0;

    ret = pGetTcpTable2(table, &table_size, 0);
    if (ret != 0) {
        pHeapFree(heap, 0, table);
        return 0;
    }

    AD_BARRIER();

    u32 localhost_nbo = 0x0100007Fu;
    b32 found_new = 0;

    u32 i;
    for (i = 0; i < table->dwNumEntries && !found_new; i++) {
        AD_MIB_TCPROW2* row = &table->table[i];
        if (row->dwState != AD_MIB_TCP_STATE_LISTEN) continue;
        if (row->dwLocalAddr != localhost_nbo) continue;

        u16 port = ad_ntohs_port(row->dwLocalPort);
        if (port <= 1024u) continue;

        // Check if this port was in our baseline snapshot
        b32 in_baseline = 0;
        u32 j;
        for (j = 0; j < g_ad_remote_snap.count; j++) {
            if (g_ad_remote_snap.ports[j] == port) {
                in_baseline = 1;
                break;
            }
        }

        if (!in_baseline) {
            found_new = 1;
        }
    }

    pHeapFree(heap, 0, table);
    AD_BARRIER();

    return found_new;
}

#else
ANTIDEBUG_INLINE b32 ad_remote_debug_check(void) { return 0; }
ANTIDEBUG_INLINE void ad_remote_debug_snapshot_init(void) {}
ANTIDEBUG_INLINE b32 ad_remote_debug_delta(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_REMOTE_DEBUG_H
