#ifndef WHIPSYSCALL_AFDSOCKET_H
#define WHIPSYSCALL_AFDSOCKET_H

#include "Types.h"
#include "SyscallResolver.h"
#include "SyscallInvoker.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

// =====================================================================
// AFD DIRECT SOCKET INTERFACE
// Bypasses ws2_32.dll by calling the NT AFD kernel driver directly via
// NtDeviceIoControlFile. No Winsock imports required.
// Compatible with Windows 10/11 x64.
// =====================================================================

// AFD IOCTL codes — Windows 11 24H2 (build 26200), captured from WS2_32 via NtDeviceIoControlFile hook.
// Formula: CTL_CODE(DeviceType=0x0001, fn=0x800+old_fn, METHOD_NEITHER=3, FILE_ANY_ACCESS=0)
//        = (0x01 << 16) | ((0x800 + old_fn) << 2) | 3
//        = 0x12000 | (old_fn << 2) | 3
// Classic (pre-Win11 24H2) used device type 0x0012, giving 0x120000-based codes.
// New codes just drop one hex zero: 0x12000x → 0x1200x.
#define IOCTL_AFD_BIND              0x12003UL   // old fn=0
#define IOCTL_AFD_CONNECT           0x12007UL   // old fn=1
#define IOCTL_AFD_RECV              0x12017UL   // old fn=5
#define IOCTL_AFD_SEND              0x1201FUL   // old fn=7
#define IOCTL_AFD_DISCONNECT        0x1202BUL   // old fn=10
#define IOCTL_AFD_SET_INFO          0x1203BUL   // old fn=14

// Server-side IOCTL codes
#define IOCTL_AFD_START_LISTEN      0x1200BUL   // fn=2,  METHOD_NEITHER  — make socket listen
#define IOCTL_AFD_WAIT_FOR_LISTEN   0x1200CUL   // fn=3,  METHOD_BUFFERED — blocks until connection arrives, returns seqNum
#define IOCTL_AFD_ACCEPT            0x12010UL   // fn=4,  METHOD_BUFFERED — sent to accept socket, completes handshake
#define IOCTL_AFD_GET_SOCK_NAME     0x1202FUL   // fn=11, METHOD_NEITHER  — returns bound local address

// Socket constants (no winsock2.h dependency)
#define AFD_AF_INET                 2
#define AFD_SOCK_STREAM             1
#define AFD_IPPROTO_TCP             6

// NtCreateFile flags for socket endpoint creation
// Values captured from WS2_32.dll on Windows 11 24H2 via NtCreateFile spy:
//   DesiredAccess    = 0xC0100000  (GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE)
//   Note: WS2_32 first tries 0xC0140000 (adds WRITE_DAC) but ACCESS_DENIED on \Device\Afd
//         for regular users. It silently retries without WRITE_DAC. We use the working value.
//   CreateDisposition= 3           (FILE_OPEN_IF, NOT FILE_CREATE!)
//   CreateOptions    = 0x20        (FILE_SYNCHRONOUS_IO_NONALERT only, NO FILE_NON_DIRECTORY_FILE)
//   Path             = \Device\Afd (NOT \Device\Afd\Endpoint)
#define AFD_DESIRED_ACCESS          0xC0100000UL // GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE
#define AFD_SHARE_ACCESS            (FILE_SHARE_READ | FILE_SHARE_WRITE)
#define AFD_CREATE_DISPOSITION      3UL   // FILE_OPEN_IF
#define AFD_CREATE_OPTIONS          0x20UL // FILE_SYNCHRONOUS_IO_NONALERT

// AFD disconnect types (maps to TDI disconnect flags)
#define AFD_DISCONNECT_ABORT        0x01UL  // TCP RST
#define AFD_DISCONNECT_GRACEFUL     0x02UL  // TCP FIN

// AFD_INFO types for IOCTL_AFD_SET_INFO
#define AFD_INFO_RECV_TIMEOUT       0x07UL
#define AFD_INFO_SEND_TIMEOUT       0x08UL

// =====================================================================
// AFD STRUCTURES
// Natural alignment (no pragma pack) for I/O structures passed via
// NtDeviceIoControlFile — kernel accesses them through typed pointers.
// AfdCreateEa uses #pragma pack(1) because it is an EA byte stream.
// =====================================================================

// IPv4 socket address — matches SOCKADDR_IN without ws2_32.h
struct AfdSockAddrIn {
    SHORT  Family;      // AF_INET = 2
    USHORT Port;        // big-endian
    ULONG  Address;     // little-endian inet_addr() format (bytes: a,b,c,d)
    BYTE   Zero[8];
};

// Bind request
struct AfdBindData {
    ULONG         ShareType;    // 0 = exclusive
    AfdSockAddrIn Address;
};

// Connect request — layout captured from WS2_32 on Windows 11 24H2 (40 bytes total):
//   0x00..0x0F  ULONG[4]      Reserved, all zeros (16 bytes)
//   0x10..0x17  LARGE_INTEGER Timeout deadline in QPC ticks (INT64_MAX = no timeout)
//   0x18..0x27  AfdSockAddrIn RemoteAddress (16 bytes)
struct AfdConnectInfo {
    ULONG         Reserved[4];   // 0x00: zeros
    LARGE_INTEGER Timeout;       // 0x10: QPC deadline; INT64_MAX = no timeout
    AfdSockAddrIn RemoteAddress; // 0x18: target
};

// Scatter/gather buffer — matches WSABUF layout (pointer after 4-byte len + padding)
struct AfdWsaBuf {
    ULONG  Len;
    // Implicit 4-byte padding on x64 to align Buf to 8-byte boundary
    BYTE*  Buf;
};

// Send request
struct AfdSendInfo {
    AfdWsaBuf* BufferArray;
    ULONG      BufferCount;
    ULONG      AfdFlags;    // 0 = blocking
    ULONG      TdiFlags;    // 0
};

// Recv request
struct AfdRecvInfo {
    AfdWsaBuf* BufferArray;
    ULONG      BufferCount;
    ULONG      AfdFlags;    // 0 = blocking
    ULONG      TdiFlags;    // 0
};

// Disconnect request
struct AfdDisconnectInfo {
    ULONG         Type;     // AFD_DISCONNECT_ABORT or AFD_DISCONNECT_GRACEFUL
    LARGE_INTEGER Timeout;  // QuadPart = 0 for immediate
};

// Socket option info for IOCTL_AFD_SET_INFO
struct AfdInfo {
    ULONG InformationType;
    union {
        ULONG   Ulong;
        ULONG64 LargeInt;
    } Data;
};

// EA buffer for NtCreateFile — kernel reads as raw byte stream, must be packed.
//
// Captured from WS2_32.dll on Windows 11 24H2 via inline hook:
//   EaNameLength = 15  ("AfdOpenPacket" + 2 extra bytes 0x58 0x58)
//   EaValueLength = 30  (6 x ULONG + 1 x ULONG + 1 x USHORT = 30 bytes)
//
// AFD_CREATE_PACKET value (30 bytes on Win11 24H2):
//   ULONG  EndpointFlags       (0)
//   ULONG  GroupID             (0)
//   ULONG  AddressFamily       (2 = AF_INET)
//   ULONG  SocketType          (1 = SOCK_STREAM)
//   ULONG  Protocol            (6 = IPPROTO_TCP)
//   ULONG  SizeOfTransportName (0 — driver selects transport automatically)
//   ULONG  EaEntrySize         (54 = total EA entry size, Win11 24H2 self-size field)
//   USHORT Reserved            (0)
//
// Total entry: 8 (header) + 15 (name) + 1 (NUL) + 30 (value) = 54 bytes.
#pragma pack(push, 1)
struct AfdCreateEa {
    // FILE_FULL_EA_INFORMATION header
    ULONG  NextEntryOffset;     // 0 (only entry)
    UCHAR  Flags;               // 0
    UCHAR  EaNameLength;        // 15 (captured from WS2_32)
    USHORT EaValueLength;       // 30 = 6 x ULONG + ULONG + USHORT
    CHAR   EaName[16];          // "AfdOpenPacket\x58\x58\0" (15 chars + null)
    // AFD_CREATE_PACKET value — 30 bytes
    ULONG  EndpointFlags;       // 0
    ULONG  GroupID;             // 0
    ULONG  AddressFamily;       // AFD_AF_INET    = 2
    ULONG  SocketType;          // AFD_SOCK_STREAM = 1
    ULONG  Protocol;            // AFD_IPPROTO_TCP = 6
    ULONG  TransportLength;     // 0 (no transport name, afd.sys auto-selects)
    ULONG  EaEntrySize;         // total EA entry size (8+EaNameLength+1+EaValueLength)
    USHORT Reserved;            // 0
};
#pragma pack(pop)

// ------------------------------------------------------------------
// Server-side structures
// ------------------------------------------------------------------

// Input for IOCTL_AFD_START_LISTEN.
// Layout (natural alignment, same as AFD.sys internal definition):
//   +0 : BOOLEAN UseSAN              (1 byte, FALSE)
//   +1 : _pad[3]                     (alignment to ULONG)
//   +4 : ULONG   Backlog
//   +8 : BOOLEAN UseDelayedAcceptance(1 byte, FALSE)
//   +9 : _pad2[3]                    (tail alignment)
// sizeof = 12 bytes
struct AfdListenData {
    BYTE  UseSAN;                // 0 = FALSE
    BYTE  _pad[3];
    ULONG Backlog;
    BYTE  UseDelayedAcceptance;  // 0 = FALSE
    BYTE  _pad2[3];
};

// Output of IOCTL_AFD_WAIT_FOR_LISTEN.
// Returned when a TCP connection is pending on the listener.
// Contains the sequence number needed for IOCTL_AFD_ACCEPT, plus
// the remote address in TRANSPORT_ADDRESS / IPv4 format.
//   +0  : ULONG  SequenceNumber      (pass to AfdAcceptData)
//   +4  : LONG   TAAddressCount = 1
//   +8  : USHORT AddressLength = 14  (IPv4 payload: port+addr+zero)
//   +10 : USHORT AddressType = 2     (AF_INET)
//   +12 : USHORT RemotePort          (network byte order)
//   +14 : ULONG  RemoteAddress       (inet_addr format)
//   +18 : BYTE   RemotePad[8]
// sizeof = 26 bytes — allocate 64 to absorb any extra fields
struct AfdWaitForListenData {
    ULONG  SequenceNumber;
    LONG   TAAddressCount;
    USHORT AddressLength;
    USHORT AddressType;
    USHORT RemotePort;
    ULONG  RemoteAddress;
    BYTE   RemotePad[8];
};

// Output of IOCTL_AFD_GET_SOCK_NAME — returns the local bound address.
// Same layout as a TRANSPORT_ADDRESS for IPv4:
//   +0  : LONG   TAAddressCount = 1
//   +4  : USHORT AddressLength = 14
//   +6  : USHORT AddressType = 2 (AF_INET)
//   +8  : USHORT Port             (network byte order — swap to get host port)
//   +10 : ULONG  Address
//   +14 : BYTE   Pad[8]
// sizeof = 22 bytes — allocate 64 to be safe
struct AfdSockNameData {
    LONG   TAAddressCount;
    USHORT AddressLength;
    USHORT AddressType;
    USHORT Port;    // network byte order
    ULONG  Address;
    BYTE   Pad[8];
};

// Input for IOCTL_AFD_ACCEPT — sent to the NEW (accept) socket.
// Completes the three-way handshake by associating the pending
// connection (identified by SequenceNumber) with the accept socket.
//   +0 : BOOLEAN SanConnection      (1 byte, FALSE)
//   +1 : _pad[3]                    (alignment)
//   +4 : ULONG   SequenceNumber     (from AfdWaitForListenData)
//   +8 : HANDLE  ListenSocket       (8 bytes on x64)
// sizeof = 16 bytes on x64
struct AfdAcceptData {
    BYTE   SanConnection;  // 0 = FALSE
    BYTE   _pad[3];
    ULONG  SequenceNumber;
    HANDLE ListenSocket;
};

// =====================================================================
// AFD SOCKET CLASS
// All methods are __forceinline to prevent IAT hooks.
// Caller is responsible for passing a valid SyscallResolver*.
// =====================================================================

class AfdSocket {
public:
    // Byte-swap USHORT: host-to-network port order
    static __forceinline USHORT HostToNetPort(USHORT port) {
        return static_cast<USHORT>((port >> 8) | (port << 8));
    }

    // Parse "a.b.c.d" → ULONG in inet_addr() format.
    // Returned value stored as-is in AfdSockAddrIn.Address.
    // Memory bytes will be [a][b][c][d] — correct network byte order on wire.
    static __forceinline ULONG ParseIpv4(const char* str) {
        if (!str) return 0;
        ULONG oct[4] = { 0 };
        int idx = 0;
        for (const char* p = str; *p; ++p) {
            char c = *p;
            if (c >= '0' && c <= '9') {
                oct[idx] = oct[idx] * 10u + static_cast<ULONG>(c - '0');
                if (oct[idx] > 255u) return 0;
            } else if (c == '.') {
                if (++idx > 3) return 0;
            } else {
                return 0;
            }
        }
        if (idx != 3) return 0;
        return oct[0] | (oct[1] << 8) | (oct[2] << 16) | (oct[3] << 24);
    }

    // ------------------------------------------------------------------
    // Create a TCP socket endpoint via NtCreateFile on \Device\Afd
    // Parameters captured from WS2_32 on Windows 11 24H2 (build 26200).
    // Returns a valid HANDLE on success, nullptr on failure.
    // ------------------------------------------------------------------
    static __forceinline HANDLE Create(SyscallResolver* resolver) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtCreateFile", ssn, addr))
            return nullptr;

        // \Device\Afd  (11 WCHARs, no \Endpoint suffix)
        const WCHAR path[] = {
            L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\',
            L'A', L'f', L'd', 0
        };
        UNICODE_STRING uPath;
        uPath.Length        = 11 * sizeof(WCHAR);  // 22 bytes
        uPath.MaximumLength = uPath.Length + sizeof(WCHAR);
        uPath.Buffer        = const_cast<PWSTR>(path);

        OBJECT_ATTRIBUTES objAttr;
        objAttr.Length                   = sizeof(OBJECT_ATTRIBUTES);
        objAttr.RootDirectory            = nullptr;
        objAttr.ObjectName               = &uPath;
        objAttr.Attributes               = 0x00000040; // OBJ_CASE_INSENSITIVE
        objAttr.SecurityDescriptor       = nullptr;
        objAttr.SecurityQualityOfService = nullptr;

        IO_STATUS_BLOCK ioStatus = { 0 };
        HANDLE          hSocket  = nullptr;

        // Build EA — "AfdOpenPacket\x58\x58" (EaNameLength=15), value = 6×ULONG, no TransportName
        AfdCreateEa ea;
        ea.NextEntryOffset = 0;
        ea.Flags           = 0;
        ea.EaNameLength    = 15; // captured: 13 chars + 2 padding bytes (0x58 0x58)
        // "AfdOpenPacket\x58\x58\0" — 16 bytes total in EaName[16]
        const char eaNameLiteral[] = "AfdOpenPacket\x58\x58";
        for (int i = 0; i < 16; ++i) ea.EaName[i] = eaNameLiteral[i];
        ea.EndpointFlags   = 0;
        ea.GroupID         = 0;
        ea.AddressFamily   = AFD_AF_INET;
        ea.SocketType      = AFD_SOCK_STREAM;
        ea.Protocol        = AFD_IPPROTO_TCP;
        ea.TransportLength = 0; // Win11 24H2: transport selected automatically
        // EaValueLength = 6×ULONG + ULONG + USHORT = 30 bytes (Win11 24H2 extended format)
        ea.EaValueLength   = 6u * sizeof(ULONG) + sizeof(ULONG) + sizeof(USHORT); // 30
        // EaEntrySize = self-size field: total bytes of this EA entry
        // = 8 (header) + EaNameLength (15) + NUL (1) + EaValueLength (30) = 54
        ea.EaEntrySize     = 8u + ea.EaNameLength + 1u + ea.EaValueLength; // 54
        ea.Reserved        = 0;

        // EaLength = same as EaEntrySize (single entry)
        const ULONG eaLen = ea.EaEntrySize; // 54

        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            &hSocket,                                                               // arg1:  FileHandle
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(AFD_DESIRED_ACCESS)),   // arg2:  DesiredAccess
            &objAttr,                                                               // arg3:  ObjectAttributes
            &ioStatus,                                                              // arg4:  IoStatusBlock
            nullptr,                                                                // arg5:  AllocationSize
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),                    // arg6:  FileAttributes
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(AFD_SHARE_ACCESS)),     // arg7:  ShareAccess
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(AFD_CREATE_DISPOSITION)), // arg8: CreateDisposition (3=FILE_OPEN_IF)
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(AFD_CREATE_OPTIONS)),   // arg9:  CreateOptions (0x20=SYNC_NONALERT)
            &ea,                                                                    // arg10: EaBuffer
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(eaLen))                 // arg11: EaLength (48)
        );

        return NT_SUCCESS(status) ? hSocket : nullptr;
    }

    // ------------------------------------------------------------------
    // Bind to a specific address and port.
    // ipNetOrder = inet_addr() format (use ParseIpv4, or 0 for INADDR_ANY).
    // port = host byte order (0 for auto-assign).
    // ------------------------------------------------------------------
    static __forceinline bool BindTo(SyscallResolver* resolver, HANDLE socket,
                                     ULONG ipNetOrder, USHORT port) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdBindData bd;
        bd.ShareType       = 2;
        bd.Address.Family  = AFD_AF_INET;
        bd.Address.Port    = HostToNetPort(port);
        bd.Address.Address = ipNetOrder;
        for (int i = 0; i < 8; ++i) bd.Address.Zero[i] = 0;

        BYTE out[64] = {};
        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,
            nullptr, nullptr, nullptr, &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_BIND)),
            &bd,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(bd))),
            out,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(out)))
        );
        return NT_SUCCESS(status);
    }

    // ------------------------------------------------------------------
    // Bind to INADDR_ANY with an auto-assigned port.
    // Called by Connect() before connecting — required by AFD on Win11 24H2.
    // Output buffer receives the actual bound address (kernel fills in port).
    // ------------------------------------------------------------------
    static __forceinline bool Bind(SyscallResolver* resolver, HANDLE socket) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdBindData bd;
        bd.ShareType       = 2; // captured from WS2_32: always 2 (allow address reuse)
        bd.Address.Family  = AFD_AF_INET;
        bd.Address.Port    = 0;
        bd.Address.Address = 0; // INADDR_ANY
        for (int i = 0; i < 8; ++i) bd.Address.Zero[i] = 0;

        // Output: AFD writes back the actual local address (TRANSPORT_ADDRESS for IPv4 ≈ 22 bytes).
        // Use 64 bytes to cover all IPv4/IPv6 variants without needing to know the exact size.
        BYTE out[64] = {};

        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,                                                                  // arg1
            nullptr,                                                                 // arg2: Event
            nullptr,                                                                 // arg3: ApcRoutine
            nullptr,                                                                 // arg4: ApcContext
            &ioStatus,                                                               // arg5
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_BIND)),        // arg6: IoControlCode
            &bd,                                                                     // arg7: InputBuffer
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(bd))),            // arg8: InputBufferLength
            out,                                                                     // arg9: OutputBuffer (receives bound addr)
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(out)))            // arg10: OutputBufferLength
        );
        return NT_SUCCESS(status);
    }

    // ------------------------------------------------------------------
    // Connect to remote IPv4:port.
    // ipNetOrder must be in inet_addr() format (use ParseIpv4).
    // port is in host byte order (will be converted internally).
    // ------------------------------------------------------------------
    static __forceinline bool Connect(SyscallResolver* resolver, HANDLE socket,
                                      ULONG ipNetOrder, USHORT port) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        // WS2_32 explicitly binds to INADDR_ANY:0 before connecting.
        Bind(resolver, socket); // ignore failure — socket may already be bound

        // Compute a QPC-based connect deadline, as WS2_32 does.
        // Captured: Timeout = QueryPerformanceCounter() + connect_timeout_ticks.
        // We use NtQueryPerformanceCounter syscall to read the current QPC, then
        // add 30 seconds worth of ticks (assuming 10 MHz QPC, standard on Win11).
        LONGLONG timeoutTicks = 30LL * 10000000LL; // 30s × 10 MHz = 300,000,000 ticks
        {
            WORD  qpcSSN; PVOID qpcAddrUnused;
            if (resolver->ResolveByName("NtQueryPerformanceCounter", qpcSSN, qpcAddrUnused)) {
                LARGE_INTEGER qpcNow = {}, qpcFreq = {};
                SyscallInvoker::Invoke(qpcSSN, &qpcNow, &qpcFreq);
                // Use actual frequency if available (should be 10,000,000 on Win11)
                LONGLONG freq = (qpcFreq.QuadPart > 0) ? qpcFreq.QuadPart : 10000000LL;
                timeoutTicks = qpcNow.QuadPart + 30LL * freq;
            }
        }

        AfdConnectInfo ci;
        ci.Reserved[0]             = 0;
        ci.Reserved[1]             = 0;
        ci.Reserved[2]             = 0;
        ci.Reserved[3]             = 0;
        ci.Timeout.QuadPart        = timeoutTicks; // QPC deadline: now + 30 seconds
        ci.RemoteAddress.Family    = AFD_AF_INET;
        ci.RemoteAddress.Port      = HostToNetPort(port);
        ci.RemoteAddress.Address   = ipNetOrder;
        for (int i = 0; i < 8; ++i) ci.RemoteAddress.Zero[i] = 0;

        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_CONNECT)),
            &ci,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(ci))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );
        return NT_SUCCESS(status);
    }

    // ------------------------------------------------------------------
    // Send bytes. Returns true and sets bytesSent on success.
    // ------------------------------------------------------------------
    static __forceinline bool Send(SyscallResolver* resolver, HANDLE socket,
                                   const BYTE* data, ULONG length, ULONG& bytesSent) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdWsaBuf wsaBuf;
        wsaBuf.Len = length;
        wsaBuf.Buf = const_cast<BYTE*>(data);

        AfdSendInfo si;
        si.BufferArray = &wsaBuf;
        si.BufferCount = 1;
        si.AfdFlags    = 0;
        si.TdiFlags    = 0;

        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_SEND)),
            &si,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(si))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );

        if (NT_SUCCESS(status)) {
            bytesSent = static_cast<ULONG>(ioStatus.Information);
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Receive bytes (blocking). Returns true and sets bytesRecv on success.
    // ------------------------------------------------------------------
    static __forceinline bool Recv(SyscallResolver* resolver, HANDLE socket,
                                   BYTE* buffer, ULONG bufferSize, ULONG& bytesRecv) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdWsaBuf wsaBuf;
        wsaBuf.Len = bufferSize;
        wsaBuf.Buf = buffer;

        AfdRecvInfo ri;
        ri.BufferArray = &wsaBuf;
        ri.BufferCount = 1;
        ri.AfdFlags    = 0;
        ri.TdiFlags    = 0x20; // TDI_RECEIVE_NORMAL — required by AFD.sys on Win11 24H2

        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_RECV)),
            &ri,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(ri))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );

        if (NT_SUCCESS(status)) {
            bytesRecv = static_cast<ULONG>(ioStatus.Information);
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Disconnect the socket. graceful=false sends TCP RST, true sends FIN.
    // ------------------------------------------------------------------
    static __forceinline bool Disconnect(SyscallResolver* resolver, HANDLE socket,
                                         bool graceful = false) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdDisconnectInfo di;
        di.Type            = graceful ? AFD_DISCONNECT_GRACEFUL : AFD_DISCONNECT_ABORT;
        di.Timeout.QuadPart = 0;

        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_DISCONNECT)),
            &di,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(di))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );
        return NT_SUCCESS(status);
    }

    // ------------------------------------------------------------------
    // Close the socket handle via NtClose.
    // ------------------------------------------------------------------
    static __forceinline void Close(SyscallResolver* resolver, HANDLE socket) {
        if (!socket) return;
        WORD  ssn;
        PVOID addr;
        if (resolver->ResolveByName("NtClose", ssn, addr))
            SyscallInvoker::Invoke(ssn, socket);
    }

    // ------------------------------------------------------------------
    // Set receive/send timeouts in milliseconds (0 = skip that direction).
    // ------------------------------------------------------------------
    static __forceinline bool SetTimeout(SyscallResolver* resolver, HANDLE socket,
                                         ULONG recvMs, ULONG sendMs) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        bool ok = true;

        if (recvMs > 0) {
            AfdInfo info;
            info.InformationType = AFD_INFO_RECV_TIMEOUT;
            info.Data.Ulong      = recvMs;
            IO_STATUS_BLOCK ioStatus = { 0 };
            NTSTATUS s = SyscallInvoker::Invoke(
                ssn,
                socket, nullptr, nullptr, nullptr, &ioStatus,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_SET_INFO)),
                &info,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(info))),
                nullptr,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
            );
            ok = ok && NT_SUCCESS(s);
        }

        if (sendMs > 0) {
            AfdInfo info;
            info.InformationType = AFD_INFO_SEND_TIMEOUT;
            info.Data.Ulong      = sendMs;
            IO_STATUS_BLOCK ioStatus = { 0 };
            NTSTATUS s = SyscallInvoker::Invoke(
                ssn,
                socket, nullptr, nullptr, nullptr, &ioStatus,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_SET_INFO)),
                &info,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(info))),
                nullptr,
                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
            );
            ok = ok && NT_SUCCESS(s);
        }

        return ok;
    }

    // ------------------------------------------------------------------
    // Start listening.  Must be called after Bind().
    // ------------------------------------------------------------------
    static __forceinline bool Listen(SyscallResolver* resolver, HANDLE socket,
                                     ULONG backlog = 5) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdListenData ld = {};
        ld.UseSAN                = 0;
        ld.Backlog               = backlog;
        ld.UseDelayedAcceptance  = 0;

        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket, nullptr, nullptr, nullptr, &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_START_LISTEN)),
            &ld,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(ld))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );
        return NT_SUCCESS(status);
    }

    // ------------------------------------------------------------------
    // Return the local port assigned after Bind (host byte order).
    // Returns 0 on failure.
    // ------------------------------------------------------------------
    static __forceinline USHORT GetLocalPort(SyscallResolver* resolver, HANDLE socket) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return 0;

        BYTE out[64] = {};
        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket, nullptr, nullptr, nullptr, &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_GET_SOCK_NAME)),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),
            out,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(out)))
        );
        if (!NT_SUCCESS(status)) return 0;

        // Output is AfdSockAddrIn (SOCKADDR_IN) format on Win11 24H2:
        //   +0: Family (USHORT = 2)
        //   +2: Port   (USHORT, network byte order)  ← here
        //   +4: Address (ULONG)
        // (NOT TRANSPORT_ADDRESS which would put Port at +8)
        USHORT netPort = static_cast<USHORT>(out[2] | (static_cast<USHORT>(out[3]) << 8));
        return HostToNetPort(netPort); // byte-swap → host order
    }

    // ------------------------------------------------------------------
    // Block until a connection arrives on the listening socket.
    // Returns true and sets seqNum (needed for Accept) on success.
    // ------------------------------------------------------------------
    static __forceinline bool WaitForListen(SyscallResolver* resolver, HANDLE socket,
                                            ULONG& seqNum) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        AfdWaitForListenData wd = {};
        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            socket, nullptr, nullptr, nullptr, &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_WAIT_FOR_LISTEN)),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),
            &wd,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(wd)))
        );
        if (!NT_SUCCESS(status)) return false;
        seqNum = wd.SequenceNumber;
        return true;
    }

    // ------------------------------------------------------------------
    // Complete an accept.  acceptSocket is the new (pre-created) socket;
    // listenSocket + seqNum come from WaitForListen.
    // After this call acceptSocket is a fully connected peer socket.
    // ------------------------------------------------------------------
    static __forceinline bool Accept(SyscallResolver* resolver,
                                     HANDLE listenSocket, HANDLE acceptSocket,
                                     ULONG seqNum, NTSTATUS* outStatus = nullptr) {
        WORD  ssn;
        PVOID addr;
        if (!resolver->ResolveByName("NtDeviceIoControlFile", ssn, addr))
            return false;

        // Layout confirmed from WS2_32 capture on Win11 24H2:
        //   IOCTL sent to LISTEN socket (FileHandle = listenSocket)
        //   Input: { SanConnection=0, SequenceNumber, AcceptSocket }
        // The "ListenSocket" field in the struct actually holds the ACCEPT socket handle.
        AfdAcceptData ad = {};
        ad.SanConnection  = 0;
        ad.SequenceNumber = seqNum;
        ad.ListenSocket   = acceptSocket;   // ← accept socket handle goes in this field

        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = SyscallInvoker::Invoke(
            ssn,
            listenSocket,                                                            // IOCTL sent to listen socket
            nullptr, nullptr, nullptr, &ioStatus,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(IOCTL_AFD_ACCEPT)),
            &ad,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(ad))),
            nullptr,
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0))
        );
        if (outStatus) *outStatus = status;
        return NT_SUCCESS(status);
    }
};

#endif // WHIPSYSCALL_AFDSOCKET_H