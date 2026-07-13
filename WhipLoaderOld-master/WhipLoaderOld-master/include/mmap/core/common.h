#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <memory>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <thread>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#ifdef _WIN64
#define ARCH_X64
#else
#define ARCH_X86
#endif

#ifndef ViewUnmap
#define ViewUnmap 1
#endif

#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

enum class ErrorCode : uint32_t {
    SUCCESS = 0,
    UNKNOWN_ERROR = 1,
    INVALID_PARAMETER = 2,
    NOT_IMPLEMENTED = 3,
    OPERATION_ABORTED = 4,

    PROCESS_NOT_FOUND = 100,
    PROCESS_ACCESS_DENIED = 101,
    PROCESS_ARCHITECTURE_MISMATCH = 102,
    ARCHITECTURE_MISMATCH = 102,
    PROCESS_INJECTION_LIMIT_REACHED = 103,

    MEMORY_ALLOCATION_FAILED = 200,
    MEMORY_WRITE_FAILED = 201,
    MEMORY_PROTECTION_FAILED = 202,
    MEMORY_PROTECT_FAILED = 202,
    INVALID_ADDRESS = 203,

    THREAD_CREATION_FAILED = 300,
    THREAD_HIJACK_FAILED = 301,
    THREAD_NOT_FOUND = 302,
    THREAD_CONTEXT_FAILED = 303,
    THREAD_EXECUTION_FAILED = 304,
    THREAD_SUSPEND_FAILED = 305,
    THREAD_RESUME_FAILED = 306,

    PE_PARSE_FAILED = 400,
    PE_INVALID_HEADER = 401,
    PE_SECTION_TABLE_CORRUPT = 402,
    PE_CHECKSUM_MISMATCH = 403,
    PE_UNSUPPORTED_TYPE = 404,

    DLLMAIN_FAILED = 500,
    SHELLCODE_CREATION_FAILED = 501,
    SHELLCODE_INJECTION_FAILED = 502,
    INJECTION_DETECTED = 503,
    INJECTION_NOT_SUPPORTED = 504,

    IMPORT_RESOLUTION_FAILED = 600,
    EXPORT_RESOLUTION_FAILED = 601,
    DELAY_IMPORT_FAILED = 602,
    BOUND_IMPORT_FAILED = 603,
    FUNCTION_NOT_FOUND = 604,

    RELOCATION_FAILED = 700,
    RELOCATION_NOT_FOUND = 701,
    RELOCATION_TYPE_UNSUPPORTED = 702,
    RELOCATION_DELTA_TOO_LARGE = 703,

    ACCESS_DENIED = 800,
    INTEGRITY_CHECK_FAILED = 801,
    ANTIVIRUS_BLOCK = 802,
    CFG_VIOLATION = 803,
    DEP_VIOLATION = 804,

    FILE_NOT_FOUND = 900,
    FILE_ACCESS_DENIED = 901,
    FILE_INVALID = 902,
    FILE_MAPPING_FAILED = 903,
    DRIVE_NOT_READY = 904,

    TIMEOUT = 1000,
    TIMEOUT_CONNECTION = 1001,
    TIMEOUT_RESPONSE = 1002,

    MODULE_NOT_FOUND = 1100,
    MODULE_NOT_LOADED = 1101,
    MODULE_LOAD_FAILED = 1102,

    SYSCALL_FAILED = 1200,
    SYSCALL_HOOK_DETECTED = 1201,
    SYSCALL_NUMBER_NOT_FOUND = 1202,

    SECTION_CREATION_FAILED = 1300,
    SECTION_PROTECTION_FAILED = 1301,
    SECTION_NOT_FOUND = 1302,

    DEBUGGER_PRESENT = 1400,
    DEBUG_REGISTER_FAILED = 1401,
    BREAKPOINT_SET_FAILED = 1402,

    CPU_FEATURE_MISSING = 1500,
    PAGE_FAULT = 1501,
    ILLEGAL_INSTRUCTION = 1502,

    INJECTION_CONTEXT_INVALID = 1600,
    INJECTION_ABORTED = 1601,
    INJECTION_PARTIAL = 1602,

    NETWORK_UNAVAILABLE = 1700,
    CONNECTION_REFUSED = 1701,
    PROTOCOL_ERROR = 1702,

    CONFIG_INVALID = 1800,
    CONFIG_MISSING = 1801,

    DRIVER_NOT_LOADED = 1900,
    DRIVER_ACCESS_DENIED = 1901,
    IOCTL_FAILED = 1902,

    SIGNATURE_INVALID = 2000,
    HASH_MISMATCH = 2001,
    DECRYPTION_FAILED = 2002,

    EXECUTION_FAILED = 2100,
    EXECUTION_INVALID_CONTEXT = 2101,
    EXECUTION_PRIVILEGE_VIOLATION = 2102,
    EXECUTION_BAD_INSTRUCTION = 2103,
    EXECUTION_STACK_OVERFLOW = 2104,
    EXECUTION_ACCESS_VIOLATION = 2105,
    EXECUTION_ILLEGAL_STATE = 2106,
    EXECUTION_HOOK_DETECTED = 2107,
    EXECUTION_GUARD_PAGE = 2108,
    EXECUTION_DEP_VIOLATION = 2109,
    EXECUTION_SYSCALL_FAILED = 2110,
    EXECUTION_ENTRYPOINT_FAILED = 2111,
    EXECUTION_CALLBACK_FAILED = 2112,
    EXECUTION_TLS_FAILURE = 2113,
    EXECUTION_SEH_FAILURE = 2114,
    EXECUTION_DEBUG_BREAK = 2115,
    EXECUTION_STACK_CORRUPTION = 2116,
    EXECUTION_HEAP_CORRUPTION = 2117,
    EXECUTION_INVALID_LOCK = 2118,
    EXECUTION_APC_FAILED = 2119,
    EXECUTION_FIBER_FAILED = 2120,
    EXECUTION_VEH_FAILED = 2121,
    EXECUTION_INVALID_HANDLE = 2122,
};

struct ErrorInfo {
    ErrorCode code;
    std::string message;
    DWORD lastWinError;
};

class ProcessInterface;
class MemoryManager;
class SyscallManager;
class NameRandomizer;
class ErrorHandler;
class PEParser;
class TlsCallback;
class RemoteVEHRelocator;
class StaticTlsResolver;
class ManualMapper;
class ImportResolver;
class ExecutionEngine;

using ProcessId = DWORD;
using ThreadId = DWORD;
using ProcessHandle = HANDLE;
using ThreadHandle = HANDLE;
using MemoryAddress = PVOID;
using MemorySize = SIZE_T;
using SectionHandle = HANDLE;

class InjectorController {
public:
    InjectorController();

    ~InjectorController();

    bool Initialize();

    bool InjectDll(const std::string &dllPath, const std::string &processName);

    bool UnloadInjectedDll();

    [[nodiscard]] std::string GetLastErrorMessage() const;

private:
    ErrorHandler *m_errorHandler;
    NameRandomizer *m_nameRandomizer;
    ProcessInterface *m_processInterface;
    SyscallManager *m_syscallManager;
    MemoryManager *m_memoryManager;
    PEParser *m_peParser;
    TlsCallback *m_tlsCallback;
    RemoteVEHRelocator *m_remoteVEHrelocator;
    ManualMapper *m_manualMapper;
    ExecutionEngine *m_executionEngine;
    StaticTlsResolver *m_staticTlsResolver;

    void CleanupResources();
};

constexpr size_t MAX_PATH_LENGTH = 260;
constexpr size_t MIN_RANDOM_NAME_LENGTH = 8;
constexpr size_t MAX_RANDOM_NAME_LENGTH = 16;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace Utils {
    std::wstring StringToWideString(const std::string &str);

    std::string WideStringToString(const std::wstring &wstr);

    uint32_t GetRandomNumber(uint32_t min, uint32_t max);

    void RandomSleep(uint32_t minMs, uint32_t maxMs);

    bool IsProcess64Bit(ProcessHandle hProcess);

    void SecureZeroMemory(void *ptr, size_t size);
}
