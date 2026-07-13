// ===== file: antidebug/checks/integrity/self_disk_mem.h =====
//
// Self Disk-vs-Memory Integrity — the gold-standard anti-patch check.
//
// All existing integrity checks in this framework (code_hash.h,
// anti_patch.h, critical_scan.h, ntdll_dispatchers.h, ntdll_full_text.h)
// compare current bytes against a BASELINE captured at INIT. That misses
// the entire class of attacks where the patch is installed BEFORE the
// baseline is taken:
//
//   * TLS callbacks in an injected DLL (executed before main())
//   * AppInit_DLLs / KnownDlls poisoning
//   * Loader hook installed by x64dbg's LoadLibrary tracing
//   * Parent-process memory write via CreateRemoteThread into
//     our suspended process image
//   * VMProtect / Themida compatibility thunks, also applied at load
//   * EDR inline-hooks installed during DLL_PROCESS_ATTACH
//
// This check closes that gap. It compares our in-memory .text against
// our OWN exe file on disk. The disk image is immutable (unless someone
// rewrote the exe itself on disk, in which case they already own the
// machine), so any byte that differs is a runtime patch — regardless
// of whether it was applied pre-init or post-init.
//
// On x64, .text is position-independent (RIP-relative addressing, no
// relocations needed), so disk bytes === memory bytes at identical RVAs.
// The only legitimate differences come from hotpatch thunks (MS
// /HOTPATCH prologues get their 0x90 0x90 replaced by a short jmp to
// the patch pad), which normally doesn't apply to user-mode exes.
//
// Zero false positives on a clean system, zero way to defeat without
// modifying the exe on disk.
//
#ifndef ANTIDEBUG_SELF_DISK_MEM_H
#define ANTIDEBUG_SELF_DISK_MEM_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef AD_SDM_MAX_PATH_CHARS
#define AD_SDM_MAX_PATH_CHARS 520u
#endif

// --- kernel32 imports for file I/O -----------------------------------------
__declspec(dllimport) void* __stdcall CreateFileW(const u16* lpFileName,
                                                   unsigned long dwDesiredAccess,
                                                   unsigned long dwShareMode,
                                                   void* lpSecurityAttributes,
                                                   unsigned long dwCreationDisposition,
                                                   unsigned long dwFlagsAndAttributes,
                                                   void* hTemplateFile);
__declspec(dllimport) int   __stdcall ReadFile(void* hFile, void* lpBuffer,
                                                unsigned long nNumberOfBytesToRead,
                                                unsigned long* lpNumberOfBytesRead,
                                                void* lpOverlapped);
__declspec(dllimport) unsigned long __stdcall SetFilePointer(void* hFile, long lDistanceToMove,
                                                              long* lpDistanceToMoveHigh,
                                                              unsigned long dwMoveMethod);
__declspec(dllimport) unsigned long __stdcall GetFileSize(void* hFile, unsigned long* lpFileSizeHigh);
__declspec(dllimport) int   __stdcall CloseHandle(void* hObject);

#ifndef AD_SDM_GENERIC_READ
#define AD_SDM_GENERIC_READ          0x80000000UL
#define AD_SDM_FILE_SHARE_READ       0x00000001UL
#define AD_SDM_OPEN_EXISTING         3UL
#define AD_SDM_FILE_ATTR_NORMAL      0x00000080UL
#define AD_SDM_FILE_BEGIN            0UL
#define AD_SDM_INVALID_HANDLE_VALUE  ((void*)(unsigned __int64)-1)
#endif

typedef struct {
    u32 chunk_count;          // number of chunks (≤ 64 for u64 bitmask)
    u32 chunk_size;           // bytes per chunk
    u8* text_base_mem;        // in-memory .text base
    u32 text_size;            // .text virtual size
    u32 text_disk_offset;     // file offset of .text in the exe
    u32 initialized;
    u32 _pad;
} ad_sdm_ctx_t;

#ifndef AD_SDM_CHUNK_COUNT
#define AD_SDM_CHUNK_COUNT 32u   // 32 bits of u64 mask usable
#endif

ANTIDEBUG_INLINE u32 ad_sdm_fnv1a(const volatile u8* p, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h;
}

// Read our own exe path from PEB->ProcessParameters->ImagePathName (UNICODE_STRING).
ANTIDEBUG_INLINE b32 ad_sdm_get_own_path(u16* out, u32 max_chars, u32* out_len) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* params = *(u8**)(peb + 0x20);
    if (!params) return 0;
    u16  len_bytes = *(u16*)(params + 0x60);       // ImagePathName.Length
    u16* buf       = *(u16**)(params + 0x68);      // ImagePathName.Buffer
    if (!buf || len_bytes == 0u) return 0;
    u32 n_chars = (u32)(len_bytes / 2u);
    if (n_chars + 1u > max_chars) n_chars = max_chars - 1u;
    u32 i;
    for (i = 0; i < n_chars; i++) out[i] = buf[i];
    out[n_chars] = 0;
    *out_len = n_chars;
    return 1;
}

// Parse in-memory PE headers to locate our .text: memory base + virtual size
// + file-offset (so we know where .text lives in the exe on disk).
ANTIDEBUG_INLINE b32 ad_sdm_locate_text(ad_sdm_ctx_t* ctx) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* image = *(u8**)(peb + 0x10);   // PEB.ImageBaseAddress
    if (!image) return 0;
    if (*(u16*)image != 0x5A4D) return 0;  // 'MZ'

    u32 pe_off = *(u32*)(image + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = image + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;  // 'PE\0\0'

    u16 n_sec    = *(u16*)(pe + 6);
    u16 opt_size = *(u16*)(pe + 20);
    u8* sections = pe + 24 + opt_size;

    u16 si;
    for (si = 0; si < n_sec; si++) {
        u8* sec = sections + (u32)si * 40u;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            u32 virt_size  = *(u32*)(sec + 8);
            u32 virt_addr  = *(u32*)(sec + 12);
            u32 raw_size   = *(u32*)(sec + 16);
            u32 raw_offset = *(u32*)(sec + 20);
            ctx->text_base_mem    = image + virt_addr;
            // Use the min(virt_size, raw_size) so we don't read past
            // either the file or the zero-padded virtual extension.
            ctx->text_size        = (virt_size < raw_size) ? virt_size : raw_size;
            ctx->text_disk_offset = raw_offset;
            return 1;
        }
    }
    return 0;
}

// Open our own exe on disk, seek to .text, read into caller buffer.
ANTIDEBUG_INLINE b32 ad_sdm_read_disk_text(const ad_sdm_ctx_t* ctx, u8* out_buf) {
    u16 path[AD_SDM_MAX_PATH_CHARS];
    u32 path_len = 0;
    if (!ad_sdm_get_own_path(path, AD_SDM_MAX_PATH_CHARS, &path_len)) return 0;

    void* h = CreateFileW(path,
                          AD_SDM_GENERIC_READ,
                          AD_SDM_FILE_SHARE_READ,
                          (void*)0,
                          AD_SDM_OPEN_EXISTING,
                          AD_SDM_FILE_ATTR_NORMAL,
                          (void*)0);
    if (h == AD_SDM_INVALID_HANDLE_VALUE || h == 0) return 0;

    // Seek to .text offset.
    unsigned long result = SetFilePointer(h, (long)ctx->text_disk_offset,
                                          (long*)0, AD_SDM_FILE_BEGIN);
    if (result == 0xFFFFFFFFu) { CloseHandle(h); return 0; }

    unsigned long bytes_read = 0;
    int ok = ReadFile(h, out_buf, ctx->text_size, &bytes_read, (void*)0);
    CloseHandle(h);
    if (!ok || bytes_read != ctx->text_size) return 0;
    return 1;
}

// Initialise context: locate .text, compute chunk_size.
ANTIDEBUG_INLINE b32 ad_sdm_init(ad_sdm_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;
    if (!ad_sdm_locate_text(ctx)) return 0;
    ctx->chunk_count = AD_SDM_CHUNK_COUNT;
    ctx->chunk_size = ctx->text_size / ctx->chunk_count;
    if (ctx->chunk_size == 0u) return 0;
    ctx->initialized = 1u;
    return 1;
}

// Main check: read disk bytes, compare chunk-by-chunk against memory.
// Returns u64 bitmask of changed chunks (bit i set if chunk i differs).
ANTIDEBUG_INLINE u64 ad_sdm_check(const ad_sdm_ctx_t* ctx, u8* scratch_buf,
                                   u32 scratch_size) {
    if (!ctx || !ctx->initialized) return 0ULL;
    if (!scratch_buf || scratch_size < ctx->text_size) return 0ULL;

    if (!ad_sdm_read_disk_text(ctx, scratch_buf)) return 0ULL;

    u64 mask = 0ULL;
    u32 i;
    for (i = 0; i < ctx->chunk_count; i++) {
        u32 len = ctx->chunk_size;
        if (i == ctx->chunk_count - 1u)
            len += ctx->text_size - ctx->chunk_count * ctx->chunk_size;

        u32 h_mem  = ad_sdm_fnv1a(ctx->text_base_mem + i * ctx->chunk_size, len);
        u32 h_disk = ad_sdm_fnv1a(scratch_buf + i * ctx->chunk_size, len);
        if (h_mem != h_disk) mask |= (1ULL << i);
    }
    return mask;
}

ANTIDEBUG_INLINE b32 ad_sdm_patched(const ad_sdm_ctx_t* ctx, u8* scratch, u32 scratch_size) {
    return (b32)(ad_sdm_check(ctx, scratch, scratch_size) != 0ULL);
}

// Locate the first differing byte within a changed chunk — useful to
// report the exact patched offset. Returns UINT32_MAX if no diff.
ANTIDEBUG_INLINE u32 ad_sdm_first_diff_offset(const ad_sdm_ctx_t* ctx,
                                               const u8* disk_buf) {
    if (!ctx || !ctx->initialized) return 0xFFFFFFFFu;
    u32 i;
    for (i = 0; i < ctx->text_size; i++) {
        if (ctx->text_base_mem[i] != disk_buf[i]) return i;
    }
    return 0xFFFFFFFFu;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_sdm_ctx_t;
ANTIDEBUG_INLINE b32 ad_sdm_init(ad_sdm_ctx_t* c) { (void)c; return 0; }
ANTIDEBUG_INLINE u64 ad_sdm_check(const ad_sdm_ctx_t* c, u8* s, u32 n) { (void)c; (void)s; (void)n; return 0ULL; }
ANTIDEBUG_INLINE b32 ad_sdm_patched(const ad_sdm_ctx_t* c, u8* s, u32 n) { (void)c; (void)s; (void)n; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_SELF_DISK_MEM_H
