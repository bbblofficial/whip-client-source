// pe_harden.c — Post-build PE hardening tool
//
// Strips metadata that leaks information to reversers:
//   1. Rich header      → reveals MSVC version, tool chain, link counts
//   2. PE timestamp     → exact build date/time
//   3. Debug directory   → PDB path (full project directory structure)
//   4. Linker version   → minor MSVC version fingerprint
//
// Usage:  pe_harden.exe <target.exe>
//
// Run after cl/link, before distribution. Does NOT touch code or sections.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

#pragma pack(push, 1)
typedef struct {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
} COFF_HEADER;

typedef struct {
    u32 VirtualAddress;
    u32 Size;
} DATA_DIR;
#pragma pack(pop)

#define IMAGE_DIRECTORY_ENTRY_DEBUG 6

static int zero_region(u8* data, u32 offset, u32 size, u32 file_size) {
    if (offset + size > file_size) return 0;
    memset(data + offset, 0, size);
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: pe_harden <target.exe>\n");
        return 1;
    }

    // Read file
    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("[-] Cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    u32 file_size = (u32)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* data = (u8*)malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);

    if (data[0] != 'M' || data[1] != 'Z') {
        printf("[-] Not a PE file\n");
        free(data);
        return 1;
    }

    u32 e_lfanew = *(u32*)(data + 0x3C);
    if (e_lfanew + 4 > file_size || memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        printf("[-] Invalid PE signature\n");
        free(data);
        return 1;
    }

    COFF_HEADER* coff = (COFF_HEADER*)(data + e_lfanew + 4);
    u8* opt_hdr = (u8*)coff + sizeof(COFF_HEADER);
    int count = 0;

    // ── 1. Strip Rich header ──────────────────────────────────────────
    // Rich header sits between DOS stub and PE signature.
    // Format: ... [encrypted data] "Rich" [XOR key]
    u8* rich_ptr = NULL;
    for (u32 i = 0x40; i < e_lfanew - 4; i++) {
        if (memcmp(data + i, "Rich", 4) == 0) {
            rich_ptr = data + i;
            break;
        }
    }
    if (rich_ptr) {
        // Zero from end of DOS header (0x40) to PE signature
        u32 rich_region_start = 0x40;  // after minimal DOS stub
        u32 rich_region_size  = e_lfanew - rich_region_start;
        zero_region(data, rich_region_start, rich_region_size, file_size);
        printf("[+] Rich header stripped (%u bytes zeroed)\n", rich_region_size);
        count++;
    } else {
        printf("[*] Rich header: not found (already stripped?)\n");
    }

    // ── 2. Zero PE timestamp ──────────────────────────────────────────
    if (coff->TimeDateStamp != 0) {
        printf("[+] PE timestamp zeroed (was 0x%08X)\n", coff->TimeDateStamp);
        coff->TimeDateStamp = 0;
        count++;
    } else {
        printf("[*] PE timestamp: already zero\n");
    }

    // ── 3. Zero linker version ────────────────────────────────────────
    // OptionalHeader offset 2,3 = MajorLinkerVersion, MinorLinkerVersion
    if (opt_hdr[2] != 0 || opt_hdr[3] != 0) {
        printf("[+] Linker version zeroed (was %u.%u)\n", opt_hdr[2], opt_hdr[3]);
        opt_hdr[2] = 0;
        opt_hdr[3] = 0;
        count++;
    }

    // ── 4. Strip debug directory (PDB path) ───────────────────────────
    // Data directories start at offset 112 in PE32+ optional header
    u16 opt_magic = *(u16*)opt_hdr;
    u32 dd_offset;
    if (opt_magic == 0x20B)       // PE32+
        dd_offset = 112;
    else if (opt_magic == 0x10B)  // PE32
        dd_offset = 96;
    else {
        printf("[-] Unknown optional header magic 0x%04X\n", opt_magic);
        free(data);
        return 1;
    }

    u32 num_rva = *(u32*)(opt_hdr + dd_offset - 4);
    if (num_rva > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        DATA_DIR* dbg_dir = (DATA_DIR*)(opt_hdr + dd_offset + IMAGE_DIRECTORY_ENTRY_DEBUG * 8);

        if (dbg_dir->Size > 0 && dbg_dir->VirtualAddress > 0) {
            // Find the raw offset of the debug directory
            // Walk sections to convert RVA → file offset
            u8* sections = opt_hdr + coff->SizeOfOptionalHeader;
            u32 dbg_raw_off = 0;

            for (int i = 0; i < coff->NumberOfSections; i++) {
                u32 sec_vaddr = *(u32*)(sections + i * 40 + 12);
                u32 sec_vsize = *(u32*)(sections + i * 40 + 8);
                u32 sec_raddr = *(u32*)(sections + i * 40 + 20);

                if (dbg_dir->VirtualAddress >= sec_vaddr &&
                    dbg_dir->VirtualAddress < sec_vaddr + sec_vsize) {
                    dbg_raw_off = sec_raddr + (dbg_dir->VirtualAddress - sec_vaddr);
                    break;
                }
            }

            if (dbg_raw_off > 0 && dbg_raw_off + dbg_dir->Size <= file_size) {
                // Each debug directory entry is 28 bytes
                // Offset 24 = PointerToRawData (file offset of debug info)
                // Offset 20 = SizeOfData
                u32 num_entries = dbg_dir->Size / 28;
                for (u32 i = 0; i < num_entries; i++) {
                    u8* entry = data + dbg_raw_off + i * 28;
                    u32 type = *(u32*)(entry + 12);
                    u32 info_size = *(u32*)(entry + 16);
                    u32 info_off  = *(u32*)(entry + 24);

                    // Type 2 = IMAGE_DEBUG_TYPE_CODEVIEW (contains PDB path)
                    if (type == 2 && info_off > 0 && info_off + info_size <= file_size) {
                        // CodeView header: "RSDS" + GUID(16) + Age(4) + PDB path
                        if (info_size > 24 && memcmp(data + info_off, "RSDS", 4) == 0) {
                            // Zero the PDB path (starts at offset 24 in CodeView)
                            u32 path_off = info_off + 24;
                            u32 path_len = info_size - 24;
                            printf("[+] PDB path erased: \"%.*s\"\n",
                                   (int)(path_len - 1), data + path_off);
                            zero_region(data, path_off, path_len, file_size);
                            count++;
                        }
                    }

                    // Zero the debug directory entry timestamp too
                    *(u32*)(entry + 4) = 0;
                }

                // Zero the debug directory RVA/Size in the PE header
                dbg_dir->VirtualAddress = 0;
                dbg_dir->Size = 0;
                printf("[+] Debug directory entry zeroed\n");
                count++;
            }
        } else {
            printf("[*] Debug directory: empty\n");
        }
    }

    // ── Write hardened PE ─────────────────────────────────────────────
    if (count > 0) {
        f = fopen(argv[1], "wb");
        if (!f) { printf("[-] Cannot write %s\n", argv[1]); free(data); return 1; }
        fwrite(data, 1, file_size, f);
        fclose(f);
        printf("\n[+] %d modifications applied to %s\n", count, argv[1]);
    } else {
        printf("\n[*] No modifications needed\n");
    }

    free(data);
    return 0;
}
