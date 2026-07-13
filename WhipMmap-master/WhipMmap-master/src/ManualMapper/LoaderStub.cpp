#include "ManualMapper/LoaderStub.h"

namespace ManualMapper
{
    ByteArray LoaderStub::GenerateStub()
    {
        ByteArray stub = {
            0x53,                                           // push rbx
            0x48, 0x89, 0xCB,                               // mov rbx, rcx
            0x48, 0x8B, 0x0B,                               // mov rcx, [rbx] (imageBase)
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,       // mov rdx, 1 (DLL_PROCESS_ATTACH)
            0x4D, 0x31, 0xC0,                               // xor r8, r8 (lpReserved = NULL)
            0x48, 0x8B, 0x43, 0x08,                         // mov rax, [rbx+8] (dllMain address)
            0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 32 (shadow space)
            0xFF, 0xD0,                                     // call rax
            0x48, 0x83, 0xC4, 0x20,                         // add rsp, 32
            0x5B,                                           // pop rbx
            0xC3                                            // ret
        };

        return stub;
    }

    size_t LoaderStub::GetStubSize()
    {
        return GenerateStub().size();
    }
}