#pragma once

#include "Types.h"

namespace ManualMapper
{
    struct LoaderParams
    {
        void* imageBase;
        void* dllMain;
    };

    class LoaderStub
    {
    public:
        static ByteArray GenerateStub();
        static size_t GetStubSize();
    };
}