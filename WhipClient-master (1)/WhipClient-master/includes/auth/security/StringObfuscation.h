#pragma once

#include <cstdint>
#include <cstddef>

namespace auth::security
{

    constexpr uint32_t HashString(const char* str, size_t len, uint32_t hash = 0x811c9dc5)
    {
        return len == 0 ? hash : HashString(str + 1, len - 1, (hash ^ static_cast<uint32_t>(*str)) * 0x01000193);
    }

    constexpr uint32_t FileHash(const char* file)
    {
        size_t len = 0;
        while (file[len]) ++len;
        return HashString(file, len);
    }

    template<uint32_t Counter, uint32_t Line, uint32_t FileH>
    constexpr uint32_t CompileTimeSeed()
    {

        return ((Counter * 0x9e3779b9) ^ (Line * 0x517cc1b7) ^ (FileH * 0x27d4eb2d)) + 0x85ebca6b;
    }

    constexpr uint32_t CompileTimePRNG(uint32_t input)
    {
        return (input * 1103515245u + 12345u) & 0x7FFFFFFFu;
    }

    constexpr uint8_t GenerateXorKey(size_t index, uint32_t seed)
    {
        uint32_t key = seed;
        for (size_t i = 0; i <= index; ++i)
        {
            key = CompileTimePRNG(key);
        }
        return static_cast<uint8_t>(key & 0xFF);
    }

    constexpr char EncryptChar(char c, size_t index, uint32_t seed)
    {
        return c ^ GenerateXorKey(index, seed);
    }

    template<size_t N, uint32_t Seed>
    class ObfuscatedString
    {
    private:
        mutable char data_[N + 1];
        mutable bool decrypted_;

    public:

        constexpr ObfuscatedString(const char* str)
            : data_{}, decrypted_(false)
        {
            for (size_t i = 0; i < N; ++i)
            {
                data_[i] = EncryptChar(str[i], i, Seed);
            }
            data_[N] = '\0';
        }

        const char* decrypt() const
        {
            if (!decrypted_)
            {
                for (size_t i = 0; i < N; ++i)
                {
                    data_[i] ^= GenerateXorKey(i, Seed);
                }
                decrypted_ = true;
            }
            return data_;
        }

        operator const char*() const
        {
            return decrypt();
        }

        constexpr size_t length() const
        {
            return N;
        }
    };

    template<size_t N, uint32_t Counter = __COUNTER__, uint32_t Line = __LINE__, uint32_t FileH = FileHash(__FILE__)>
    constexpr auto MakeObfuscatedString(const char(&str)[N])
    {
        return ObfuscatedString<N - 1, CompileTimeSeed<Counter, Line, FileH>()>(str);
    }
}

#define OBFSTR(str) (auth::security::MakeObfuscatedString(str).decrypt())

#define OBFSTR_OBJ(str) (auth::security::MakeObfuscatedString(str))
