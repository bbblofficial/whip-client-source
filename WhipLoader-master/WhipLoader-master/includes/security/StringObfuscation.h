#pragma once

#include <cstdint>
#include <cstddef>

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_mm_pause)
#endif

//
// Compile-Time String Obfuscation System
// Usage: OBFSTR("sensitive string")
// The string is XOR-encrypted at compile-time and auto-decrypts at runtime
//

namespace whip::security
{
    // Compile-time hash for __FILE__ string
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

    // Compile-time random seed - unique per instantiation
    // Uses __COUNTER__ (unique per use), __LINE__ (location), and __FILE__ hash
    template<uint32_t Counter, uint32_t Line, uint32_t FileH>
    constexpr uint32_t CompileTimeSeed()
    {
        // Combine multiple sources of entropy that can't be extracted from PE timestamp
        return ((Counter * 0x9e3779b9) ^ (Line * 0x517cc1b7) ^ (FileH * 0x27d4eb2d)) + 0x85ebca6b;
    }

    // Simple compile-time PRNG using linear congruential generator
    constexpr uint32_t CompileTimePRNG(uint32_t input)
    {
        return (input * 1103515245u + 12345u) & 0x7FFFFFFFu;
    }

    // Generate XOR key for a specific character position
    constexpr uint8_t GenerateXorKey(size_t index, uint32_t seed)
    {
        uint32_t key = seed;
        for (size_t i = 0; i <= index; ++i)
        {
            key = CompileTimePRNG(key);
        }
        return static_cast<uint8_t>(key & 0xFF);
    }

    // XOR encrypt a character at compile-time
    constexpr char EncryptChar(char c, size_t index, uint32_t seed)
    {
        return c ^ GenerateXorKey(index, seed);
    }

    // Encrypted string container
    template<size_t N, uint32_t Seed>
    class ObfuscatedString
    {
    private:
        mutable char data_[N + 1];
        mutable volatile long decrypted_;  // 0 = encrypted, 1 = decrypted (atomic via interlocked ops)

    public:
        // Constructor: stores encrypted string
        constexpr ObfuscatedString(const char* str)
            : data_{}, decrypted_(0)
        {
            for (size_t i = 0; i < N; ++i)
            {
                data_[i] = EncryptChar(str[i], i, Seed);
            }
            data_[N] = '\0';
        }

        // Decrypt and return plain string (thread-safe using interlocked operations)
        const char* decrypt() const
        {
            // Thread-safe compare-and-swap: if decrypted_ == 0, set to 1 and return 0
            // Only one thread will win this race
            if (_InterlockedCompareExchange(&decrypted_, 1, 0) == 0)
            {
                // We won the race - perform decryption
                for (size_t i = 0; i < N; ++i)
                {
                    data_[i] ^= GenerateXorKey(i, Seed);
                }
                // Memory barrier to ensure decryption is visible to other threads
                _ReadWriteBarrier();
            }
            else
            {
                // Another thread is decrypting or already decrypted
                // Spin-wait until decryption is complete
                while (decrypted_ == 0)
                {
                    _mm_pause();  // CPU hint to reduce power consumption during spin-wait
                }
            }
            return data_;
        }

        // Auto-conversion to const char*
        operator const char*() const
        {
            return decrypt();
        }

        // Get length
        constexpr size_t length() const
        {
            return N;
        }
    };

    // Helper to create obfuscated string with automatic length deduction
    // Each instantiation gets a unique seed based on counter, line, and file
    template<size_t N, uint32_t Counter = __COUNTER__, uint32_t Line = __LINE__, uint32_t FileH = FileHash(__FILE__)>
    constexpr auto MakeObfuscatedString(const char(&str)[N])
    {
        return ObfuscatedString<N - 1, CompileTimeSeed<Counter, Line, FileH>()>(str);
    }
}

// Main macro for obfuscating strings
#define OBFSTR(str) (whip::security::MakeObfuscatedString(str).decrypt())

// Alternative macro that returns the ObfuscatedString object
#define OBFSTR_OBJ(str) (whip::security::MakeObfuscatedString(str))
