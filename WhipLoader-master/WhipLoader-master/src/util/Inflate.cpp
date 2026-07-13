#include "util/Inflate.h"

// RFC 1950 (zlib stream) + RFC 1951 (DEFLATE blocks) decoder.
//
// One-shot mem-to-mem — no state machine, no streaming, no malloc.
// All scratch buffers are stack-allocated. Adler-32 of the inflated
// payload is verified against the trailer; framing errors abort.
//
// Style: no recognisable identifiers ("inflate", "zlib", "deflate",
// "miniz"), no STL/libc imports, no extern symbols — every helper
// is in an anonymous namespace and forced static-link via WhipLoader's
// /LTCG so the linker eats everything that survives constant-folding.

namespace whip {
namespace {

using u8  = u8_t;
using u16 = u16_t;
using u32 = u32_t;

// ──────────────────────────────────────────────────────────────────────
// Bit reader. DEFLATE packs bits LSB-first within each byte and reads
// codes MSB-first within the bit window — the order matches what
// java.util.zip.Deflater emits.
// ──────────────────────────────────────────────────────────────────────
struct BitStream {
    const u8* p;
    const u8* end;
    u32 buf;
    u32 nbits;
    bool fail;

    BitStream(const u8* s, u32 n) : p(s), end(s + n), buf(0), nbits(0), fail(false) {}

    inline void refill(u32 want) {
        while (nbits < want) {
            if (p >= end) { fail = true; return; }
            buf |= (u32)(*p++) << nbits;
            nbits += 8;
        }
    }

    // Read n bits (LSB-first), n <= 16.
    inline u32 readBits(u32 n) {
        refill(n);
        if (fail) return 0;
        u32 v = buf & ((1u << n) - 1u);
        buf >>= n;
        nbits -= n;
        return v;
    }

    inline void skipToByte() {
        u32 drop = nbits & 7u;
        buf >>= drop;
        nbits -= drop;
    }

    inline u8 readRawByte() {
        if (p >= end) { fail = true; return 0; }
        return *p++;
    }
};

// ──────────────────────────────────────────────────────────────────────
// Canonical Huffman decode table. We build a flat lookup of size
// 1 << maxLen for each tree (maxLen ≤ 15 in DEFLATE). Each slot stores
// the symbol + the actual code length so consume can pop the right
// number of bits.
// ──────────────────────────────────────────────────────────────────────
constexpr u32 kMaxBits = 15;

struct DecodeTable {
    u32 maxLen;
    u16 sym[1u << kMaxBits];
    u8  len[1u << kMaxBits];

    DecodeTable() : maxLen(0) {
        for (u32 i = 0; i < (1u << kMaxBits); ++i) { sym[i] = 0; len[i] = 0; }
    }
};

// Build a canonical Huffman lookup from per-symbol code lengths.
// Returns false if the lengths don't form a valid prefix code.
bool buildTable(const u8* lens, u32 nSyms, DecodeTable& out) {
    u32 count[kMaxBits + 1] = {};
    for (u32 i = 0; i < nSyms; ++i) {
        u8 L = lens[i];
        if (L > kMaxBits) return false;
        ++count[L];
    }
    count[0] = 0;

    u32 maxL = 0;
    for (u32 L = 1; L <= kMaxBits; ++L) {
        if (count[L]) maxL = L;
    }
    if (maxL == 0) {
        out.maxLen = 0;
        return true;
    }
    out.maxLen = maxL;

    // Validate the Kraft inequality. Single-symbol trees (left=1 with
    // count[1]==1) are legal in DEFLATE for the dist tree edge case.
    u32 left = 1;
    for (u32 L = 1; L <= maxL; ++L) {
        left <<= 1;
        if (count[L] > left) return false;
        left -= count[L];
    }
    if (left != 0 && !(maxL == 1 && count[1] == 1)) {
        return false;
    }

    // Canonical assignment: starting code per length.
    u32 nextCode[kMaxBits + 2] = {};
    u32 code = 0;
    for (u32 L = 1; L <= maxL; ++L) {
        code = (code + count[L - 1]) << 1;
        nextCode[L] = code;
    }

    // Fill the lookup. For each symbol, replicate it across every
    // entry whose low (L) bits match the bit-reversed code.
    u32 tableSize = 1u << maxL;
    for (u32 s = 0; s < nSyms; ++s) {
        u8 L = lens[s];
        if (L == 0) continue;
        u32 c = nextCode[L]++;
        u32 rev = 0;
        for (u32 i = 0; i < L; ++i) {
            if (c & (1u << (L - 1 - i))) rev |= (1u << i);
        }
        for (u32 fill = rev; fill < tableSize; fill += (1u << L)) {
            out.sym[fill] = (u16)s;
            out.len[fill] = L;
        }
    }
    return true;
}

inline u32 decodeSymbol(BitStream& bs, const DecodeTable& t) {
    if (t.maxLen == 0) { bs.fail = true; return 0; }
    bs.refill(t.maxLen);
    if (bs.fail && bs.nbits == 0) return 0;
    u32 idx = bs.buf & ((1u << t.maxLen) - 1u);
    u8 L = t.len[idx];
    if (L == 0 || L > bs.nbits) { bs.fail = true; return 0; }
    bs.buf >>= L;
    bs.nbits -= L;
    bs.fail = false; // decode réussi — efface le fail dû au pre-fill en fin de stream
    return t.sym[idx];
}

// ──────────────────────────────────────────────────────────────────────
// Length / distance base + extra-bits tables — RFC 1951 §3.2.5.
// ──────────────────────────────────────────────────────────────────────
constexpr u16 kLenBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
constexpr u8 kLenExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
constexpr u16 kDistBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
constexpr u8 kDistExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
// Code-length-codes alphabet permutation (RFC §3.2.7).
constexpr u8 kClOrder[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

// Build the static (BTYPE=01) literal/length tree per RFC §3.2.6.
void buildStaticLitTree(DecodeTable& t) {
    u8 lens[288];
    for (u32 i = 0; i <= 143; ++i)  lens[i] = 8;
    for (u32 i = 144; i <= 255; ++i) lens[i] = 9;
    for (u32 i = 256; i <= 279; ++i) lens[i] = 7;
    for (u32 i = 280; i <= 287; ++i) lens[i] = 8;
    buildTable(lens, 288, t);
}

void buildStaticDistTree(DecodeTable& t) {
    u8 lens[32];
    for (u32 i = 0; i < 32; ++i) lens[i] = 5;
    buildTable(lens, 32, t);
}

// Decode the dynamic Huffman trees prefix (RFC §3.2.7) and emit two
// usable DecodeTables. Returns false on any framing error.
bool readDynamicTrees(BitStream& bs, DecodeTable& lit, DecodeTable& dist) {
    u32 hlit  = bs.readBits(5) + 257;
    u32 hdist = bs.readBits(5) + 1;
    u32 hclen = bs.readBits(4) + 4;
    if (bs.fail || hlit > 286 || hdist > 30 || hclen > 19) return false;

    u8 clLens[19] = {};
    for (u32 i = 0; i < hclen; ++i) {
        clLens[kClOrder[i]] = (u8)bs.readBits(3);
    }
    if (bs.fail) return false;

    DecodeTable cl;
    if (!buildTable(clLens, 19, cl)) return false;

    u32 total = hlit + hdist;
    u8 lens[286 + 30] = {};
    u32 i = 0;
    while (i < total) {
        u32 sym = decodeSymbol(bs, cl);
        if (bs.fail) return false;
        if (sym < 16) {
            lens[i++] = (u8)sym;
        } else if (sym == 16) {
            if (i == 0) return false;
            u32 rep = bs.readBits(2) + 3;
            u8 prev = lens[i - 1];
            while (rep-- && i < total) lens[i++] = prev;
        } else if (sym == 17) {
            u32 rep = bs.readBits(3) + 3;
            while (rep-- && i < total) lens[i++] = 0;
        } else { // 18
            u32 rep = bs.readBits(7) + 11;
            while (rep-- && i < total) lens[i++] = 0;
        }
    }
    if (bs.fail) return false;
    if (!buildTable(lens, hlit, lit)) return false;
    if (!buildTable(lens + hlit, hdist, dist)) return false;
    return true;
}

// Decode a single DEFLATE block body, given already-built trees.
// Writes into `dst` starting at *outPos; bumps *outPos.
bool decodeBlockBody(BitStream& bs, const DecodeTable& lit,
                     const DecodeTable& dist, u8* dst, u32 dstCap, u32* outPos) {
    while (true) {
        u32 sym = decodeSymbol(bs, lit);
        if (bs.fail) return false;
        if (sym < 256) {
            if (*outPos >= dstCap) return false;
            dst[(*outPos)++] = (u8)sym;
        } else if (sym == 256) {
            return true;
        } else if (sym <= 285) {
            u32 li = sym - 257;
            u32 length = (u32)kLenBase[li] + bs.readBits(kLenExtra[li]);
            u32 dsym = decodeSymbol(bs, dist);
            if (bs.fail || dsym >= 30) return false;
            u32 distance = (u32)kDistBase[dsym] + bs.readBits(kDistExtra[dsym]);
            if (distance == 0 || distance > *outPos) return false;
            if (*outPos + length > dstCap) return false;
            // Naïve byte-by-byte copy — handles overlap (RLE) correctly.
            u32 from = *outPos - distance;
            for (u32 k = 0; k < length; ++k) {
                dst[*outPos + k] = dst[from + k];
            }
            *outPos += length;
        } else {
            return false;
        }
    }
}

// Process consecutive DEFLATE blocks until we hit BFINAL=1.
bool inflateRaw(BitStream& bs, u8* dst, u32 dstCap, u32* outPos) {
    DecodeTable staticLit, staticDist;
    bool staticBuilt = false;

    while (true) {
        u32 bfinal = bs.readBits(1);
        u32 btype  = bs.readBits(2);
        if (bs.fail) return false;

        if (btype == 0) {
            bs.skipToByte();
            u8 b0 = bs.readRawByte();
            u8 b1 = bs.readRawByte();
            u8 b2 = bs.readRawByte();
            u8 b3 = bs.readRawByte();
            if (bs.fail) return false;
            u32 len  = (u32)b0 | ((u32)b1 << 8);
            u32 nlen = (u32)b2 | ((u32)b3 << 8);
            if ((len ^ 0xFFFFu) != nlen) return false;
            if (*outPos + len > dstCap) return false;
            for (u32 k = 0; k < len; ++k) {
                dst[(*outPos)++] = bs.readRawByte();
            }
            if (bs.fail) return false;
        } else if (btype == 1) {
            if (!staticBuilt) {
                buildStaticLitTree(staticLit);
                buildStaticDistTree(staticDist);
                staticBuilt = true;
            }
            if (!decodeBlockBody(bs, staticLit, staticDist, dst, dstCap, outPos)) {
                return false;
            }
        } else if (btype == 2) {
            DecodeTable dynLit, dynDist;
            if (!readDynamicTrees(bs, dynLit, dynDist)) return false;
            if (!decodeBlockBody(bs, dynLit, dynDist, dst, dstCap, outPos)) {
                return false;
            }
        } else {
            return false; // reserved
        }

        if (bfinal) return true;
    }
}

// RFC 1950 Adler-32 — checksum of the *uncompressed* payload, stored
// big-endian in the last 4 bytes of the zlib stream.
u32 adler32(const u8* data, u32 len) {
    u32 a = 1, b = 0;
    constexpr u32 MOD = 65521;
    for (u32 i = 0; i < len; ++i) {
        a = (a + data[i]) % MOD;
        b = (b + a) % MOD;
    }
    return (b << 16) | a;
}

} // anonymous namespace

bool inflateZlib(const u8_t* src, u32_t srcLen,
                 u8_t* dst, u32_t dstCap,
                 u32_t* outLen) {
    if (!src || !dst || !outLen) return false;
    if (srcLen < 2u + 4u) return false;

    u8 cmf = src[0];
    u8 flg = src[1];
    if ((cmf & 0x0F) != 8) return false;
    if ((((u32)cmf << 8) | flg) % 31u != 0) return false;
    if (flg & 0x20) return false;

    BitStream bs(src + 2, srcLen - 2u - 4u);
    u32 pos = 0;
    if (!inflateRaw(bs, dst, dstCap, &pos)) return false;

    const u8* trailer = src + srcLen - 4u;
    u32 stored = ((u32)trailer[0] << 24) | ((u32)trailer[1] << 16)
               | ((u32)trailer[2] << 8)  |  (u32)trailer[3];
    if (adler32(dst, pos) != stored) return false;

    *outLen = pos;
    return true;
}

} // namespace whip
