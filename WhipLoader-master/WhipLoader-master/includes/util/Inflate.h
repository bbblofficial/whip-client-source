#pragma once

namespace whip {

// Self-contained typedefs — no <cstdint>, <stdint.h> or any other STL
// header pulled into the binary's import table. A reverser dumping
// loaded modules / strings won't see "std::" or libc++ markers from
// this TU.
using u8_t  = unsigned char;
using u16_t = unsigned short;
using u32_t = unsigned int;

/**
 * One-shot mem-to-mem decompressor for the wire format the server uses
 * for chunked file downloads (java.util.zip.Deflater output — that's a
 * RFC 1950 zlib stream wrapping RFC 1951 DEFLATE blocks).
 *
 * Intentionally a self-contained implementation rather than a vendored
 * lib: keeps every well-known marker (ZIP magic, "miniz" / "zlib"
 * string literals, the canonical Huffman tables tdef.c ships) out of
 * the binary, so an attacker scanning for a known compressor signature
 * has nothing to pivot on.
 *
 * Returns true on success and writes the decompressed length to
 * *outLen. False on any framing/checksum/overflow error — caller
 * should treat the destination buffer as undefined in that case.
 */
bool inflateZlib(const u8_t* src, u32_t srcLen,
                 u8_t* dst, u32_t dstCap,
                 u32_t* outLen);

} // namespace whip
