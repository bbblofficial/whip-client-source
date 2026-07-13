#pragma once

namespace whip {

using u8_t  = unsigned char;
using u16_t = unsigned short;
using u32_t = unsigned int;

bool inflateZlib(const u8_t* src, u32_t srcLen,
                 u8_t* dst, u32_t dstCap,
                 u32_t* outLen);

}
