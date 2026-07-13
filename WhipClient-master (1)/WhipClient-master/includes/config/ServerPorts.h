#pragma once

namespace whip {

#ifdef WHIP_PRODUCTION

    constexpr uint16_t DEFAULT_SERVER_PORT = 7777;
#else

    constexpr uint16_t DEFAULT_SERVER_PORT = 7778;
#endif

}
