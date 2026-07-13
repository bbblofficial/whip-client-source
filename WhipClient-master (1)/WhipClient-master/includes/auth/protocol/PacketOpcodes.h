#pragma once

#include <whipnexus/Types.h>

namespace WhipOpcodes {

    constexpr u16 INIT_REQUEST           = 0x12;
    constexpr u16 INIT_RESPONSE          = 0x13;
    constexpr u16 PRODUCT_SELECT         = 0x14;
    constexpr u16 AUTH_RESPONSE          = 0x15;
    constexpr u16 CLIENT_AUTH            = 0x16;
    constexpr u16 CLIENT_AUTH_RESPONSE   = 0x17;
    constexpr u16 MACHINE_INFO           = 0x18;
    constexpr u16 MACHINE_INFO_RESPONSE  = 0x19;

    constexpr u16 SERVER_ATTESTATION_CHALLENGE = 0x1A;
    constexpr u16 CLIENT_ATTESTATION_RESPONSE  = 0x1B;

    constexpr u16 FILE_REQUEST           = 0x20;
    constexpr u16 FILE_RESPONSE          = 0x21;
    constexpr u16 KEYED_FILE_REQUEST     = 0x22;
    constexpr u16 KEYED_FILE_RESPONSE    = 0x23;
    constexpr u16 FILE_CHUNK_META        = 0x24;
    constexpr u16 FILE_CHUNK             = 0x25;

    constexpr u16 HEARTBEAT              = 0x30;
    constexpr u16 HEARTBEAT_ACK          = 0x31;

    constexpr u16 DISCONNECT             = 0x40;
    constexpr u16 SESSION_REVOKED        = 0x41;

    constexpr u16 LOADER_CONFIG          = 0x50;
    constexpr u16 LOADER_COMMAND         = 0x51;
    constexpr u16 LOADER_SHUTDOWN        = 0x52;

    constexpr u16 CLIENT_LOAD_START      = 0x60;
    constexpr u16 CLIENT_LOAD_AUTH       = 0x61;
    constexpr u16 CLIENT_LOAD_VERSIONS   = 0x62;
    constexpr u16 CLIENT_LOAD_MAPPINGS   = 0x63;
    constexpr u16 CLIENT_LOAD_HOOKS      = 0x64;
    constexpr u16 CLIENT_LOAD_COMPLETE   = 0x65;

    constexpr u16 CLIENT_HEARTBEAT       = 0x70;
    constexpr u16 CLIENT_STATUS          = 0x71;
    constexpr u16 CLIENT_DESTRUCT        = 0x72;

    constexpr u16 CONFIG_REQUEST         = 0x80;
    constexpr u16 CONFIG_RESPONSE        = 0x81;

    constexpr u16 REVERSE_DETECTED       = 0x90;

    constexpr u16 SESSION_CRASH          = 0x91;
}
