
#pragma once

#include <cstdint>

namespace AuthOpcode
{
    constexpr uint8_t LOGON_CHALLENGE = 0x00;
    constexpr uint8_t LOGON_PROOF = 0x01;
    constexpr uint8_t RECONNECT_CHALLENGE = 0x02;
    constexpr uint8_t RECONNECT_PROOF = 0x03;
    constexpr uint8_t REALM_LIST = 0x10;
}

namespace AuthStatus
{
    constexpr uint8_t SUCCESS = 0x00;
    constexpr uint8_t FAIL_BANNED = 0x03;
    constexpr uint8_t FAIL_UNKNOWN_ACCOUNT = 0x04;
    constexpr uint8_t FAIL_INCORRECT_PASSWORD = 0x05;
    constexpr uint8_t FAIL_ALREADY_ONLINE = 0x06;
    constexpr uint8_t FAIL_NO_ACCESS = 0x09;
}
