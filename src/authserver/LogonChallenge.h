#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct LogonChallenge
{
    std::array<uint8_t, 4> game;
    uint8_t versionMajor = 0;
    uint8_t versionMinor = 0;
    uint8_t versionPatch = 0;

    uint16_t build = 0;

    std::array<uint8_t, 4> platform;
    std::array<uint8_t, 4> operatingSystem;
    std::array<uint8_t, 4> country;

    uint32_t timezone = 0;
    uint32_t ip = 0;

    std::string username;
};

class LogonChallengeParser
{
public:
    static bool Parse(
        const std::vector<uint8_t>& data,
        LogonChallenge& result,
        std::string& error
    );
};
