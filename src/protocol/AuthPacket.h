
#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

class AuthPacketReader
{
public:
    explicit AuthPacketReader(
        const std::vector<uint8_t>& data);

    bool ReadUInt8(uint8_t& value);
    bool ReadUInt16(uint16_t& value);
    bool ReadUInt32(uint32_t& value);

    bool ReadBytes(
        uint8_t* output,
        size_t length);

    bool ReadString(
        std::string& value,
        size_t length);

    size_t Remaining() const;

private:
    const std::vector<uint8_t>& data_;
    size_t position_ = 0;
};
