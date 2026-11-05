
#include "AuthPacket.h"

#include <algorithm>

AuthPacketReader::AuthPacketReader(
    const std::vector<uint8_t>& data)
    : data_(data)
{
}

bool AuthPacketReader::ReadUInt8(uint8_t& value)
{
    if (Remaining() < 1)
        return false;

    value = data_[position_++];
    return true;
}

bool AuthPacketReader::ReadUInt16(uint16_t& value)
{
    if (Remaining() < 2)
        return false;

    value =
        static_cast<uint16_t>(data_[position_]) |
        (static_cast<uint16_t>(data_[position_ + 1]) << 8);

    position_ += 2;
    return true;
}

bool AuthPacketReader::ReadUInt32(uint32_t& value)
{
    if (Remaining() < 4)
        return false;

    value =
        static_cast<uint32_t>(data_[position_]) |
        (static_cast<uint32_t>(data_[position_ + 1]) << 8) |
        (static_cast<uint32_t>(data_[position_ + 2]) << 16) |
        (static_cast<uint32_t>(data_[position_ + 3]) << 24);

    position_ += 4;
    return true;
}

bool AuthPacketReader::ReadBytes(
    uint8_t* output,
    size_t length)
{
    if (Remaining() < length)
        return false;

    std::copy_n(
        data_.begin() + position_,
        length,
        output
    );

    position_ += length;
    return true;
}

bool AuthPacketReader::ReadString(
    std::string& value,
    size_t length)
{
    if (Remaining() < length)
        return false;

    value.assign(
        data_.begin() + position_,
        data_.begin() + position_ + length
    );

    position_ += length;
    return true;
}

size_t AuthPacketReader::Remaining() const
{
    return data_.size() - position_;
}
