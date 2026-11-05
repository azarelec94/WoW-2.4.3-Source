#include "LogonChallenge.h"

#include <algorithm>
#include <cstddef>

namespace
{
    constexpr std::size_t MIN_BODY_SIZE = 30;
    constexpr std::size_t MAX_USERNAME_SIZE = 16;

    uint16_t ReadUInt16LE(const uint8_t* data)
    {
        return static_cast<uint16_t>(
            static_cast<uint16_t>(data[0]) |
            (static_cast<uint16_t>(data[1]) << 8)
        );
    }

    uint32_t ReadUInt32LE(const uint8_t* data)
    {
        return
            static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    bool IsValidUsername(const std::string& username)
    {
        if (username.empty() ||
            username.size() > MAX_USERNAME_SIZE)
        {
            return false;
        }

        for (unsigned char character : username)
        {
            // Aceptamos caracteres ASCII alfanuméricos
            // y guion bajo para el nombre de cuenta.
            const bool valid =
                (character >= 'A' && character <= 'Z') ||
                (character >= 'a' && character <= 'z') ||
                (character >= '0' && character <= '9') ||
                character == '_';

            if (!valid)
                return false;
        }

        return true;
    }
}

bool LogonChallengeParser::Parse(
    const std::vector<uint8_t>& data,
    LogonChallenge& result,
    std::string& error)
{
    error.clear();
    result = {};

    if (data.size() < MIN_BODY_SIZE)
    {
        error = "El paquete LOGON_CHALLENGE es demasiado corto.";
        return false;
    }

    if (data.size() > MIN_BODY_SIZE + MAX_USERNAME_SIZE)
    {
        error = "El paquete LOGON_CHALLENGE es demasiado grande.";
        return false;
    }

    std::size_t offset = 0;

    // Game name: bytes recibidos en orden de red.
    std::copy_n(
        data.begin() + offset,
        4,
        result.game.begin()
    );
    offset += 4;

    // Version: major, minor, patch.
    result.versionMajor = data[offset++];
    result.versionMinor = data[offset++];
    result.versionPatch = data[offset++];

    // Build: little-endian.
    result.build = ReadUInt16LE(&data[offset]);
    offset += 2;

    // Platform.
    std::copy_n(
        data.begin() + offset,
        4,
        result.platform.begin()
    );
    offset += 4;

    // Operating system.
    std::copy_n(
        data.begin() + offset,
        4,
        result.operatingSystem.begin()
    );
    offset += 4;

    // Country / locale.
    std::copy_n(
        data.begin() + offset,
        4,
        result.country.begin()
    );
    offset += 4;

    // Timezone bias.
    result.timezone = ReadUInt32LE(&data[offset]);
    offset += 4;

    // Client IP: conservar los cuatro bytes tal como llegan.
    // No convertirlo en una dirección de red aquí.
    result.ip = ReadUInt32LE(&data[offset]);
    offset += 4;

    // Username length.
    const uint8_t usernameLength = data[offset++];

    if (usernameLength == 0 ||
        usernameLength > MAX_USERNAME_SIZE)
    {
        error = "Longitud del nombre de cuenta inválida.";
        return false;
    }

    if (data.size() - offset != usernameLength)
    {
        error = "La longitud del nombre no coincide con el paquete.";
        return false;
    }

    result.username.assign(
        reinterpret_cast<const char*>(data.data() + offset),
        usernameLength
    );

    if (!IsValidUsername(result.username))
    {
        error = "El nombre de cuenta contiene caracteres inválidos.";
        return false;
    }

    // En el cable, el identificador de WoW está invertido.
    constexpr std::array<uint8_t, 4> EXPECTED_GAME{
        0x00, 'W', 'o', 'W'
    };

    if (result.game != EXPECTED_GAME)
    {
        error = "El identificador del juego no es WoW.";
        return false;
    }

    return true;
}
