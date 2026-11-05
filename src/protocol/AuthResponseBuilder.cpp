#include "AuthResponseBuilder.h"

#include <algorithm>
#include <stdexcept>

namespace AuthResponseBuilder
{
    namespace
    {
        // Primo N de SRP6 de World of Warcraft.
        //
        // Se transmite en little-endian.
        constexpr std::array<std::uint8_t, 32> SRP6_PRIME =
        {
            0xB7, 0x9B, 0xE3, 0x2A,
            0x72, 0x82, 0x3C, 0xAB,
            0x8F, 0x5E, 0xBF, 0xBF,
            0x8E, 0xB1, 0x01, 0x08,
            0x53, 0x50, 0x06, 0x29,
            0x8B, 0x5B, 0xAD, 0xBD,
            0x5B, 0x53, 0xE1, 0x89,
            0x5E, 0x64, 0x4B, 0x89
        };

        constexpr std::uint8_t SRP6_GENERATOR = 7;

        void AppendByte(
            std::vector<std::uint8_t>& packet,
            std::uint8_t value)
        {
            packet.push_back(value);
        }

        void AppendUInt16LE(
            std::vector<std::uint8_t>& packet,
            std::uint16_t value)
        {
            packet.push_back(
                static_cast<std::uint8_t>(value & 0xFF)
            );

            packet.push_back(
                static_cast<std::uint8_t>((value >> 8) & 0xFF)
            );
        }

        void AppendUInt32LE(
            std::vector<std::uint8_t>& packet,
            std::uint32_t value)
        {
            packet.push_back(
                static_cast<std::uint8_t>(value & 0xFF)
            );

            packet.push_back(
                static_cast<std::uint8_t>((value >> 8) & 0xFF)
            );

            packet.push_back(
                static_cast<std::uint8_t>((value >> 16) & 0xFF)
            );

            packet.push_back(
                static_cast<std::uint8_t>((value >> 24) & 0xFF)
            );
        }

        template <typename Container>
        void AppendFixed(
            std::vector<std::uint8_t>& packet,
            const Container& data,
            std::size_t expectedSize)
        {
            if (data.size() != expectedSize)
            {
                throw std::runtime_error(
                    "AuthResponseBuilder: longitud SRP6 incorrecta"
                );
            }

            packet.insert(
                packet.end(),
                data.begin(),
                data.end()
            );
        }
    }

    // ========================================================
    // LOGON_CHALLENGE SUCCESS
    // ========================================================

    std::vector<std::uint8_t> BuildLogonChallengeSuccess(
        const SRP6Server& srp,
        std::uint8_t securityFlags)
    {
        if (!srp.IsReady())
        {
            throw std::runtime_error(
                "SRP6 no esta preparado para crear el challenge"
            );
        }

        // En esta implementacion solo aceptamos las banderas
        // que tienen una estructura definida en el protocolo.
        if ((securityFlags & 0xF8) != 0)
        {
            throw std::invalid_argument(
                "AuthResponseBuilder: securityFlags desconocidas"
            );
        }

        // PIN y Matrix requieren campos adicionales.
        // No anunciarlos hasta implementar sus datos.
        if ((securityFlags & (SECURITY_FLAG_PIN |
                             SECURITY_FLAG_MATRIX)) != 0)
        {
            throw std::invalid_argument(
                "PIN y Matrix aun no estan implementados"
            );
        }

        const auto& B = srp.GetB();
        const auto& salt = srp.GetSalt();

        std::vector<std::uint8_t> packet;
        packet.reserve(119);

        // Estado de autenticacion: WOW_SUCCESS.
        AppendByte(
            packet,
            static_cast<std::uint8_t>(AuthResult::Success)
        );

        // Clave publica del servidor B: 32 bytes.
        AppendFixed(packet, B, 32);

        // Longitud del generador.
        AppendByte(packet, 1);

        // Generador g = 7.
        AppendByte(packet, SRP6_GENERATOR);

        // Longitud del primo N.
        AppendByte(packet, 32);

        // Primo N: 32 bytes little-endian.
        AppendFixed(packet, SRP6_PRIME, 32);

        // Salt: 32 bytes.
        AppendFixed(packet, salt, 32);

        // Version challenge: 16 bytes.
        AppendFixed(packet, VERSION_CHALLENGE, 16);

        // Banderas de seguridad.
        AppendByte(packet, securityFlags);

        return packet;
    }

    // ========================================================
    // LOGON_CHALLENGE FAILURE
    // ========================================================

    std::vector<std::uint8_t> BuildLogonChallengeFailure(
        AuthResult result)
    {
        std::vector<std::uint8_t> packet;
        packet.reserve(1);

        AppendByte(
            packet,
            static_cast<std::uint8_t>(result)
        );

        return packet;
    }

    // ========================================================
    // LOGON_PROOF SUCCESS
    // ========================================================

    std::vector<std::uint8_t> BuildLogonProofSuccess(
        std::span<const std::uint8_t, 20> serverM2,
        std::uint32_t accountFlags,
        std::uint32_t surveyId,
        std::uint16_t loginFlags)
    {
        std::vector<std::uint8_t> packet;
        packet.reserve(31);

        // Estado de autenticacion correcto.
        AppendByte(
            packet,
            static_cast<std::uint8_t>(AuthResult::Success)
        );

        // M2 del servidor: 20 bytes.
        packet.insert(
            packet.end(),
            serverM2.begin(),
            serverM2.end()
        );

        // Account flags.
        AppendUInt32LE(packet, accountFlags);

        // Survey ID.
        AppendUInt32LE(packet, surveyId);

        // Login flags.
        AppendUInt16LE(packet, loginFlags);

        return packet;
    }

    // ========================================================
    // LOGON_PROOF FAILURE
    // ========================================================

    std::vector<std::uint8_t> BuildLogonProofFailure(
        AuthResult result)
    {
        std::vector<std::uint8_t> packet;
        packet.reserve(1);

        AppendByte(
            packet,
            static_cast<std::uint8_t>(result)
        );

        return packet;
    }
}
