#pragma once

#include "crypto/SRP6Server.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace AuthResponseBuilder
{
    // Estados de respuesta del protocolo de autenticacion.
    enum class AuthResult : std::uint8_t
    {
        Success             = 0x00,
        FailUnknownAccount  = 0x04,
        FailIncorrectPassword = 0x05,
        FailVersionInvalid  = 0x09,
        FailDbBusy          = 0x10
    };

    // Desafio de version utilizado por el protocolo WoW.
    inline constexpr std::array<std::uint8_t, 16> VERSION_CHALLENGE =
    {
        0xBA, 0xA3, 0x1E, 0x99,
        0xA0, 0x0B, 0x21, 0x57,
        0xFC, 0x37, 0x3F, 0xB3,
        0x69, 0xCD, 0xD2, 0xF1
    };

    // Banderas de seguridad.
    inline constexpr std::uint8_t SECURITY_FLAG_NONE = 0x00;
    inline constexpr std::uint8_t SECURITY_FLAG_PIN = 0x01;
    inline constexpr std::uint8_t SECURITY_FLAG_MATRIX = 0x02;
    inline constexpr std::uint8_t SECURITY_FLAG_TOKEN = 0x04;

    // Respuesta correcta a LOGON_CHALLENGE.
    //
    // Incluye:
    // status
    // B[32]
    // g_length
    // g
    // N_length
    // N[32]
    // salt[32]
    // version_challenge[16]
    // security_flags
    //
    // No incluye un opcode adicional.
    std::vector<std::uint8_t> BuildLogonChallengeSuccess(
        const SRP6Server& srp,
        std::uint8_t securityFlags = SECURITY_FLAG_NONE
    );

    // Respuesta de error a LOGON_CHALLENGE.
    std::vector<std::uint8_t> BuildLogonChallengeFailure(
        AuthResult result
    );

    // Respuesta correcta a LOGON_PROOF.
    //
    // serverM2 debe contener los 20 bytes calculados por SRP6.
    // accountFlags, surveyId y loginFlags son campos del protocolo.
    std::vector<std::uint8_t> BuildLogonProofSuccess(
        std::span<const std::uint8_t, 20> serverM2,
        std::uint32_t accountFlags = 0,
        std::uint32_t surveyId = 0,
        std::uint16_t loginFlags = 0
    );

    // Respuesta de error a LOGON_PROOF.
    std::vector<std::uint8_t> BuildLogonProofFailure(
        AuthResult result
    );
      }
