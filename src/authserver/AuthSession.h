#pragma once

#include <boost/asio.hpp>
#include "LogonChallenge.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class AuthSession : public std::enable_shared_from_this<AuthSession>
{
public:
    using Socket = boost::asio::ip::tcp::socket;

    explicit AuthSession(std::shared_ptr<Socket> socket);

    void Start();
    void Close();

private:
    enum class State
    {
        Connected,
        WaitingChallenge,
        WaitingProof,
        Authenticated,
        WaitingRealmList,
        Closed
    };

    // Lectura de paquetes
    void ReadOpcode();
    void ReadChallengeHeader();
    void ReadPayload(std::size_t size);

    // Procesamiento de paquetes
    void HandlePacket(
        uint8_t opcode,
        const std::vector<uint8_t>& body
    );

    void HandleLogonChallenge(
        const std::vector<uint8_t>& body
    );

    void HandleLogonProof(
        const std::vector<uint8_t>& body
    );

    void HandleRealmList(
        const std::vector<uint8_t>& body
    );

    // Validación
    bool IsValidChallengeSize(std::size_t size) const;

private:
    std::shared_ptr<Socket> socket_;

    State state_ = State::Connected;

    uint8_t opcode_ = 0;

    // Cabecera especial de LOGON_CHALLENGE:
    // protocol version (1 byte) + body size (2 bytes)
    std::array<uint8_t, 3> challengeHeader_{};

    uint8_t protocolVersion_ = 0;

    std::vector<uint8_t> body_;

    std::string username_;

    uint16_t clientBuild_ = 0;
};

