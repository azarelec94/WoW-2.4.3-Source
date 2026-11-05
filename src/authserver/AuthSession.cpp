
#include "AuthSession.h"

#include "../protocol/AuthOpcodes.h"
#include "../protocol/AuthPacket.h"

#include <iostream>
#include <algorithm>
#include <array>
#include <cctype>

AuthSession::AuthSession(
    std::shared_ptr<Socket> socket)
    : socket_(std::move(socket))
{
}

void AuthSession::Start()
{
    state_ = State::WaitingChallenge;
    ReadHeader();
}

void AuthSession::Close()
{
    if (state_ == State::Closed)
        return;

    state_ = State::Closed;

    boost::system::error_code error;

    socket_->shutdown(
        boost::asio::ip::tcp::socket::shutdown_both,
        error
    );

    socket_->close(error);
}

void AuthSession::ReadHeader()
{
    if (state_ == State::Closed)
        return;

    auto self = shared_from_this();

    boost::asio::async_read(
        *socket_,
        boost::asio::buffer(header_),
        [self](const boost::system::error_code& error,
               std::size_t)
        {
            if (error)
            {
                self->Close();
                return;
            }

            const uint8_t opcode = self->header_[0];

            const uint16_t size =
                static_cast<uint16_t>(self->header_[2]) |
                (static_cast<uint16_t>(
                    self->header_[3]) << 8);

            // Prevent oversized authentication packets.
            if (size > 4096)
            {
                self->Close();
                return;
            }

            self->ReadBody(size);
        }
    );
}

void AuthSession::ReadBody(uint16_t size)
{
    body_.assign(size, 0);

    auto self = shared_from_this();

    if (size == 0)
    {
        HandlePacket(header_[0], body_);
        if (state_ != State::Closed)
            ReadHeader();
        return;
    }

    boost::asio::async_read(
        *socket_,
        boost::asio::buffer(body_),
        [self](const boost::system::error_code& error,
               std::size_t)
        {
            if (error)
            {
                self->Close();
                return;
            }

            self->HandlePacket(
                self->header_[0],
                self->body_
            );

            if (self->state_ != State::Closed)
                self->ReadHeader();
        }
    );
}

void AuthSession::HandlePacket(
    uint8_t opcode,
    const std::vector<uint8_t>& body)
{
    switch (opcode)
    {
        case AuthOpcode::LOGON_CHALLENGE:
            if (state_ != State::WaitingChallenge)
            {
                Close();
                return;
            }

            HandleLogonChallenge(body);
            break;

        case AuthOpcode::LOGON_PROOF:
            if (state_ != State::WaitingProof)
            {
                Close();
                return;
            }

            HandleLogonProof(body);
            break;

        case AuthOpcode::REALM_LIST:
            if (state_ != State::Authenticated &&
                state_ != State::WaitingRealmList)
            {
                Close();
                return;
            }

            HandleRealmList(body);
            break;

        default:
            std::cerr << "Unknown auth opcode: "
                      << static_cast<unsigned>(opcode)
                      << '\n';

            Close();
            break;
    }
}

void AuthSession::HandleLogonChallenge(
    const std::vector<uint8_t>& body)
{
    AuthPacketReader reader(body);

    std::array<uint8_t, 4> game{};
    std::array<uint8_t, 3> version{};
    std::array<uint8_t, 4> platform{};
    std::array<uint8_t, 4> os{};
    std::array<uint8_t, 4> country{};

    uint16_t build = 0;
    uint32_t timezone = 0;
    uint32_t clientIP = 0;
    uint8_t usernameLength = 0;

    if (!reader.ReadBytes(game.data(), game.size()) ||
        !reader.ReadBytes(version.data(), version.size()) ||
        !reader.ReadUInt16(build) ||
        !reader.ReadBytes(platform.data(), platform.size()) ||
        !reader.ReadBytes(os.data(), os.size()) ||
        !reader.ReadBytes(country.data(), country.size()) ||
        !reader.ReadUInt32(timezone) ||
        !reader.ReadUInt32(clientIP) ||
        !reader.ReadUInt8(usernameLength))
    {
        Close();
        return;
    }

    if (usernameLength == 0 ||
        usernameLength > 32 ||
        reader.Remaining() != usernameLength)
    {
        Close();
        return;
    }

    if (std::string(game.begin(), game.end()) !=
        std::string("\0WoW", 4))
    {
        Close();
        return;
    }

    if (version[0] != 2 ||
        version[1] != 4 ||
        version[2] != 3 ||
        build != 8606)
    {
        std::cerr << "Unsupported client version/build\n";
        Close();
        return;
    }

    if (!reader.ReadString(username_, usernameLength))
    {
        Close();
        return;
    }

    std::transform(
        username_.begin(),
        username_.end(),
        username_.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(std::toupper(c));
        }
    );

    clientBuild_ = build;

    std::cout << "Authentication request: "
              << username_
              << " | Build: "
              << clientBuild_
              << '\n';

    // Next module:
    // Load salt and verifier from MySQL.
    // Generate SRP6 challenge B.
    // Send the challenge response.
    //
    // Do not transition to WaitingProof until
    // the server challenge has been successfully sent.

    Close();
}

void AuthSession::HandleLogonProof(
    const std::vector<uint8_t>& body)
{
    // Implemented after SRP6 repository integration.
    Close();
}

void AuthSession::HandleRealmList(
    const std::vector<uint8_t>& body)
{
    // Implemented after successful authentication
    // and realm repository integration.
    Close();
}
