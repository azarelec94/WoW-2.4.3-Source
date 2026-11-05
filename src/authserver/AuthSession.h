
#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>

class AuthSession :
    public std::enable_shared_from_this<AuthSession>
{
public:
    using Socket = boost::asio::ip::tcp::socket;

    explicit AuthSession(
        std::shared_ptr<Socket> socket);

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

    void ReadHeader();
    void ReadBody(uint16_t size);

    void HandlePacket(
        uint8_t opcode,
        const std::vector<uint8_t>& body);

    void HandleLogonChallenge(
        const std::vector<uint8_t>& body);

    void HandleLogonProof(
        const std::vector<uint8_t>& body);

    void HandleRealmList(
        const std::vector<uint8_t>& body);

    std::shared_ptr<Socket> socket_;
    State state_ = State::Connected;

    std::array<uint8_t, 4> header_{};
    std::vector<uint8_t> body_;

    std::string username_;
    uint16_t clientBuild_ = 0;
};
