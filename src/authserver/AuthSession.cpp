#include "AuthSession.h"

#include "protocol/AuthOpcodes.h"

#include <boost/asio/read.hpp>

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>

namespace
{
    constexpr std::size_t CHALLENGE_HEADER_SIZE = 3;

    constexpr std::size_t CHALLENGE_BODY_MIN_SIZE = 30;
    constexpr std::size_t MAX_USERNAME_SIZE = 16;

    // LOGON_PROOF:
    // A[32] + M1[20] + CRC[20] + numberOfKeys[1] + securityFlags[1]
    constexpr std::size_t LOGON_PROOF_BASE_SIZE = 74;

    // REALM_LIST request: 4-byte build/version field.
    constexpr std::size_t REALM_LIST_BODY_SIZE = 4;

    uint16_t ReadUInt16LE(const uint8_t* data)
    {
        return static_cast<uint16_t>(
            static_cast<uint16_t>(data[0]) |
            (static_cast<uint16_t>(data[1]) << 8)
        );
    }
}

AuthSession::AuthSession(std::shared_ptr<Socket> socket)
    : socket_(std::move(socket))
{
}

void AuthSession::Start()
{
    if (!socket_ || !socket_->is_open())
        return;

    state_ = State::WaitingChallenge;

    ReadOpcode();
}

void AuthSession::Close()
{
    if (state_ == State::Closed)
        return;

    state_ = State::Closed;

    if (!socket_)
        return;

    boost::system::error_code error;

    socket_->shutdown(
        boost::asio::ip::tcp::socket::shutdown_both,
        error
    );

    socket_->close(error);
}

void AuthSession::ReadOpcode()
{
    if (state_ == State::Closed)
        return;

    auto self = shared_from_this();

    boost::asio::async_read(
        *socket_,
        boost::asio::buffer(&opcode_, sizeof(opcode_)),

        [self](const boost::system::error_code& error,
               std::size_t bytesTransferred)
        {
            if (error || bytesTransferred != 1)
            {
                self->Close();
                return;
            }

            switch (self->opcode_)
            {
                case AuthOpcode::LOGON_CHALLENGE:
                {
                    self->ReadChallengeHeader();
                    break;
                }

                case AuthOpcode::LOGON_PROOF:
                {
                    self->ReadPayload(LOGON_PROOF_BASE_SIZE);
                    break;
                }

                case AuthOpcode::REALM_LIST:
                {
                    self->ReadPayload(REALM_LIST_BODY_SIZE);
                    break;
                }

                case AuthOpcode::RECONNECT_CHALLENGE:
                {
                    // Todavía no implementado.
                    self->Close();
                    break;
                }

                case AuthOpcode::RECONNECT_PROOF:
                {
                    // Todavía no implementado.
                    self->Close();
                    break;
                }

                default:
                {
                    std::cerr
                        << "[AuthSession] Opcode desconocido: "
                        << static_cast<unsigned int>(self->opcode_)
                        << '\n';

                    self->Close();
                    break;
                }
            }
        }
    );
}

void AuthSession::ReadChallengeHeader()
{
    if (state_ == State::Closed)
        return;

    auto self = shared_from_this();

    boost::asio::async_read(
        *socket_,
        boost::asio::buffer(
            challengeHeader_.data(),
            CHALLENGE_HEADER_SIZE
        ),

        [self](const boost::system::error_code& error,
               std::size_t bytesTransferred)
        {
            if (error || bytesTransferred != CHALLENGE_HEADER_SIZE)
            {
                self->Close();
                return;
            }

            self->protocolVersion_ = self->challengeHeader_[0];

            const uint16_t bodySize = ReadUInt16LE(
                self->challengeHeader_.data() + 1
            );

            // Para el cliente 2.4.3 esperamos protocol version 8.
            if (self->protocolVersion_ != 8)
            {
                std::cerr
                    << "[AuthSession] Version de protocolo no soportada: "
                    << static_cast<unsigned int>(
                        self->protocolVersion_
                    )
                    << '\n';

                self->Close();
                return;
            }

            if (!self->IsValidChallengeSize(bodySize))
            {
                std::cerr
                    << "[AuthSession] Tamano invalido de challenge: "
                    << bodySize
                    << '\n';

                self->Close();
                return;
            }

            self->ReadPayload(bodySize);
        }
    );
}

bool AuthSession::IsValidChallengeSize(std::size_t size) const
{
    const std::size_t maximumSize =
        CHALLENGE_BODY_MIN_SIZE + MAX_USERNAME_SIZE;

    return size >= CHALLENGE_BODY_MIN_SIZE &&
           size <= maximumSize;
}

void AuthSession::ReadPayload(std::size_t size)
{
    if (state_ == State::Closed)
        return;

    // Evita tamaños absurdos o desbordamientos.
    constexpr std::size_t MAX_PACKET_SIZE = 4096;

    if (size == 0 || size > MAX_PACKET_SIZE)
    {
        Close();
        return;
    }

    body_.assign(size, 0);

    auto self = shared_from_this();

    boost::asio::async_read(
        *socket_,
        boost::asio::buffer(body_.data(), body_.size()),

        [self](const boost::system::error_code& error,
               std::size_t bytesTransferred)
        {
            if (error || bytesTransferred != self->body_.size())
            {
                self->Close();
                return;
            }

            self->HandlePacket(
                self->opcode_,
                self->body_
            );

            // Los handlers deben dejar la sesión abierta si
            // corresponde continuar leyendo paquetes.
            if (self->state_ != State::Closed)
            {
                self->ReadOpcode();
            }
        }
    );
}

void AuthSession::HandlePacket(
    uint8_t opcode,
    const std::vector<uint8_t>& body)
{
    if (state_ == State::Closed)
        return;

    switch (opcode)
    {
        case AuthOpcode::LOGON_CHALLENGE:
        {
            HandleLogonChallenge(body);
            break;
        }

        case AuthOpcode::LOGON_PROOF:
        {
            HandleLogonProof(body);
            break;
        }

        case AuthOpcode::REALM_LIST:
        {
            HandleRealmList(body);
            break;
        }

        default:
        {
            Close();
            break;
        }
    }
}
void AuthSession::HandleLogonChallenge(
    const std::vector<uint8_t>& body)
{
    if (body.size() < CHALLENGE_BODY_MIN_SIZE ||
        body.size() > CHALLENGE_BODY_MIN_SIZE + MAX_USERNAME_SIZE)
    {
        Close();
        return;
    }

    // La estructura completa del challenge se analizará
    // en el siguiente paso, incluyendo el nombre de cuenta.
    std::cout << "[AuthSession] LOGON_CHALLENGE recibido. "
              << "Bytes: " << body.size() << '\n';

    // No enviar todavía una respuesta SRP incompleta.
    // Mantener la conexión abierta para la siguiente etapa.
    state_ = State::WaitingProof;
}

void AuthSession::HandleLogonProof(
    const std::vector<uint8_t>& body)
{
    if (body.size() != LOGON_PROOF_BASE_SIZE)
    {
        Close();
        return;
    }

    std::cout << "[AuthSession] LOGON_PROOF recibido. "
              << "Bytes: " << body.size() << '\n';

    // Aquí irá la verificación SRP6.
}

void AuthSession::HandleRealmList(
    const std::vector<uint8_t>& body)
{
    if (body.size() != REALM_LIST_BODY_SIZE)
    {
        Close();
        return;
    }

    std::cout << "[AuthSession] REALM_LIST recibido. "
              << "Bytes: " << body.size() << '\n';

    // Aquí irá la respuesta con la lista de reinos.
}
