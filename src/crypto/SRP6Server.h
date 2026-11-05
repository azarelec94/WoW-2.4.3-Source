
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include <openssl/bn.h>

class SRP6Server
{
public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t PROOF_SIZE = 20;
    static constexpr std::size_t SESSION_KEY_SIZE = 40;

    using Key = std::array<uint8_t, KEY_SIZE>;
    using Proof = std::array<uint8_t, PROOF_SIZE>;
    using SessionKey = std::array<uint8_t, SESSION_KEY_SIZE>;

    SRP6Server();
    ~SRP6Server();

    SRP6Server(const SRP6Server&) = delete;
    SRP6Server& operator=(const SRP6Server&) = delete;

    bool CreateChallenge(
        const std::string& username,
        const Key& salt,
        const Key& verifier
    );

    bool VerifyClientProof(
        const Key& clientA,
        const Proof& clientM1,
        Proof& serverM2
    );

    const Key& GetB() const;
    const Key& GetSalt() const;

    bool IsReady() const;
    bool IsAuthenticated() const;

private:
    void Reset();

    BIGNUM* privateB_ = nullptr;

    Key publicB_{};
    Key salt_{};

    std::string username_;

    SessionKey sessionKey_{};

    bool ready_ = false;
    bool authenticated_ = false;
};
