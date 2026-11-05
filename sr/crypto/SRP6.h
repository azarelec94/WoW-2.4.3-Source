
#pragma once

#include <array>
#include <string>
#include <optional>
#include <cstdint>

namespace Crypto
{
    using Salt = std::array<uint8_t, 32>;
    using Verifier = std::array<uint8_t, 32>;
    using PublicKey = std::array<uint8_t, 32>;
    using Proof = std::array<uint8_t, 20>;
    using SessionKey = std::array<uint8_t, 40>;

    struct Challenge
    {
        PublicKey B{};
        Salt salt{};
    };

    struct AuthResult
    {
        Proof M2{};
        SessionKey K{};
    };

    bool GenerateSalt(Salt& salt);

    bool GenerateVerifier(
        const std::string& username,
        const std::string& password,
        const Salt& salt,
        Verifier& verifier
    );

    class SRP6Server
    {
    public:
        SRP6Server();
        ~SRP6Server();

        SRP6Server(const SRP6Server&) = delete;
        SRP6Server& operator=(const SRP6Server&) = delete;

        bool Begin(
            const std::string& username,
            const Salt& salt,
            const Verifier& verifier,
            Challenge& challenge
        );

        std::optional<AuthResult> Verify(
            const PublicKey& A,
            const Proof& M1
        );

    private:
        struct Impl;
        Impl* impl;
    };
}
