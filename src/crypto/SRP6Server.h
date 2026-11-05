#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/bn.h>

class SRP6Server
{
public:
    static constexpr std::size_t KEY_SIZE = 32;

    using Key = std::array<uint8_t, KEY_SIZE>;

    SRP6Server();
    ~SRP6Server();

    SRP6Server(const SRP6Server&) = delete;
    SRP6Server& operator=(const SRP6Server&) = delete;

    bool CreateChallenge(
        const Key& salt,
        const Key& verifier
    );

    const Key& GetB() const;
    const Key& GetSalt() const;

    bool IsReady() const;

private:
    BIGNUM* privateB_ = nullptr;

    Key publicB_{};
    Key salt_{};

    bool ready_ = false;
};
