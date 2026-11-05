#include "SRP6Server.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <vector>

namespace
{
    constexpr char PRIME_HEX[] =
        "894B645E89E1535BBDAD5B8B29065053"
        "0801B18EBFBF5E8FAB3C82872A3E9BB7";

    constexpr unsigned long GENERATOR = 7;
    constexpr unsigned long MULTIPLIER = 3;

    // SHA1(N) XOR SHA1(g), constante de la variante WoW.
    constexpr std::array<uint8_t, 20> XOR_N_G =
    {
        221, 123, 176, 58, 56,
        172, 115, 17, 3, 152,
        124, 90, 80, 111, 202,
        150, 108, 123, 194, 167
    };

    using BNPtr =
        std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;

    using BNContextPtr =
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

    using DigestContextPtr =
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    BNPtr MakeBN()
    {
        return BNPtr(BN_new(), BN_clear_free);
    }

    BNPtr MakePrime()
    {
        BIGNUM* raw = nullptr;

        if (BN_hex2bn(&raw, PRIME_HEX) == 0)
            return BNPtr(nullptr, BN_clear_free);

        return BNPtr(raw, BN_clear_free);
    }

    bool Sha1(
        const uint8_t* data,
        std::size_t size,
        std::array<uint8_t, 20>& output)
    {
        DigestContextPtr context(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );

        if (!context)
            return false;

        unsigned int outputSize = 0;

        if (EVP_DigestInit_ex(
                context.get(), EVP_sha1(), nullptr) != 1)
            return false;

        if (size != 0 &&
            EVP_DigestUpdate(context.get(), data, size) != 1)
            return false;

        if (EVP_DigestFinal_ex(
                context.get(),
                output.data(),
                &outputSize) != 1)
            return false;

        return outputSize == output.size();
    }

    bool Sha1(
        const std::vector<uint8_t>& data,
        std::array<uint8_t, 20>& output)
    {
        return Sha1(data.data(), data.size(), output);
    }

    void Append(
        std::vector<uint8_t>& destination,
        const uint8_t* source,
        std::size_t size)
    {
        destination.insert(
            destination.end(),
            source,
            source + size
        );
    }

    bool ToLittleEndian(
        const BIGNUM* value,
        uint8_t* output,
        int size)
    {
        return BN_bn2lebinpad(value, output, size) == size;
    }

    bool DeriveSessionKey(
        const BIGNUM* secret,
        SRP6Server::SessionKey& output)
    {
        std::array<uint8_t, 32> secretBytes{};

        if (!ToLittleEndian(
                secret,
                secretBytes.data(),
                static_cast<int>(secretBytes.size())))
        {
            return false;
        }

        std::array<uint8_t, 16> evenBytes{};
        std::array<uint8_t, 16> oddBytes{};

        for (std::size_t i = 0; i < 16; ++i)
        {
            evenBytes[i] = secretBytes[i * 2];
            oddBytes[i] = secretBytes[i * 2 + 1];
        }

        std::array<uint8_t, 20> evenHash{};
        std::array<uint8_t, 20> oddHash{};

        const bool evenOk = Sha1(
            evenBytes.data(),
            evenBytes.size(),
            evenHash
        );

        const bool oddOk = Sha1(
            oddBytes.data(),
            oddBytes.size(),
            oddHash
        );

        if (!evenOk || !oddOk)
            return false;

        for (std::size_t i = 0; i < 20; ++i)
        {
            output[i * 2] = evenHash[i];
            output[i * 2 + 1] = oddHash[i];
        }

        OPENSSL_cleanse(secretBytes.data(), secretBytes.size());
        OPENSSL_cleanse(evenBytes.data(), evenBytes.size());
        OPENSSL_cleanse(oddBytes.data(), oddBytes.size());

        return true;
    }
}

SRP6Server::SRP6Server() = default;

SRP6Server::~SRP6Server()
{
    Reset();
}

void SRP6Server::Reset()
{
    if (privateB_)
    {
        BN_clear_free(privateB_);
        privateB_ = nullptr;
    }

    OPENSSL_cleanse(publicB_.data(), publicB_.size());
    OPENSSL_cleanse(salt_.data(), salt_.size());
    OPENSSL_cleanse(verifier_.data(), verifier_.size());
    OPENSSL_cleanse(sessionKey_.data(), sessionKey_.size());

    username_.clear();

    ready_ = false;
    authenticated_ = false;
}

bool SRP6Server::CreateChallenge(
    const std::string& username,
    const Key& salt,
    const Key& verifier)
{
    Reset();

    if (username.empty() || username.size() > 16)
        return false;

    username_ = username;

    for (char& character : username_)
    {
        const unsigned char c =
            static_cast<unsigned char>(character);

        if (c < 0x21 || c > 0x7E)
        {
            Reset();
            return false;
        }

        character = static_cast<char>(std::toupper(c));
    }

    BNPtr N = MakePrime();
    BNPtr g = MakeBN();
    BNPtr v = MakeBN();
    BNPtr gb = MakeBN();
    BNPtr kv = MakeBN();
    BNPtr B = MakeBN();
    BNPtr b = MakeBN();

    BNContextPtr context(
        BN_CTX_new(),
        BN_CTX_free
    );

    if (!N || !g || !v || !gb ||
        !kv || !B || !b || !context)
    {
        Reset();
        return false;
    }

    if (!BN_set_word(g.get(), GENERATOR) ||
        !BN_set_word(kv.get(), MULTIPLIER))
    {
        Reset();
        return false;
    }

    // v se almacena en la base de datos little-endian.
    if (!BN_lebin2bn(
            verifier.data(),
            static_cast<int>(verifier.size()),
            v.get()))
    {
        Reset();
        return false;
    }

    if (BN_is_zero(v.get()) ||
        BN_cmp(v.get(), N.get()) >= 0)
    {
        Reset();
        return false;
    }

    // Generar b criptográficamente aleatorio.
    if (!BN_priv_rand(
            b.get(),
            256,
            BN_RAND_TOP_ONE,
            BN_RAND_BOTTOM_ANY))
    {
        Reset();
        return false;
    }

    // gb = g^b mod N
    if (!BN_mod_exp(
            gb.get(),
            g.get(),
            b.get(),
            N.get(),
            context.get()))
    {
        Reset();
        return false;
    }

    // kv = 3*v mod N
    if (!BN_mod_mul(
            kv.get(),
            kv.get(),
            v.get(),
            N.get(),
            context.get()))
    {
        Reset();
        return false;
    }

    // B = (3*v + g^b) mod N
    if (!BN_mod_add(
            B.get(),
            kv.get(),
            gb.get(),
            N.get(),
            context.get()))
    {
        Reset();
        return false;
    }

    if (BN_is_zero(B.get()))
    {
        Reset();
        return false;
    }

    if (!ToLittleEndian(
            B.get(),
            publicB_.data(),
            static_cast<int>(publicB_.size())))
    {
        Reset();
        return false;
    }

    salt_ = salt;
    verifier_ = verifier;

    privateB_ = b.release();

    ready_ = true;
    authenticated_ = false;

    return true;
}

bool SRP6Server::VerifyClientProof(
    const Key& clientA,
    const Proof& clientM1,
    Proof& serverM2)
{
    serverM2.fill(0);

    if (!ready_ || authenticated_ || !privateB_)
        return false;

    BNPtr N = MakePrime();
    BNPtr A = MakeBN();
    BNPtr v = MakeBN();
    BNPtr u = MakeBN();
    BNPtr vu = MakeBN();
    BNPtr base = MakeBN();
    BNPtr secret = MakeBN();

    BNContextPtr context(
        BN_CTX_new(),
        BN_CTX_free
    );

    if (!N || !A || !v || !u ||
        !vu || !base || !secret || !context)
        return false;

    // A recibido del cliente: little-endian.
    if (!BN_lebin2bn(
            clientA.data(),
            static_cast<int>(clientA.size()),
            A.get()))
        return false;

    if (BN_is_zero(A.get()) ||
        BN_cmp(A.get(), N.get()) >= 0)
        return false;

    if (!BN_lebin2bn(
            verifier_.data(),
            static_cast<int>(verifier_.size()),
            v.get()))
        return false;

    // u = SHA1(A || B), interpretado como little-endian.
    std::vector<uint8_t> uInput;

    Append(uInput, clientA.data(), clientA.size());
    Append(uInput, publicB_.data(), publicB_.size());

    std::array<uint8_t, 20> uHash{};

    if (!Sha1(uInput, uHash))
        return false;

    if (!BN_lebin2bn(
            uHash.data(),
            static_cast<int>(uHash.size()),
            u.get()))
        return false;

    if (BN_is_zero(u.get()))
        return false;

    // vu = v^u mod N
    if (!BN_mod_exp(
            vu.get(),
            v.get(),
            u.get(),
            N.get(),
            context.get()))
        return false;

    // base = A * v^u mod N
    if (!BN_mod_mul(
            base.get(),
            A.get(),
            vu.get(),
            N.get(),
            context.get()))
        return false;

    // S = (A * v^u)^b mod N
    if (!BN_mod_exp(
            secret.get(),
            base.get(),
            privateB_,
            N.get(),
            context.get()))
        return false;

    // K = interleave(S)
    if (!DeriveSessionKey(secret.get(), sessionKey_))
        return false;

    // M1 = SHA1(
    //   XOR_N_G ||
    //   SHA1(username) ||
    //   salt || A || B || K
    // )

    std::array<uint8_t, 20> usernameHash{};

    if (!Sha1(
            reinterpret_cast<const uint8_t*>(username_.data()),
            username_.size(),
            usernameHash))
    {
        OPENSSL_cleanse(sessionKey_.data(), sessionKey_.size());
        return false;
    }

    std::vector<uint8_t> m1Input;

    Append(m1Input, XOR_N_G.data(), XOR_N_G.size());
    Append(m1Input, usernameHash.data(), usernameHash.size());
    Append(m1Input, salt_.data(), salt_.size());
    Append(m1Input, clientA.data(), clientA.size());
    Append(m1Input, publicB_.data(), publicB_.size());
    Append(m1Input, sessionKey_.data(), sessionKey_.size());

    Proof expectedM1{};

    if (!Sha1(m1Input, expectedM1))
    {
        OPENSSL_cleanse(sessionKey_.data(), sessionKey_.size());
        return false;
    }

    // Comparación de prueba en tiempo constante.
    if (CRYPTO_memcmp(
            expectedM1.data(),
            clientM1.data(),
            expectedM1.size()) != 0)
    {
        OPENSSL_cleanse(sessionKey_.data(), sessionKey_.size());
        return false;
    }

    // M2 = SHA1(A || M1 || K)
    std::vector<uint8_t> m2Input;

    Append(m2Input, clientA.data(), clientA.size());
    Append(m2Input, expectedM1.data(), expectedM1.size());
    Append(m2Input, sessionKey_.data(), sessionKey_.size());

    if (!Sha1(m2Input, serverM2))
    {
        OPENSSL_cleanse(sessionKey_.data(), sessionKey_.size());
        return false;
    }

    authenticated_ = true;

    // b deja de ser necesario después de calcular S.
    BN_clear_free(privateB_);
    privateB_ = nullptr;

    OPENSSL_cleanse(uHash.data(), uHash.size());
    OPENSSL_cleanse(usernameHash.data(), usernameHash.size());

    return true;
}

const SRP6Server::Key& SRP6Server::GetB() const
{
    return publicB_;
}

const SRP6Server::Key& SRP6Server::GetSalt() const
{
    return salt_;
}

const SRP6Server::SessionKey& SRP6Server::GetSessionKey() const
{
    return sessionKey_;
}

bool SRP6Server::IsReady() const
{
    return ready_;
}

bool SRP6Server::IsAuthenticated() const
{
    return authenticated_;
}
