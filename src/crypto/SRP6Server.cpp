#include "SRP6Server.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
    constexpr char PRIME_HEX[] =
        "894B645E89E1535BBDAD5B8B29065053"
        "0801B18EBFBF5E8FAB3C82872A3E9BB7";

    constexpr unsigned long GENERATOR = 7;
    constexpr unsigned long MULTIPLIER = 3;

    using BNPtr =
        std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;

    using BNContextPtr =
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

    using EVPContextPtr =
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    BNPtr MakeBN()
    {
        return BNPtr(BN_new(), BN_clear_free);
    }

    bool Sha1(
        const uint8_t* data,
        std::size_t size,
        std::array<uint8_t, 20>& output)
    {
        EVPContextPtr context(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );

        if (!context)
            return false;

        unsigned int outputSize = 0;

        if (EVP_DigestInit_ex(
                context.get(), EVP_sha1(), nullptr) != 1)
            return false;

        if (size > 0 &&
            EVP_DigestUpdate(context.get(), data, size) != 1)
            return false;

        if (EVP_DigestFinal_ex(
                context.get(), output.data(), &outputSize) != 1)
            return false;

        return outputSize == output.size();
    }

    bool ToLittleEndian(
        const BIGNUM* value,
        uint8_t* output,
        int size)
    {
        return BN_bn2lebinpad(value, output, size) == size;
    }

    bool HashParts(
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

    bool DeriveSessionKey(
        const BIGNUM* secret,
        SRP6Server::SessionKey& output)
    {
        std::array<uint8_t, 32> secretLE{};

        if (!ToLittleEndian(
                secret,
                secretLE.data(),
                static_cast<int>(secretLE.size())))
            return false;

        std::array<uint8_t, 16> even{};
        std::array<uint8_t, 16> odd{};

        for (std::size_t i = 0; i < 16; ++i)
        {
            even[i] = secretLE[i * 2];
            odd[i] = secretLE[i * 2 + 1];
        }

        std::array<uint8_t, 20> evenHash{};
        std::array<uint8_t, 20> oddHash{};

        if (!Sha1(even.data(), even.size(), evenHash))
            return false;

        if (!Sha1(odd.data(), odd.size(), oddHash))
            return false;

        for (std::size_t i = 0; i < 20; ++i)
        {
            output[i * 2] = evenHash[i];
            output[i * 2 + 1] = oddHash[i];
        }

        OPENSSL_cleanse(secretLE.data(), secretLE.size());
        OPENSSL_cleanse(even.data(), even.size());
        OPENSSL_cleanse(odd.data(), odd.size());

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

    std::transform(
        username_.begin(),
        username_.end(),
        username_.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(std::toupper(c));
        }
    );

    BNPtr rawN = MakeBN();
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

    if (!rawN || !g || !v || !gb ||
        !kv || !B || !b || !context)
        return false;

    BIGNUM* prime = nullptr;

    if (!BN_hex2bn(&prime, PRIME_HEX))
        return false;

    BNPtr N(prime, BN_clear_free);

    if (!BN_set_word(g.get(), GENERATOR))
        return false;

    if (!BN_set_word(kv.get(), MULTIPLIER))
        return false;

    // El verifier de la base de datos está almacenado
    // como un entero little-endian de 32 bytes.
    if (!BN_lebin2bn(
            verifier.data(),
            static_cast<int>(verifier.size()),
            v.get()))
        return false;

    if (BN_is_zero(v.get()) ||
        BN_cmp(v.get(), N.get()) >= 0)
        return false;

    // Generar b aleatorio criptográficamente seguro.
    if (!BN_priv_rand(
            b.get(),
            256,
            BN_RAND_TOP_ONE,
            BN_RAND_BOTTOM_ANY))
        return false;

    // gb = g^b mod N
    if (!BN_mod_exp(
            gb.get(),
            g.get(),
            b.get(),
            N.get(),
            context.get()))
        return false;

    // kv = 3 * v mod N
    if (!BN_mod_mul(
            kv.get(),
            kv.get(),
            v.get(),
            N.get(),
            context.get()))
        return false;

    // B = (3*v + g^b) mod N
    if (!BN_mod_add(
            B.get(),
            kv.get(),
            gb.get(),
            N.get(),
            context.get()))
        return false;

    if (BN_is_zero(B.get()))
        return false;

    if (!ToLittleEndian(
            B.get(),
            publicB_.data(),
            static_cast<int>(publicB_.size())))
        return false;

    salt_ = salt;

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
    if (!ready_ || authenticated_ || !privateB_)
        return false;

    serverM2.fill(0);

    BNPtr N = MakeBN();
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

    BIGNUM* prime = nullptr;

    if (!BN_hex2bn(&prime, PRIME_HEX))
        return false;

    BNPtr primePtr(prime, BN_clear_free);

    if (!BN_lebin2bn(
            clientA.data(),
            static_cast<int>(clientA.size()),
            A.get()))
        return false;

    if (BN_is_zero(A.get()) ||
        BN_cmp(A.get(), primePtr.get()) >= 0)
        return false;

    // Reconstruct verifier from the account repository.
    // The verifier must be retained for this session.
    // This implementation requires it as a stored member.
    //
    // See the correction below: verifier_ is added to the class.

    return false;
}

const SRP6Server::Key& SRP6Server::GetB() const
{
    return publicB_;
}

const SRP6Server::Key& SRP6Server::GetSalt() const
{
    return salt_;
}

bool SRP6Server::IsReady() const
{
    return ready_;
}

bool SRP6Server::IsAuthenticated() const
{
    return authenticated_;
}
