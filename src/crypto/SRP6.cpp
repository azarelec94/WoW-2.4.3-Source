
#include "SRP6.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <memory>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace Crypto
{
    namespace
    {
        constexpr char N_HEX[] =
            "894B645E89E1535BBDAD5B8B29065053"
            "0801B18EBFBF5E8FAB3C82872A3E9BB7";

        using BNPtr = std::unique_ptr<BIGNUM,
            decltype(&BN_free)>;

        using CtxPtr = std::unique_ptr<BN_CTX,
            decltype(&BN_CTX_free)>;

        BNPtr NewBN()
        {
            return BNPtr(BN_new(), BN_free);
        }

        CtxPtr NewContext()
        {
            return CtxPtr(BN_CTX_new(), BN_CTX_free);
        }

        bool Hash(const std::vector<uint8_t>& data,
                  Proof& output)
        {
            unsigned int length = 0;

            return EVP_Digest(
                data.data(),
                data.size(),
                output.data(),
                &length,
                EVP_sha1(),
                nullptr
            ) == 1 && length == output.size();
        }

        void Append(
            std::vector<uint8_t>& output,
            const uint8_t* data,
            size_t length)
        {
            output.insert(
                output.end(),
                data,
                data + length
            );
        }

        std::string Normalize(std::string value)
        {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::toupper(c)
                    );
                }
            );

            return value;
        }

        BNPtr FromLE(
            const uint8_t* data,
            size_t length)
        {
            return BNPtr(
                BN_lebin2bn(data, length, nullptr),
                BN_free
            );
        }

        bool ToLE(
            const BIGNUM* value,
            uint8_t* output,
            size_t length)
        {
            return BN_bn2lebinpad(
                value,
                output,
                static_cast<int>(length)
            ) == static_cast<int>(length);
        }

        bool GetModulus(BIGNUM* N)
        {
            return BN_hex2bn(&N, N_HEX) != 0;
        }

        bool CalculateX(
            const std::string& username,
            const std::string& password,
            const Salt& salt,
            BIGNUM* x)
        {
            const std::string credentials =
                Normalize(username) + ":" +
                Normalize(password);

            Proof inner{};

            std::vector<uint8_t> first(
                credentials.begin(),
                credentials.end()
            );

            if (!Hash(first, inner))
                return false;

            std::vector<uint8_t> second;

            Append(second, salt.data(), salt.size());
            Append(second, inner.data(), inner.size());

            Proof digest{};

            if (!Hash(second, digest))
                return false;

            return BN_lebin2bn(
                digest.data(),
                digest.size(),
                x
            ) != nullptr;
        }

        bool CalculateSessionKey(
            const BIGNUM* A,
            const BIGNUM* verifier,
            const BIGNUM* b,
            const BIGNUM* N,
            const BIGNUM* u,
            SessionKey& K,
            BN_CTX* ctx)
        {
            auto vu = NewBN();
            auto base = NewBN();
            auto S = NewBN();

            if (!vu || !base || !S)
                return false;

            if (!BN_mod_exp(
                vu.get(), verifier, u, N, ctx))
                return false;

            if (!BN_mod_mul(
                base, A, vu.get(), N, ctx))
                return false;

            if (!BN_mod_exp(
                S.get(), base, b, N, ctx))
                return false;

            std::array<uint8_t, 32> raw{};

            if (!ToLE(S.get(), raw.data(), raw.size()))
                return false;

            size_t offset = 0;

            while (offset + 2 <= raw.size() &&
                   raw[offset] == 0)
            {
                offset += 2;
            }

            std::vector<uint8_t> even;
            std::vector<uint8_t> odd;

            for (size_t i = offset; i < raw.size(); i += 2)
            {
                even.push_back(raw[i]);
                odd.push_back(raw[i + 1]);
            }

            Proof evenHash{};
            Proof oddHash{};

            if (!Hash(even, evenHash) ||
                !Hash(odd, oddHash))
                return false;

            for (size_t i = 0; i < 20; ++i)
            {
                K[i * 2] = evenHash[i];
                K[i * 2 + 1] = oddHash[i];
            }

            OPENSSL_cleanse(raw.data(), raw.size());

            return true;
        }

        bool CalculateM1(
            const std::string& username,
            const Salt& salt,
            const PublicKey& A,
            const PublicKey& B,
            const SessionKey& K,
            Proof& M1)
        {
            static constexpr uint8_t XOR_HASH[20] =
            {
                0xdd, 0x7b, 0xb0, 0x3a, 0x38,
                0xac, 0x73, 0x11, 0x03, 0x98,
                0x7c, 0x5a, 0x50, 0x6f, 0xca,
                0x96, 0x6c, 0x7b, 0xc2, 0xa7
            };

            const std::string name = Normalize(username);

            Proof userHash{};

            std::vector<uint8_t> userBytes(
                name.begin(),
                name.end()
            );

            if (!Hash(userBytes, userHash))
                return false;

            std::vector<uint8_t> data;

            Append(data, XOR_HASH, sizeof(XOR_HASH));
            Append(data, userHash.data(), userHash.size());
            Append(data, salt.data(), salt.size());
            Append(data, A.data(), A.size());
            Append(data, B.data(), B.size());
            Append(data, K.data(), K.size());

            return Hash(data, M1);
        }
    }

    bool GenerateSalt(Salt& salt)
    {
        return RAND_bytes(
            salt.data(),
            static_cast<int>(salt.size())
        ) == 1;
    }

    bool GenerateVerifier(
        const std::string& username,
        const std::string& password,
        const Salt& salt,
        Verifier& verifier)
    {
        auto N = NewBN();
        auto g = NewBN();
        auto x = NewBN();
        auto v = NewBN();

        auto ctx = NewContext();

        if (!N || !g || !x || !v || !ctx)
            return false;

        if (!GetModulus(N.get()) ||
            !BN_set_word(g.get(), 7))
            return false;

        if (!CalculateX(
            username, password, salt, x.get()))
            return false;

        if (!BN_mod_exp(
            v.get(), g.get(), x.get(), N.get(), ctx.get()))
            return false;

        return ToLE(
            v.get(),
            verifier.data(),
            verifier.size()
        );
    }

    struct SRP6Server::Impl
    {
        std::string username;

        Salt salt{};
        Verifier verifier{};

        PublicKey B{};

        BNPtr N{nullptr, BN_free};
        BNPtr b{nullptr, BN_free};
        BNPtr v{nullptr, BN_free};

        CtxPtr ctx{nullptr, BN_CTX_free};

        bool active = false;
    };

    SRP6Server::SRP6Server()
        : impl(new Impl())
    {
    }

    SRP6Server::~SRP6Server()
    {
        delete impl;
    }

    bool SRP6Server::Begin(
        const std::string& username,
        const Salt& salt,
        const Verifier& verifier,
        Challenge& challenge)
    {
        impl->active = false;

        impl->N = NewBN();
        impl->b = NewBN();
        impl->v = FromLE(
            verifier.data(), verifier.size());

        impl->ctx = NewContext();

        auto g = NewBN();
        auto k = NewBN();
        auto gb = NewBN();
        auto kv = NewBN();
        auto B = NewBN();

        if (!impl->N || !impl->b || !impl->v ||
            !impl->ctx || !g || !k || !gb ||
            !kv || !B)
            return false;

        if (!GetModulus(impl->N.get()) ||
            !BN_set_word(g.get(), 7) ||
            !BN_set_word(k.get(), 3))
            return false;

        if (RAND_priv_bytes(
            reinterpret_cast<unsigned char*>(
                challenge.B.data()), 32) != 1)
            return false;

        if (!BN_lebin2bn(
            challenge.B.data(), 32, impl->b.get()))
            return false;

        if (BN_is_zero(impl->b.get()))
            return false;

        if (!BN_mod_exp(
            gb.get(), g.get(), impl->b.get(),
            impl->N.get(), impl->ctx.get()))
            return false;

        if (!BN_mul(kv.get(), k.get(), impl->v.get(),
                    impl->ctx.get()))
            return false;

        if (!BN_mod_add(
            B.get(), kv.get(), gb.get(),
            impl->N.get(), impl->ctx.get()))
            return false;

        if (!ToLE(B.get(), impl->B.data(), 32))
            return false;

        impl->username = Normalize(username);
        impl->salt = salt;
        impl->verifier = verifier;

        challenge.B = impl->B;
        challenge.salt = salt;

        impl->active = true;

        return true;
    }

    std::optional<AuthResult> SRP6Server::Verify(
        const PublicKey& A,
        const Proof& clientM1)
    {
        if (!impl->active)
            return std::nullopt;

        impl->active = false;

        auto clientA = FromLE(A.data(), A.size());
        auto B = FromLE(impl->B.data(), impl->B.size());
        auto u = NewBN();

        if (!clientA || !B || !u)
            return std::nullopt;

        if (BN_is_zero(clientA.get()) ||
            BN_cmp(clientA.get(), impl->N.get()) >= 0)
            return std::nullopt;

        std::vector<uint8_t> uInput;

        Append(uInput, A.data(), A.size());
        Append(uInput, impl->B.data(), impl->B.size());

        Proof uHash{};

        if (!Hash(uInput, uHash))
            return std::nullopt;

        if (!BN_lebin2bn(
            uHash.data(), uHash.size(), u.get()))
            return std::nullopt;

        if (BN_is_zero(u.get()))
            return std::nullopt;

        AuthResult result{};

        if (!CalculateSessionKey(
            clientA.get(),
            impl->v.get(),
            impl->b.get(),
            impl->N.get(),
            u.get(),
            result.K,
            impl->ctx.get()))
            return std::nullopt;

        Proof expectedM1{};

        if (!CalculateM1(
            impl->username,
            impl->salt,
            A,
            impl->B,
            result.K,
            expectedM1))
            return std::nullopt;

        if (CRYPTO_memcmp(
            expectedM1.data(),
            clientM1.data(),
            expectedM1.size()) != 0)
        {
            OPENSSL_cleanse(
                result.K.data(), result.K.size());
            return std::nullopt;
        }

        std::vector<uint8_t> proofData;

        Append(proofData, A.data(), A.size());
        Append(proofData, clientM1.data(), clientM1.size());
        Append(proofData, result.K.data(), result.K.size());

        if (!Hash(proofData, result.M2))
            return std::nullopt;

        return result;
    }
}
