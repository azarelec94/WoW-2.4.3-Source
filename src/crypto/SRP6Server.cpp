#include "SRP6Server.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <memory>

namespace
{
    constexpr char PRIME_HEX[] =
        "894B645E89E1535BBDAD5B8B29065053"
        "0801B18EBFBF5E8FAB3C82872A3E9BB7";

    using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;

    BNPtr MakeBN()
    {
        return BNPtr(BN_new(), BN_clear_free);
    }

    bool ToLittleEndian(
        const BIGNUM* value,
        uint8_t* output,
        int size)
    {
        return BN_bn2lebinpad(value, output, size) == size;
    }
}

SRP6Server::SRP6Server() = default;

SRP6Server::~SRP6Server()
{
    if (privateB_)
        BN_clear_free(privateB_);
}

bool SRP6Server::CreateChallenge(
    const Key& salt,
    const Key& verifier)
{
    ready_ = false;

    if (privateB_)
    {
        BN_clear_free(privateB_);
        privateB_ = nullptr;
    }

    BNPtr N = MakeBN();
    BNPtr g = MakeBN();
    BNPtr v = MakeBN();
    BNPtr gb = MakeBN();
    BNPtr kv = MakeBN();
    BNPtr B = MakeBN();

    BN_CTX* context = BN_CTX_new();

    if (!N || !g || !v || !gb || !kv || !B || !context)
    {
        BN_CTX_free(context);
        return false;
    }

    if (!BN_hex2bn(&N.get(), PRIME_HEX))
    {
        BN_CTX_free(context);
        return false;
    }

    if (!BN_set_word(g.get(), 7))
    {
        BN_CTX_free(context);
        return false;
    }

    if (!BN_set_word(kv.get(), 3))
    {
        BN_CTX_free(context);
        return false;
    }

    // Database verifier is little-endian.
    if (!BN_lebin2bn(verifier.data(), KEY_SIZE, v.get()))
    {
        BN_CTX_free(context);
        return false;
    }

    if (BN_is_zero(v.get()) || BN_cmp(v.get(), N.get()) >= 0)
    {
        BN_CTX_free(context);
        return false;
    }

    BNPtr b = MakeBN();

    if (!b || !BN_rand(b.get(), 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
    {
        BN_CTX_free(context);
        return false;
    }

    // gb = g^b mod N
    if (!BN_mod_exp(gb.get(), g.get(), b.get(), N.get(), context))
    {
        BN_CTX_free(context);
        return false;
    }

    // kv = 3 * verifier mod N
    if (!BN_mod_mul(kv.get(), kv.get(), v.get(), N.get(), context))
    {
        BN_CTX_free(context);
        return false;
    }

    // B = (3 * verifier + g^b) mod N
    if (!BN_mod_add(B.get(), kv.get(), gb.get(), N.get(), context))
    {
        BN_CTX_free(context);
        return false;
    }

    if (BN_is_zero(B.get()))
    {
        BN_CTX_free(context);
        return false;
    }

    if (!ToLittleEndian(B.get(), publicB_.data(), KEY_SIZE))
    {
        BN_CTX_free(context);
        return false;
    }

    salt_ = salt;

    privateB_ = b.release();
    ready_ = true;

    BN_CTX_free(context);

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

bool SRP6Server::IsReady() const
{
    return ready_;
}
