//------------------------------------------------------------------------------
/*
    This file is part of validator-keys-tool:
        https://github.com/ripple/validator-keys-tool
    Copyright (c) 2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <ValidatorKeys.h>

#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/base64.h>
#include <xrpl/json/json_reader.h>
#include <xrpl/json/to_string.h>
#include <xrpl/protocol/HashPrefix.h>
#include <xrpl/protocol/Serializer.h>
#include <xrpl/protocol/Sign.h>

#include <boost/algorithm/clamp.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>

#include <fstream>

namespace ripple {

std::string
ValidatorToken::toString() const
{
    Json::Value jv;
    jv["validation_secret_key"] = strHex(secretKey);
    jv["manifest"] = manifest;

    return ripple::base64_encode(to_string(jv));
}

ValidatorKeys::ValidatorKeys(KeyType const& keyType)
    : keyType_(keyType)
    , keys_(generateKeyPair(keyType_, randomSeed()))
    , tokenSequence_(0)
    , revoked_(false)
{
}

ValidatorKeys::ValidatorKeys(
    KeyType const& keyType,
    SecretKey const& secretKey,
    std::uint32_t tokenSequence,
    bool revoked)
    : keyType_(keyType)
    , keys_({derivePublicKey(keyType_, secretKey), secretKey})
    , tokenSequence_(tokenSequence)
    , revoked_(revoked)
{
}

ValidatorKeys::ValidatorKeys(
    KeyType const& keyType,
    PublicKey const& publicKey,
    std::uint32_t tokenSequence,
    bool revoked)
    : keyType_(keyType)
    , keys_(publicKey)
    , tokenSequence_(tokenSequence)
    , revoked_(revoked)
{
}

ValidatorKeys
ValidatorKeys::make_ValidatorKeys(boost::filesystem::path const& keyFile)
{
    std::ifstream ifsKeys(keyFile.c_str(), std::ios::in);

    if (!ifsKeys)
        throw std::runtime_error(
            "Failed to open key file: " + keyFile.string());

    Json::Reader reader;
    Json::Value jKeys;
    if (!reader.parse(ifsKeys, jKeys))
    {
        throw std::runtime_error(
            "Unable to parse json key file: " + keyFile.string());
    }

    static std::array<std::string, 4> const requiredFields{
        {"key_type", "secret_key", "token_sequence", "revoked"}};

    for (auto field : requiredFields)
    {
        if (!jKeys.isMember(field))
        {
            throw std::runtime_error(
                "Key file '" + keyFile.string() + "' is missing \"" + field +
                "\" field");
        }
    }

    auto const keyType = keyTypeFromString(jKeys["key_type"].asString());
    if (!keyType)
    {
        throw std::runtime_error(
            "Key file '" + keyFile.string() +
            "' contains invalid \"key_type\" field: " +
            jKeys["key_type"].toStyledString());
    }

    auto const secret = parseBase58<SecretKey>(
        TokenType::NodePrivate, jKeys["secret_key"].asString());

    auto const pubKey = [&]() -> std::optional<PublicKey> {
        if (jKeys["secret_key"].asString() == "external")
        {
            if (!jKeys.isMember("public_key"))
            {
                throw std::runtime_error(
                    "Key file '" + keyFile.string() +
                    "' is missing \"public_key\" field");
            }
            auto const pubKey = parseBase58<PublicKey>(
                TokenType::NodePublic, jKeys["public_key"].asString());
            if (!pubKey)
                throw std::runtime_error(
                    "Key file '" + keyFile.string() +
                    "' contains invalid \"public_key\" field: " +
                    jKeys["public_key"].toStyledString());
            return pubKey;
        }
        else if (!secret)
        {
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"secret_key\" field: " +
                jKeys["secret_key"].toStyledString());
        }
        return std::nullopt;
    }();

    std::uint32_t tokenSequence;
    try
    {
        if (!jKeys["token_sequence"].isIntegral())
            throw std::runtime_error("");

        tokenSequence = jKeys["token_sequence"].asUInt();
    }
    catch (std::runtime_error&)
    {
        throw std::runtime_error(
            "Key file '" + keyFile.string() +
            "' contains invalid \"token_sequence\" field: " +
            jKeys["token_sequence"].toStyledString());
    }

    if (!jKeys["revoked"].isBool())
        throw std::runtime_error(
            "Key file '" + keyFile.string() +
            "' contains invalid \"revoked\" field: " +
            jKeys["revoked"].toStyledString());

    ValidatorKeys vk = [&]() {
        if (secret)
            return ValidatorKeys(
                *keyType, *secret, tokenSequence, jKeys["revoked"].asBool());
        else
        {
            assert(*keyType == *publicKeyType(*pubKey));
            return ValidatorKeys(
                *keyType, *pubKey, tokenSequence, jKeys["revoked"].asBool());
        }
    }();

    if (jKeys.isMember("domain"))
    {
        if (!jKeys["domain"].isString())
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"domain\" field: " +
                jKeys["domain"].toStyledString());

        vk.domain(jKeys["domain"].asString());
    }

    if (jKeys.isMember("manifest"))
    {
        if (!jKeys["manifest"].isString())
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"manifest\" field: " +
                jKeys["manifest"].toStyledString());

        auto ret = strUnHex(jKeys["manifest"].asString());

        if (!ret || ret->size() == 0)
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"manifest\" field: " +
                jKeys["manifest"].toStyledString());

        vk.manifest_.clear();
        vk.manifest_.reserve(ret->size());
        std::copy(ret->begin(), ret->end(), std::back_inserter(vk.manifest_));
    }

    if (jKeys.isMember("pending_token_secret"))
    {
        if (!jKeys["pending_token_secret"].isString())
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"pending_token_secret\" field: " +
                jKeys["pending_token_secret"].toStyledString());

        vk.pendingTokenSecret_ = parseBase58<SecretKey>(
            TokenType::NodePrivate, jKeys["pending_token_secret"].asString());

        if (!vk.pendingTokenSecret_)
        {
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"pending_token_secret\" field: " +
                jKeys["pending_manifest"].toStyledString());
        }
    }

    if (jKeys.isMember("pending_key_type"))
    {
        auto const keyType =
            keyTypeFromString(jKeys["pending_key_type"].asString());
        if (!keyType)
        {
            throw std::runtime_error(
                "Key file '" + keyFile.string() +
                "' contains invalid \"pending_key_type\" field: " +
                jKeys["key_type"].toStyledString());
        }
        vk.pendingKeyType_ = keyType;
    }

    return vk;
}

void
ValidatorKeys::writeToFile(boost::filesystem::path const& keyFile) const
{
    using namespace boost::filesystem;

    Json::Value jv;
    jv["key_type"] = to_string(keyType_);
    jv["public_key"] = toBase58(TokenType::NodePublic, keys_.publicKey);
    jv["secret_key"] = keys_.secretKey
        ? toBase58(TokenType::NodePrivate, *keys_.secretKey)
        : "external";
    jv["token_sequence"] = Json::UInt(tokenSequence_);
    jv["revoked"] = revoked_;
    if (!domain_.empty())
        jv["domain"] = domain_;
    if (!manifest_.empty())
        jv["manifest"] = strHex(makeSlice(manifest_));
    if (pendingTokenSecret_)
        jv["pending_token_secret"] =
            toBase58(TokenType::NodePrivate, *pendingTokenSecret_);
    if (pendingKeyType_)
        jv["pending_key_type"] = to_string(*pendingKeyType_);

    if (!keyFile.parent_path().empty())
    {
        boost::system::error_code ec;
        if (!exists(keyFile.parent_path()))
            boost::filesystem::create_directories(keyFile.parent_path(), ec);

        if (ec || !is_directory(keyFile.parent_path()))
            throw std::runtime_error(
                "Cannot create directory: " + keyFile.parent_path().string());
    }

    std::ofstream o(keyFile.string(), std::ios_base::trunc);
    if (o.fail())
        throw std::runtime_error("Cannot open key file: " + keyFile.string());

    o << jv.toStyledString();
}

void
ValidatorKeys::verifyManifest() const
{
    STObject st(sfGeneric);
    SerialIter sit(manifest_.data(), manifest_.size());
    st.set(sit);

    auto fail = []() {
        throw std::runtime_error("Manifest is not properly signed");
    };
    auto const tpk = get<PublicKey>(st, sfSigningPubKey);
    if (revoked() && tpk)
        fail();

    if (!revoked() && (!tpk || !verify(st, HashPrefix::manifest, *tpk)))
        fail();

    auto const pk = get<PublicKey>(st, sfPublicKey);
    if (!pk || !verify(st, HashPrefix::manifest, *pk, sfMasterSignature))
        fail();
}

// Helper functions
[[nodiscard]] STObject
generatePartialManifest(
    uint32_t sequence,
    PublicKey const& masterPubKey,
    PublicKey const& signingPubKey,
    std::string const& domain)
{
    STObject st(sfGeneric);
    st[sfSequence] = sequence;
    st[sfPublicKey] = masterPubKey;
    st[sfSigningPubKey] = signingPubKey;

    if (!domain.empty())
        st[sfDomain] = makeSlice(domain);

    return st;
}

[[nodiscard]] STObject
generatePartialRevocation(PublicKey const& masterPubKey)
{
    STObject st(sfGeneric);
    st[sfSequence] = std::numeric_limits<std::uint32_t>::max();
    st[sfPublicKey] = masterPubKey;

    return st;
}

boost::optional<ValidatorToken>
ValidatorKeys::createValidatorToken(KeyType const& keyType)
{
    if (revoked() ||
        std::numeric_limits<std::uint32_t>::max() - 1 <= tokenSequence_)
        return boost::none;

    // Invalid secret key
    if (!keys_.secretKey)
        throw std::runtime_error(
            "This key file cannot be used to sign tokens.");

    ++tokenSequence_;

    auto const tokenSecret = generateSecretKey(keyType, randomSeed());
    auto const tokenPublic = derivePublicKey(keyType, tokenSecret);

    STObject st = generatePartialManifest(
        tokenSequence_, keys_.publicKey, tokenPublic, domain_);

    ripple::sign(st, HashPrefix::manifest, keyType, tokenSecret);
    ripple::sign(
        st,
        HashPrefix::manifest,
        keyType_,
        *keys_.secretKey,
        sfMasterSignature);

    setManifest(st);

    return ValidatorToken{
        ripple::base64_encode(manifest_.data(), manifest_.size()), tokenSecret};
}

boost::optional<std::string>
ValidatorKeys::startValidatorToken(KeyType const& keyType) const
{
    if (revoked() ||
        std::numeric_limits<std::uint32_t>::max() - 1 <= tokenSequence_)
        return boost::none;

    auto const tokenSecret = generateSecretKey(keyType, randomSeed());
    auto const tokenPublic = derivePublicKey(keyType, tokenSecret);

    // Generate the next manifest with the next sequence number, but
    // don't update until it's been signed
    STObject st = generatePartialManifest(
        tokenSequence_ + 1, keys_.publicKey, tokenPublic, domain_);

    Serializer s;
    s.add32(HashPrefix::manifest);
    st.addWithoutSigningFields(s);

    pendingTokenSecret_ = tokenSecret;
    pendingKeyType_ = keyType;

    return strHex(s.peekData());
}

boost::optional<ValidatorToken>
ValidatorKeys::finishToken(Blob const& masterSig)
{
    if (revoked())
        return boost::none;

    if (!pendingTokenSecret_ || !pendingKeyType_)
        throw std::runtime_error("No pending token to finish");

    ++tokenSequence_;

    auto const tokenSecret = *pendingTokenSecret_;
    auto const tokenPublic = derivePublicKey(*pendingKeyType_, tokenSecret);

    STObject st = generatePartialManifest(
        tokenSequence_, keys_.publicKey, tokenPublic, domain_);

    ripple::sign(st, HashPrefix::manifest, *pendingKeyType_, tokenSecret);
    st[sfMasterSignature] = makeSlice(masterSig);

    setManifest(st);

    return ValidatorToken{
        ripple::base64_encode(manifest_.data(), manifest_.size()), tokenSecret};
}

std::string
ValidatorKeys::revoke()
{
    // Invalid secret key
    if (!keys_.secretKey)
        throw std::runtime_error(
            "This key file cannot be used to sign tokens.");

    revoked_ = true;

    STObject st = generatePartialRevocation(keys_.publicKey);

    ripple::sign(
        st,
        HashPrefix::manifest,
        keyType_,
        *keys_.secretKey,
        sfMasterSignature);

    setManifest(st);

    return ripple::base64_encode(manifest_.data(), manifest_.size());
}

std::string
ValidatorKeys::startRevoke() const
{
    // Generate the revocation manifest, but
    // don't update until it's been signed
    STObject st = generatePartialRevocation(keys_.publicKey);

    Serializer s;
    s.add32(HashPrefix::manifest);
    st.addWithoutSigningFields(s);

    pendingTokenSecret_.reset();
    pendingKeyType_.reset();

    return strHex(s.peekData());
}

std::string
ValidatorKeys::finishRevoke(Blob const& masterSig)
{
    revoked_ = true;

    STObject st = generatePartialRevocation(keys_.publicKey);

    st[sfMasterSignature] = makeSlice(masterSig);

    setManifest(st);

    return ripple::base64_encode(manifest_.data(), manifest_.size());
}

void
ValidatorKeys::setManifest(STObject const& st)
{
    Serializer s;
    st.add(s);

    manifest_.clear();
    manifest_.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(manifest_));

    verifyManifest();

    pendingTokenSecret_.reset();
    pendingKeyType_.reset();
}

std::string
ValidatorKeys::sign(std::string const& data) const
{
    // Invalid secret key
    if (!keys_.secretKey)
        throw std::runtime_error("This key file cannot be used to sign.");

    return strHex(
        ripple::sign(keys_.publicKey, *keys_.secretKey, makeSlice(data)));
}

std::string
ValidatorKeys::signHex(std::string data) const
{
    // Invalid secret key
    if (!keys_.secretKey)
        throw std::runtime_error("This key file cannot be used to sign.");

    boost::algorithm::trim(data);
    auto const blob = strUnHex(data);
    if (!blob)
        throw std::runtime_error("Could not decode hex string: " + data);
    return strHex(
        ripple::sign(keys_.publicKey, *keys_.secretKey, makeSlice(*blob)));
}

void
ValidatorKeys::domain(std::string d)
{
    if (!d.empty())
    {
        // A valid domain for a validator must be at least 4 characters
        // long, should contain at least one . and should not be longer
        // that 128 characters.
        if (d.size() < 4 || d.size() > 128)
            throw std::runtime_error(
                "The domain must be between 4 and 128 characters long.");

        // This regular expression should do a decent job of weeding out
        // obviously wrong domain names but it isn't perfect. It does not
        // really support IDNs. If this turns out to be an issue, a more
        // thorough regex can be used or this check can just be removed.
        static boost::regex const re(
            "^"                   // Beginning of line
            "("                   // Hostname or domain name
            "(?!-)"               //  - must not begin with '-'
            "[a-zA-Z0-9-]{1,63}"  //  - only alphanumeric and '-'
            "(?<!-)"              //  - must not end with '-'
            "\\."                 // segment separator
            ")+"                  // 1 or more segments
            "[A-Za-z]{2,63}"      // TLD
            "$"                   // End of line
            ,
            boost::regex_constants::optimize);

        if (!boost::regex_match(d, re))
            throw std::runtime_error(
                "The domain field must use the '[host.][subdomain.]domain.tld' "
                "format");
    }

    domain_ = std::move(d);
}

}  // namespace ripple
