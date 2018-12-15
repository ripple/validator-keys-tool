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
#include <ripple/basics/base64.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/json/json_reader.h>
#include <ripple/json/to_string.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <boost/algorithm/clamp.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <fstream>

namespace ripple {

std::string
ValidatorToken::toString () const
{
    Json::Value jv;
    jv["validation_secret_key"] = strHex(secretKey);
    jv["manifest"] = manifest;

    return ripple::base64_encode(to_string(jv));
}

ValidatorKeys::ValidatorKeys (KeyType const& keyType)
    : keyType_ (keyType)
    , tokenSequence_ (0)
    , revoked_ (false)
{
    std::tie (publicKey_, secretKey_) = generateKeyPair (
        keyType_, randomSeed ());
}

ValidatorKeys::ValidatorKeys (
    KeyType const& keyType,
    SecretKey const& secretKey,
    std::uint32_t tokenSequence,
    bool revoked)
    : keyType_ (keyType)
    , secretKey_ (secretKey)
    , tokenSequence_ (tokenSequence)
    , revoked_ (revoked)
{
    publicKey_ = derivePublicKey(keyType_, secretKey_);
}

ValidatorKeys
ValidatorKeys::make_ValidatorKeys (
    boost::filesystem::path const& keyFile)
{
    std::ifstream ifsKeys (keyFile.c_str (), std::ios::in);

    if (! ifsKeys)
        throw std::runtime_error (
            "Failed to open key file: " + keyFile.string());

    Json::Reader reader;
    Json::Value jKeys;
    if (! reader.parse (ifsKeys, jKeys))
    {
        throw std::runtime_error (
            "Unable to parse json key file: " + keyFile.string());
    }

    static std::array<std::string, 4> const requiredFields {{
        "key_type",
        "secret_key",
        "token_sequence",
        "revoked"
    }};

    for (auto field : requiredFields)
    {
        if (! jKeys.isMember(field))
        {
            throw std::runtime_error (
                "Key file '" + keyFile.string() +
                "' is missing \"" + field + "\" field");
        }
    }

    auto const keyType = keyTypeFromString (jKeys["key_type"].asString());
    if (!keyType)
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid \"key_type\" field: " +
            jKeys["key_type"].toStyledString());
    }

    auto const secret = parseBase58<SecretKey> (
        TokenType::NodePrivate, jKeys["secret_key"].asString());

    if (! secret)
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid \"secret_key\" field: " +
            jKeys["secret_key"].toStyledString());
    }

    std::uint32_t tokenSequence;
    try {
        if (! jKeys["token_sequence"].isIntegral())
            throw std::runtime_error ("");

        tokenSequence = jKeys["token_sequence"].asUInt();
    }
    catch (std::runtime_error&)
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid \"token_sequence\" field: " +
            jKeys["token_sequence"].toStyledString());
    }

    if (! jKeys["revoked"].isBool())
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid \"revoked\" field: " +
            jKeys["revoked"].toStyledString());

    ValidatorKeys vk(
        *keyType, *secret, tokenSequence, jKeys["revoked"].asBool());

    if (jKeys.isMember("domain"))
    {
        if (! jKeys["domain"].isString())
            throw std::runtime_error (
                "Key file '" + keyFile.string() +
                "' contains invalid \"domain\" field: " +
                jKeys["domain"].toStyledString());

        vk.domain(jKeys["domain"].asString());
    }

    if (jKeys.isMember("manifest"))
    {
        if (! jKeys["manifest"].isString())
            throw std::runtime_error (
                "Key file '" + keyFile.string() +
                "' contains invalid \"manifest\" field: " +
                jKeys["manifest"].toStyledString());

        auto ret = strUnHex (jKeys["manifest"].asString());

        if (!ret || ret->size() == 0)
            throw std::runtime_error (
                "Key file '" + keyFile.string() +
                "' contains invalid \"manifest\" field: " +
                jKeys["manifest"].toStyledString());

        vk.manifest_.clear();
        vk.manifest_.reserve(ret->size());
        std::copy(ret->begin(), ret->end(),
            std::back_inserter(vk.manifest_));
    }

    return vk;
}

void
ValidatorKeys::writeToFile (
    boost::filesystem::path const& keyFile) const
{
    using namespace boost::filesystem;

    Json::Value jv;
    jv["key_type"] = to_string(keyType_);
    jv["public_key"] = toBase58(TokenType::NodePublic, publicKey_);
    jv["secret_key"] = toBase58(TokenType::NodePrivate, secretKey_);
    jv["token_sequence"] = Json::UInt (tokenSequence_);
    jv["revoked"] = revoked_;
    if (!domain_.empty())
        jv["domain"] = domain_;
    if (!manifest_.empty())
        jv["manifest"] = strHex(makeSlice(manifest_));

    if (! keyFile.parent_path().empty())
    {
        boost::system::error_code ec;
        if (! exists (keyFile.parent_path()))
            boost::filesystem::create_directories(keyFile.parent_path(), ec);

        if (ec || ! is_directory (keyFile.parent_path()))
            throw std::runtime_error ("Cannot create directory: " +
                    keyFile.parent_path().string());
    }

    std::ofstream o (keyFile.string (), std::ios_base::trunc);
    if (o.fail())
        throw std::runtime_error ("Cannot open key file: " +
            keyFile.string());

    o << jv.toStyledString();
}

boost::optional<ValidatorToken>
ValidatorKeys::createValidatorToken (
    KeyType const& keyType)
{
    if (revoked () ||
            std::numeric_limits<std::uint32_t>::max () - 1 <= tokenSequence_)
        return boost::none;

    ++tokenSequence_;

    auto const tokenSecret = generateSecretKey (keyType, randomSeed ());
    auto const tokenPublic = derivePublicKey(keyType, tokenSecret);

    STObject st(sfGeneric);
    st[sfSequence] = tokenSequence_;
    st[sfPublicKey] = publicKey_;
    st[sfSigningPubKey] = tokenPublic;

    if (!domain_.empty())
        st[sfDomain] = makeSlice(domain_);

    ripple::sign(st, HashPrefix::manifest, keyType, tokenSecret);
    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_, sfMasterSignature);

    Serializer s;
    st.add(s);

    manifest_.clear();
    manifest_.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(manifest_));

    return ValidatorToken {
        ripple::base64_encode(manifest_.data(), manifest_.size()), tokenSecret };
}

std::string
ValidatorKeys::revoke ()
{
    revoked_ = true;

    STObject st(sfGeneric);
    st[sfSequence] = std::numeric_limits<std::uint32_t>::max ();
    st[sfPublicKey] = publicKey_;

    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_, sfMasterSignature);

    Serializer s;
    st.add(s);

    manifest_.clear();
    manifest_.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(manifest_));

    return ripple::base64_encode(manifest_.data(), manifest_.size());
}

std::string
ValidatorKeys::sign (std::string const& data) const
{
    return strHex(ripple::sign (publicKey_, secretKey_, makeSlice (data)));
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
            throw std::runtime_error (
                "The domain must be between 4 and 128 characters long.");

        // This regular expression should do a decent job of weeding out
        // obviously wrong domain names but it isn't perfect. It does not
        // really support IDNs. If this turns out to be an issue, a more
        // thorough regex can be used or this check can just be removed.
        static boost::regex const re(
                "^"                     // Beginning of line
                "("                     // Hostname or domain name
                "(?!-)"                 //  - must not begin with '-'
                "[a-zA-Z0-9-]{1,63}"    //  - only alphanumeric and '-'
                "(?<!-)"                //  - must not end with '-'
                "\\."                   // segment separator
                ")+"                    // 1 or more segments
                "[A-Za-z]{2,63}"        // TLD
                "$"                     // End of line
            , boost::regex_constants::optimize);

        if (!boost::regex_match(d, re))
            throw std::runtime_error (
                "The domain field must use the '[host.][subdomain.]domain.tld' format");
    }

    domain_ = std::move(d);
}

} // ripple
