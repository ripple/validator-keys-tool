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
#include <boost/filesystem.hpp>
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

    return ValidatorKeys (
        *keyType, *secret, tokenSequence, jKeys["revoked"].asBool());
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

    ripple::sign(st, HashPrefix::manifest, keyType, tokenSecret);

    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_,
        sfMasterSignature);

    Serializer s;
    st.add(s);

    std::string m (static_cast<char const*> (s.data()), s.size());
    return ValidatorToken {
        ripple::base64_encode(m), tokenSecret };
}

std::string
ValidatorKeys::revoke ()
{
    revoked_ = true;

    STObject st(sfGeneric);
    st[sfSequence] = std::numeric_limits<std::uint32_t>::max ();
    st[sfPublicKey] = publicKey_;

    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_,
        sfMasterSignature);

    Serializer s;
    st.add(s);

    std::string m (static_cast<char const*> (s.data()), s.size());
    return ripple::base64_encode(m);
}

std::string
ValidatorKeys::sign (std::string const& data)
{
    return strHex(ripple::sign (publicKey_, secretKey_, makeSlice (data)));
}

} // ripple
