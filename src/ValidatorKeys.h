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

#include <ripple/crypto/KeyType.h>
#include <ripple/protocol/SecretKey.h>

namespace boost
{
namespace filesystem
{
class path;
}
}

namespace ripple {

struct ValidatorToken
{
    std::string const manifest;
    SecretKey const secretKey;

    /// Returns base64-encoded JSON object
    std::string toString () const;
};

class ValidatorKeys
{
private:
    KeyType keyType_;
    PublicKey publicKey_;
    SecretKey secretKey_;
    std::uint32_t tokenSequence_;
    bool revoked_;

public:
    explicit
    ValidatorKeys (
        KeyType const& keyType);

    ValidatorKeys (
        KeyType const& keyType,
        SecretKey const& secretKey,
        std::uint32_t sequence,
        bool revoked = false);

    /** Returns ValidatorKeys constructed from JSON file

        @param keyFile Path to JSON key file

        @throws std::runtime_error if file content is invalid
    */
    static ValidatorKeys make_ValidatorKeys(
        boost::filesystem::path const& keyFile);

    ~ValidatorKeys () = default;
    ValidatorKeys(ValidatorKeys const&) = default;
    ValidatorKeys& operator=(ValidatorKeys const&) = default;

    inline bool
    operator==(ValidatorKeys const& rhs) const
    {
        // TODO Compare secretKey_
        return revoked_ == rhs.revoked_ &&
            keyType_ == rhs.keyType_ &&
            tokenSequence_ == rhs.tokenSequence_ &&
            publicKey_ == rhs.publicKey_;
    }

    /** Write keys to JSON file

        @param keyFile Path to file to write

        @note Overwrites existing key file

        @throws std::runtime_error if unable to create parent directory
    */
    void
    writeToFile (boost::filesystem::path const& keyFile) const;

    /** Returns validator token for current sequence

        @param keyType Key type for the token keys
    */
    boost::optional<ValidatorToken>
    createValidatorToken (KeyType const& keyType = KeyType::secp256k1);

    /** Revokes validator keys

        @return base64-encoded key revocation
    */
    std::string
    revoke ();

    /** Signs string with validator key

    @papam data String to sign

    @return hex-encoded signature
    */
    std::string
    sign (std::string const& data);

    /** Returns the public key. */
    PublicKey const&
    publicKey () const
    {
        return publicKey_;
    }

    /** Returns true if keys are revoked. */
    bool
    revoked () const
    {
        return revoked_;
    }
};

} // ripple
