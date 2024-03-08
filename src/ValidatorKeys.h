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

#include <ripple/protocol/KeyType.h>
#include <ripple/protocol/SecretKey.h>
#include <boost/optional.hpp>
#include <cstdint>
#include <string>
#include <vector>

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

    // struct used to contain both public and secret keys
    struct Keys {
        PublicKey publicKey;
        SecretKey secretKey;

        Keys() = delete;
        Keys(std::pair<PublicKey, SecretKey> p)
          : publicKey(p.first), secretKey(p.second) {}
    };

    std::vector<std::uint8_t> manifest_;
    std::uint32_t tokenSequence_;
    bool revoked_;
    std::string domain_;
    Keys keys_;

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

    inline bool operator==(ValidatorKeys const &rhs) const {
        return revoked_ == rhs.revoked_ && keyType_ == rhs.keyType_ &&
             tokenSequence_ == rhs.tokenSequence_ &&
             keys_.publicKey == rhs.keys_.publicKey &&
             keys_.secretKey == rhs.keys_.secretKey;
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
    sign (std::string const& data) const;

    /** Returns the public key. */
    PublicKey const& publicKey() const
    {
        return keys_.publicKey;
    }

    /** Returns true if keys are revoked. */
    bool
    revoked () const
    {
        return revoked_;
    }

    /** Returns the domain associated with this key, if any */
    std::string
    domain() const
    {
        return domain_;
    }

    /** Sets the domain associated with this key */
    void domain(std::string d);

    /** Returns the last manifest we generated for this domain, if available. */
    std::vector<std::uint8_t> manifest() const
    {
        return manifest_;
    }

    /** Returns the sequence number of the last manifest generated. */
    std::uint32_t sequence() const
    {
        return tokenSequence_;
    }
};

} // ripple
