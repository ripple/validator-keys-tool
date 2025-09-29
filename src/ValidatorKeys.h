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

#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/SecretKey.h>

#include <boost/optional.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace boost {
namespace filesystem {
class path;
}
}  // namespace boost

namespace ripple {

struct ValidatorToken
{
    std::string const manifest;
    SecretKey const secretKey;

    /// Returns base64-encoded JSON object
    std::string
    toString() const;
};

class ValidatorKeys
{
private:
    // struct used to contain both public and secret keys
    struct Keys
    {
        PublicKey publicKey;
        // An unseated secretKey indicates that this object requires external
        // signing
        std::optional<SecretKey> secretKey;

        Keys() = delete;
        Keys(std::pair<PublicKey, SecretKey> const& p)
            : publicKey(p.first), secretKey(p.second)
        {
        }
        Keys(PublicKey const& pub) : publicKey(pub), secretKey(std::nullopt)
        {
        }
    };

    KeyType const keyType_;
    Keys const keys_;
    std::vector<std::uint8_t> manifest_;
    std::uint32_t tokenSequence_;
    bool revoked_;
    std::string domain_;
    // The pending fields are mutable so they can be updated
    // in const functions without risking updating anything else.
    // This may not be the best way to do this.
    mutable std::optional<SecretKey> pendingTokenSecret_;
    mutable std::optional<KeyType> pendingKeyType_;

public:
    explicit ValidatorKeys(KeyType const& keyType);

    ValidatorKeys(
        KeyType const& keyType,
        SecretKey const& secretKey,
        std::uint32_t tokenSequence,
        bool revoked = false);

    /** Special case: Create only with a PublicKey, which implies
        that the SecretKey is stored and used externally. The file
        will be written with "secret_key: external"
    */
    ValidatorKeys(
        KeyType const& keyType,
        PublicKey const& publicKey,
        std::uint32_t tokenSequence = 0,
        bool revoked = false);

    /** Returns ValidatorKeys constructed from JSON file

        @param keyFile Path to JSON key file

        @throws std::runtime_error if file content is invalid
    */
    static ValidatorKeys
    make_ValidatorKeys(boost::filesystem::path const& keyFile);

    ~ValidatorKeys() = default;
    ValidatorKeys(ValidatorKeys const&) = default;
    ValidatorKeys&
    operator=(ValidatorKeys const&) = delete;

    inline bool
    operator==(ValidatorKeys const& rhs) const
    {
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
    writeToFile(boost::filesystem::path const& keyFile) const;

    /** Returns validator token for current sequence

        @param keyType Key type for the token keys
    */
    boost::optional<ValidatorToken>
    createValidatorToken(KeyType const& keyType = KeyType::secp256k1);

    /** Returns partial validator token for current sequence

        @param keyType Key type for the token keys
    */
    boost::optional<std::string>
    startValidatorToken(KeyType const& keyType = KeyType::secp256k1) const;

    /** Returns validator token for current sequence

        @param masterSig Master signature
    */
    boost::optional<ValidatorToken>
    finishToken(Blob const& masterSig);

    /** Revokes validator keys

        @return base64-encoded key revocation
    */
    std::string
    revoke();

    /** Returns partial revocation token

        @param keyType Key type for the token keys
    */
    std::string
    startRevoke() const;

    /** Returns full revocation token

        @param masterSig Master signature
    */
    std::string
    finishRevoke(Blob const& masterSig);

    /** Signs string with validator key

    @papam data String to sign

    @return hex-encoded signature
    */
    std::string
    sign(std::string const& data) const;

    /** Signs hex-encoded string with validator key

    @papam data Hex string to sign. Will be decoded to raw bytes for signing.

    @return hex-encoded signature
    */
    std::string
    signHex(std::string data) const;

    /** Returns the public key. */
    PublicKey const&
    publicKey() const
    {
        return keys_.publicKey;
    }

    /** Returns true if keys are revoked. */
    bool
    revoked() const
    {
        return revoked_;
    }

    /** Returns the domain associated with this key, if any */
    std::string const&
    domain() const
    {
        return domain_;
    }

    /** Sets the domain associated with this key */
    void
    domain(std::string d);

    // Throws if the manifest is malformed or not signed correctly.
    void
    verifyManifest() const;

    /** Returns the last manifest we generated for this domain, if available. */
    std::vector<std::uint8_t>
    manifest() const
    {
        if (!manifest_.empty())
            verifyManifest();

        return manifest_;
    }

    /** Returns the sequence number of the last manifest generated. */
    std::uint32_t
    sequence() const
    {
        return tokenSequence_;
    }

private:
    void
    setManifest(STObject const& st);
};

}  // namespace ripple
