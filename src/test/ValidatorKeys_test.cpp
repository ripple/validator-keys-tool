//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright 2016 Ripple Labs Inc.

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
#include <test/KeyFileGuard.h>
#include <ripple/basics/base64.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>

namespace ripple {

namespace tests {

class ValidatorKeys_test : public beast::unit_test::suite
{
private:

    void
    testKeyFile (boost::filesystem::path const& keyFile,
        Json::Value const& jv, std::string const& expectedError)
    {
        {
            std::ofstream o (keyFile.string (), std::ios_base::trunc);
            o << jv.toStyledString();
            o.close();
        }

        try {
            ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT(expectedError.empty());
        } catch (std::runtime_error& e) {
            BEAST_EXPECT(e.what() == expectedError);
        }
    }

    std::array<KeyType, 2> const keyTypes {{
        KeyType::ed25519,
        KeyType::secp256k1 }};

    void
    testMakeValidatorKeys ()
    {
        testcase ("Make Validator Keys");

        using namespace boost::filesystem;

        std::string const subdir = "test_key_file";
        path const keyFile = subdir / "validator_keys.json";

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys const keys (keyType);

            KeyFileGuard const g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT (exists (keyFile));

            auto const keys2 = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == keys2);
        }
        {
            // Require expected fields
            KeyFileGuard g (*this, subdir);

            auto expectedError =
                "Failed to open key file: " + keyFile.string();
            std::string error;
            try {
                ValidatorKeys::make_ValidatorKeys (keyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            expectedError =
                "Unable to parse json key file: " + keyFile.string();

            {
                std::ofstream o (keyFile.string (), std::ios_base::trunc);
                o << "{{}";
                o.close();
            }

            try {
                ValidatorKeys::make_ValidatorKeys (keyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            Json::Value jv;
            jv["dummy"] = "field";
            expectedError = "Key file '" + keyFile.string() +
                "' is missing \"key_type\" field";
            testKeyFile (keyFile, jv, expectedError);

            jv["key_type"] = "dummy keytype";
            expectedError = "Key file '" + keyFile.string() +
                "' is missing \"secret_key\" field";
            testKeyFile (keyFile, jv, expectedError);

            jv["secret_key"] = "dummy secret";
            expectedError = "Key file '" + keyFile.string() +
                "' is missing \"token_sequence\" field";
            testKeyFile (keyFile, jv, expectedError);

            jv["token_sequence"] = "dummy sequence";
            expectedError = "Key file '" + keyFile.string() +
                "' is missing \"revoked\" field";
            testKeyFile (keyFile, jv, expectedError);

            jv["revoked"] = "dummy revoked";
            expectedError = "Key file '" + keyFile.string() +
                "' contains invalid \"key_type\" field: " +
                jv["key_type"].toStyledString();
            testKeyFile (keyFile, jv, expectedError);

            auto const keyType = KeyType::ed25519;
            jv["key_type"] = to_string(keyType);
            expectedError = "Key file '" + keyFile.string() +
                "' contains invalid \"secret_key\" field: " +
                jv["secret_key"].toStyledString();
            testKeyFile (keyFile, jv, expectedError);

            ValidatorKeys const keys (keyType);
            {
                auto const kp = generateKeyPair (keyType, randomSeed ());
                jv["secret_key"] =
                    toBase58(TokenType::NodePrivate, kp.second);
            }
            expectedError = "Key file '" + keyFile.string() +
                "' contains invalid \"token_sequence\" field: " +
                jv["token_sequence"].toStyledString();
            testKeyFile (keyFile, jv, expectedError);

            jv["token_sequence"] = -1;
            expectedError = "Key file '" + keyFile.string() +
                "' contains invalid \"token_sequence\" field: " +
                jv["token_sequence"].toStyledString();
            testKeyFile (keyFile, jv, expectedError);

            jv["token_sequence"] =
                Json::UInt(std::numeric_limits<std::uint32_t>::max ());
            expectedError = "Key file '" + keyFile.string() +
                "' contains invalid \"revoked\" field: " +
                jv["revoked"].toStyledString();
            testKeyFile (keyFile, jv, expectedError);

            jv["revoked"] = false;
            expectedError = "";
            testKeyFile (keyFile, jv, expectedError);

            jv["revoked"] = true;
            testKeyFile (keyFile, jv, expectedError);
        }
    }

    void
    testCreateValidatorToken ()
    {
        testcase ("Create Validator Token");

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys keys (keyType);
            std::uint32_t sequence = 0;

            for (auto const tokenKeyType : keyTypes)
            {
                auto const token = keys.createValidatorToken (tokenKeyType);

                if(! BEAST_EXPECT(token))
                    continue;

                auto const tokenPublicKey =
                    derivePublicKey(tokenKeyType, token->secretKey);

                STObject st (sfGeneric);
                auto const manifest = ripple::base64_decode(token->manifest);
                SerialIter sit (manifest.data (), manifest.size ());
                st.set (sit);

                auto const seq = get (st, sfSequence);
                BEAST_EXPECT (seq);
                BEAST_EXPECT (*seq == ++sequence);

                auto const tpk = get<PublicKey>(st, sfSigningPubKey);
                BEAST_EXPECT (tpk);
                BEAST_EXPECT (*tpk == tokenPublicKey);
                BEAST_EXPECT (verify (st, HashPrefix::manifest, tokenPublicKey));

                auto const pk = get<PublicKey>(st, sfPublicKey);
                BEAST_EXPECT (pk);
                BEAST_EXPECT (*pk == keys.publicKey ());
                BEAST_EXPECT (verify (
                    st, HashPrefix::manifest, keys.publicKey (),
                    sfMasterSignature));
            }
        }

        auto const keyType = KeyType::ed25519;
        auto const kp = generateKeyPair (keyType, randomSeed ());

        auto keys = ValidatorKeys (
            keyType,
            kp.second,
            std::numeric_limits<std::uint32_t>::max () - 1);

        BEAST_EXPECT (! keys.createValidatorToken (keyType));

        keys.revoke ();
        BEAST_EXPECT (! keys.createValidatorToken (keyType));
    }

    void
    testRevoke ()
    {
        testcase ("Revoke");

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys keys (keyType);

            auto const revocation = keys.revoke ();

            STObject st (sfGeneric);
            auto const manifest = ripple::base64_decode(revocation);
            SerialIter sit (manifest.data (), manifest.size ());
            st.set (sit);

            auto const seq = get (st, sfSequence);
            BEAST_EXPECT (seq);
            BEAST_EXPECT (*seq == std::numeric_limits<std::uint32_t>::max ());

            auto const pk = get (st, sfPublicKey);
            BEAST_EXPECT (pk);
            BEAST_EXPECT (*pk == keys.publicKey ());
            BEAST_EXPECT (verify (
                st, HashPrefix::manifest, keys.publicKey (),
                sfMasterSignature));
        }
    }

    void
    testSign ()
    {
        testcase ("Sign");

        std::map<KeyType, std::string> expected({
            { KeyType::ed25519, "2EE541D6825791BF5454C571D2B363EAB3F01C73159B1F"
                "237AC6D38663A82B9D5EAD262D5F776B916E68247A1F082090F3BAE7ABC939"
                "C8F29B0DC759FD712300" },
            { KeyType::secp256k1, "3045022100F142C27BF83D8D4541C7A4E759DE64A672"
                "51A388A422DFDA6F4B470A2113ABC4022002DA56695F3A805F62B55E7CC8D5"
                "55438D64A229CD0B4BA2AE33402443B20409" }
        });

        std::string const data = "data to sign";

        for (auto const keyType : keyTypes)
        {
            auto const sk = generateSecretKey(keyType, generateSeed("test"));
            ValidatorKeys keys (keyType, sk, 1);

            auto const signature = keys.sign (data);
            BEAST_EXPECT(expected[keyType] == signature);

            auto const ret = strUnHex (signature);
            BEAST_EXPECT (ret.second);
            BEAST_EXPECT (ret.first.size ());
            BEAST_EXPECT (verify (
                keys.publicKey(),
                makeSlice (data),
                makeSlice (ret.first)));
        }
    }

    void
    testWriteToFile ()
    {
        testcase ("Write to File");

        using namespace boost::filesystem;

        auto const keyType = KeyType::ed25519;
        ValidatorKeys keys (keyType);

        {
            std::string const subdir = "test_key_file";
            path const keyFile = subdir / "validator_keys.json";
            KeyFileGuard g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT(exists (keyFile));

            auto fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);

            // Overwrite file with new sequence
            keys.createValidatorToken (KeyType::secp256k1);
            keys.writeToFile (keyFile);

            fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);
        }
        {
            // Write to key file in current relative directory
            path const keyFile = "test_validator_keys.json";
            if (!exists (keyFile))
            {
                keys.writeToFile (keyFile);
                remove (keyFile.string());
            }
            else
            {
                // Cannot run the test. Someone created a file
                // where we want to put our key file
                Throw<std::runtime_error> (
                    "Cannot create key file: " + keyFile.string ());
            }
        }
        {
            // Create key file directory
            std::string const subdir = "test_key_file";
            path const keyFile =
                subdir / "directories/to/create/validator_keys.json";
            KeyFileGuard g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT(exists (keyFile));

            auto const fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);
        }
        {
            // Fail if file cannot be opened for write
            std::string const subdir = "test_key_file";
            KeyFileGuard g (*this, subdir);

            path const badKeyFile = subdir / ".";
            auto expectedError = "Cannot open key file: " + badKeyFile.string();
            std::string error;
            try {
                keys.writeToFile (badKeyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            // Fail if parent directory is existing file
            path const keyFile = subdir / "validator_keys.json";
            keys.writeToFile (keyFile);
            path const conflictingPath =
                keyFile / "validators_keys.json";
            expectedError = "Cannot create directory: " +
                conflictingPath.parent_path().string();
            try {
                keys.writeToFile (conflictingPath);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);
        }
    }

public:
    void
    run() override
    {
        testMakeValidatorKeys ();
        testCreateValidatorToken ();
        testRevoke ();
        testSign ();
        testWriteToFile ();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorKeys, keys, ripple);

} // tests

} // ripple
