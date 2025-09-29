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
#include <ValidatorKeysTool.h>

#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/base64.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/core/SemanticVersion.h>
#include <xrpl/beast/unit_test.h>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/program_options.hpp>

//------------------------------------------------------------------------------
//  The build version number. You must edit this for each release
//  and follow the format described at http://semver.org/
//--------------------------------------------------------------------------
char const* const versionString =
    "0.4.0"

#if defined(DEBUG) || defined(SANITIZER)
    "+"
#ifdef DEBUG
    "DEBUG"
#ifdef SANITIZER
    "."
#endif
#endif

#ifdef SANITIZER
    BOOST_PP_STRINGIZE(SANITIZER)
#endif
#endif

    //--------------------------------------------------------------------------
    ;

static int
runUnitTests()
{
    using namespace beast::unit_test;
    reporter r;
    bool const anyFailed = r.run_each(global_suites());
    if (anyFailed)
        return EXIT_FAILURE;  // LCOV_EXCL_LINE
    return EXIT_SUCCESS;
}

void
createKeyFile(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (exists(keyFile))
        throw std::runtime_error(
            "Refusing to overwrite existing key file: " + keyFile.string());

    ValidatorKeys const keys(KeyType::ed25519);
    keys.writeToFile(keyFile);

    std::cout << "Validator keys stored in " << keyFile.string()
              << "\n\nThis file should be stored securely and not shared.\n\n";
}

void
createExternal(std::string const& data, boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (exists(keyFile))
        throw std::runtime_error(
            "Refusing to overwrite existing key file: " + keyFile.string());

    auto const pkInfo = [&]() {
        if (auto const unBase58 =
                parseBase58<PublicKey>(TokenType::NodePublic, data))
            // parseBase58 checks but does not return the key type, so it's safe
            // to dereference the function result.
            return std::make_pair(*publicKeyType(*unBase58), *unBase58);

        if (auto const unHex = strUnHex(data))
        {
            auto const slice = makeSlice(*unHex);
            if (auto const pkType = publicKeyType(slice))
                return std::make_pair(*pkType, PublicKey(slice));
        }

        {
            auto const unBase64 = base64_decode(data);
            auto const slice = makeSlice(unBase64);
            if (auto const pkType = publicKeyType(slice))
                return std::make_pair(*pkType, PublicKey(slice));
        }

        throw std::runtime_error("Unable to parse public key: " + data);
    }();

    ValidatorKeys const keys(pkInfo.first, pkInfo.second);
    keys.writeToFile(keyFile);

    std::cout << "Validator keys stored in " << keyFile.string()
              << "\n\nThis file should be stored securely and not shared.\n\n";
}

void
createToken(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        throw std::runtime_error("Validator keys have been revoked.");

    auto const token = keys.createValidatorToken();

    if (!token)
        throw std::runtime_error(
            "Maximum number of tokens have already been generated.\n"
            "Revoke validator keys if previous token has been compromised.");

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout
        << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: "
              << toBase58(TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_token]\n";

    auto const tokenStr = token->toString();
    auto const len = 72;
    for (auto i = 0; i < tokenStr.size(); i += len)
        std::cout << tokenStr.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void
startToken(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        throw std::runtime_error("Validator keys have been revoked.");

    auto const token = keys.startValidatorToken();

    if (!token)
        throw std::runtime_error(
            "Maximum number of tokens have already been generated.\n"
            "Revoke validator keys if previous token has been compromised.");

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout << *token << std::endl;

    std::cout << std::endl;
}

/// Master signature input can be provided as hex- or base64-encoded. There is
/// no structural way to check that it is valid other than trying to use it, so
/// if the decoding succeeds, proceed.
ripple::Blob
decodeMasterSignature(std::string const& data)
{
    using namespace ripple;
    if (auto const unHex = strUnHex(data))
    {
        return *unHex;
    }

    // base64_decode will decode as far as it can, and return partial data if
    // the input is not valid. To ensure the input is valid, encode the result
    // and check that they match. This is not the fastest possible way to check,
    // but this app runs in human time scales, so it's ok.
    if (auto const unBase64 = base64_decode(data);
        base64_encode(unBase64) == data)
    {
        return Blob(unBase64.begin(), unBase64.end());
    }

    throw std::runtime_error("Invalid master signature");
}

void
finishToken(std::string const& data, boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        throw std::runtime_error("Validator keys have been revoked.");

    auto const masterSig = decodeMasterSignature(data);

    auto const token = keys.finishToken(masterSig);

    if (!token)
        throw std::runtime_error(
            "Maximum number of tokens have already been generated.\n"
            "Revoke validator keys if previous token has been compromised.");

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout
        << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: "
              << toBase58(TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_token]\n";

    auto const tokenStr = token->toString();
    auto const len = 72;
    for (auto i = 0; i < tokenStr.size(); i += len)
        std::cout << tokenStr.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void
createRevocation(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have already been revoked!\n\n";
    else
        std::cout << "WARNING: This will revoke your validator keys!\n\n";

    auto const revocation = keys.revoke();

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout
        << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: "
              << toBase58(TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_key_revocation]\n";

    auto const len = 72;
    for (auto i = 0; i < revocation.size(); i += len)
        std::cout << revocation.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void
startRevocation(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        std::cerr << "WARNING: Validator keys have already been revoked!\n\n";
    else
        std::cerr << "WARNING: This will revoke your validator keys!\n\n";

    auto const revocation = keys.startRevoke();

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout << revocation << std::endl;

    std::cout << std::endl;
}

void
finishRevocation(
    std::string const& data,
    boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have already been revoked!\n\n";
    else
        std::cout << "WARNING: This will revoke your validator keys!\n\n";

    auto const masterSig = decodeMasterSignature(data);

    auto const revocation = keys.finishRevoke(masterSig);

    // Update key file with new token sequence
    keys.writeToFile(keyFile);

    std::cout
        << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: "
              << toBase58(TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_key_revocation]\n";

    auto const len = 72;
    for (auto i = 0; i < revocation.size(); i += len)
        std::cout << revocation.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void
attestDomain(ripple::ValidatorKeys const& keys)
{
    using namespace ripple;

    if (keys.domain().empty())
    {
        std::cout << "No attestation is necessary if no domain is specified!\n";
        std::cout << "If you have an attestation in your xrpl-ledger.toml\n";
        std::cout << "you should remove it at this time.\n";
        return;
    }

    std::cout << "The domain attestation for validator "
              << toBase58(TokenType::NodePublic, keys.publicKey())
              << " is:\n\n";

    std::cout << "attestation=\""
              << keys.sign(
                     "[domain-attestation-blob:" + keys.domain() + ":" +
                     toBase58(TokenType::NodePublic, keys.publicKey()) + "]")
              << "\"\n\n";

    std::cout << "You should include it in your xrp-ledger.toml file in the\n";
    std::cout << "section for this validator.\n";
}

void
attestDomain(boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        throw std::runtime_error(
            "Operation error: The specified master key has been revoked!");

    attestDomain(keys);
}

void
setDomain(std::string const& domain, boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        throw std::runtime_error(
            "Operation error: The specified master key has been revoked!");

    if (domain == keys.domain())
    {
        if (domain.empty())
            std::cout << "The domain name was already cleared!\n";
        else
            std::cout << "The domain name was already set.\n";
        return;
    }

    // Set the domain and generate a new token
    keys.domain(domain);
    auto const token = keys.createValidatorToken();
    if (!token)
        throw std::runtime_error(
            "Maximum number of tokens have already been generated.\n"
            "Revoke validator keys if previous token has been compromised.");

    // Flush to disk
    keys.writeToFile(keyFile);

    if (domain.empty())
        std::cout << "The domain name has been cleared.\n";
    else
        std::cout << "The domain name has been set to: " << domain << "\n\n";
    attestDomain(keys);

    std::cout << "\n";
    std::cout << "You also need to update the rippled.cfg file to add a new\n";
    std::cout << "validator token and restart rippled:\n\n";
    std::cout << "# validator public key: "
              << toBase58(TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_token]\n";

    auto const tokenStr = token->toString();
    auto const len = 72;
    for (auto i = 0; i < tokenStr.size(); i += len)
        std::cout << tokenStr.substr(i, len) << std::endl;

    std::cout << "\n";
}

void
signData(std::string const& data, boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (data.empty())
        throw std::runtime_error(
            "Syntax error: Must specify data string to sign");

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have been revoked!\n\n";

    std::cout << keys.sign(data) << std::endl;
    std::cout << std::endl;
}

void
signHexData(std::string const& data, boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (data.empty())
        throw std::runtime_error(
            "Syntax error: Must specify data string to sign");

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have been revoked!\n\n";

    std::cout << keys.signHex(data) << std::endl;
    std::cout << std::endl;
}

void
generateManifest(
    std::string const& type,
    boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys(keyFile);

    auto const m = keys.manifest();

    if (m.empty())
    {
        std::cout << "The last manifest generated is unavailable. You can\n";
        std::cout << "generate a new one.\n\n";
        return;
    }

    if (type == "base64")
    {
        std::cout << "Manifest #" << keys.sequence() << " (Base64):\n";
        std::cout << base64_encode(m.data(), m.size()) << "\n\n";
        return;
    }

    if (type == "hex")
    {
        std::cout << "Manifest #" << keys.sequence() << " (Hex):\n";
        std::cout << strHex(makeSlice(m)) << "\n\n";
        return;
    }

    std::cout << "Unknown encoding '" << type << "'\n";
}

int
runCommand(
    std::string const& command,
    std::vector<std::string> const& args,
    boost::filesystem::path const& keyFile)
{
    using namespace std;

    static map<string, vector<string>::size_type> const commandArgs = {
        {"create_keys", 0},
        {"create_token", 0},
        {"revoke_keys", 0},
        {"set_domain", 1},
        {"clear_domain", 0},
        {"attest_domain", 0},
        {"show_manifest", 1},
        {"sign", 1},
        {"sign_hex", 1},
        {"create_external", 1},
        {"start_token", 0},
        {"finish_token", 1},
        {"start_revoke_keys", 0},
        {"finish_revoke_keys", 1},
    };

    auto const iArgs = commandArgs.find(command);

    if (iArgs == commandArgs.end())
        throw std::runtime_error("Unknown command: " + command);

    if (args.size() != iArgs->second)
        throw std::runtime_error("Syntax error: Wrong number of arguments");

    if (command == "create_keys")
        createKeyFile(keyFile);
    else if (command == "create_token")
        createToken(keyFile);
    else if (command == "revoke_keys")
        createRevocation(keyFile);
    else if (command == "set_domain")
        setDomain(args[0], keyFile);
    else if (command == "clear_domain")
        setDomain("", keyFile);
    else if (command == "attest_domain")
        attestDomain(keyFile);
    else if (command == "sign")
        signData(args[0], keyFile);
    else if (command == "sign_hex")
        signHexData(args[0], keyFile);
    else if (command == "show_manifest")
        generateManifest(args[0], keyFile);
    else if (command == "create_external")
        createExternal(args[0], keyFile);
    else if (command == "start_token")
        startToken(keyFile);
    else if (command == "finish_token")
        finishToken(args[0], keyFile);
    else if (command == "start_revoke_keys")
        startRevocation(keyFile);
    else if (command == "finish_revoke_keys")
        finishRevocation(args[0], keyFile);

    return 0;
}

// LCOV_EXCL_START
static std::string
getEnvVar(char const* name)
{
    std::string value;

    auto const v = getenv(name);

    if (v != nullptr)
        value = v;

    return value;
}

void
printHelp(const boost::program_options::options_description& desc)
{
    std::cerr
        << "validator-keys [options] <command> [<argument> ...]\n"
        << desc << std::endl
        << "Commands: \n"
           "     create_keys                   Generate validator keys.\n"
           "     create_token                  Generate validator token.\n"
           "     revoke_keys                   Revoke validator keys.\n"
           "     sign <data>                   Sign string with validator "
           "key.\n"
           "     sign_hex <data>               Decode and sign hex string with "
           "validator key.\n"
           "     show_manifest [hex|base64]    Displays the last generated "
           "manifest\n"
           "     set_domain <domain>           Associate a domain with the "
           "validator key.\n"
           "     clear_domain                  Disassociate a domain from a "
           "validator key.\n"
           "     attest_domain                 Produce the attestation string "
           "for a domain.\n"
           "Commands for signing externally: \n"
           "     create_external <public key>  Generate validator keys without "
           "a secret.\n"
           "     start_token                   Generate a partial token for "
           "external signing.\n"
           "     finish_token <sig>            Finish generating token with "
           "external signature.\n"
           "     start_revoke_keys             Generate a partial revocation "
           "for external signing.\n"
           "     finish_revoke_keys <sig>      Finish generating revocation "
           "with external signature.\n";
}
// LCOV_EXCL_STOP

std::string const&
getVersionString()
{
    static std::string const value = [] {
        std::string const s = versionString;
        beast::SemanticVersion v;
        if (!v.parse(s) || v.print() != s)
            throw std::logic_error(
                s + ": Bad version string");  // LCOV_EXCL_LINE
        return s;
    }();
    return value;
}

int
main(int argc, char** argv)
{
    namespace po = boost::program_options;

    po::variables_map vm;

    // Set up option parsing.
    //
    po::options_description general("General Options");
    general.add_options()("help,h", "Display this message.")(
        "keyfile", po::value<std::string>(), "Specify the key file.")(
        "unittest,u", "Perform unit tests.")(
        "version", "Display the build version.");

    po::options_description hidden("Hidden options");
    hidden.add_options()("command", po::value<std::string>(), "Command.")(
        "arguments",
        po::value<std::vector<std::string>>()->default_value(
            std::vector<std::string>(), "empty"),
        "Arguments.");
    po::positional_options_description p;
    p.add("command", 1).add("arguments", -1);

    po::options_description cmdline_options;
    cmdline_options.add(general).add(hidden);

    // Parse options, if no error.
    try
    {
        po::store(
            po::command_line_parser(argc, argv)
                .options(cmdline_options)  // Parse options.
                .positional(p)
                .run(),
            vm);
        po::notify(vm);  // Invoke option notify functions.
    }
    // LCOV_EXCL_START
    catch (std::exception const&)
    {
        std::cerr << "validator-keys: Incorrect command line syntax."
                  << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return EXIT_FAILURE;
    }
    // LCOV_EXCL_STOP

    // Run the unit tests if requested.
    // The unit tests will exit the application with an appropriate return code.
    if (vm.count("unittest"))
        return runUnitTests();

    // LCOV_EXCL_START
    if (vm.count("version"))
    {
        std::cout << "validator-keys version " << getVersionString()
                  << std::endl;
        return 0;
    }

    if (vm.count("help") || !vm.count("command"))
    {
        printHelp(general);
        return EXIT_SUCCESS;
    }

    std::string const homeDir = getEnvVar("HOME");
    std::string const defaultKeyFile =
        (homeDir.empty() ? boost::filesystem::current_path().string()
                         : homeDir) +
        "/.ripple/validator-keys.json";

    try
    {
        using namespace boost::filesystem;
        path keyFile = vm.count("keyfile") ? vm["keyfile"].as<std::string>()
                                           : defaultKeyFile;

        return runCommand(
            vm["command"].as<std::string>(),
            vm["arguments"].as<std::vector<std::string>>(),
            keyFile);
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
    // LCOV_EXCL_STOP
}
