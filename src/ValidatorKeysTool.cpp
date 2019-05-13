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

#include <ValidatorKeysTool.h>
#include <ValidatorKeys.h>
#include <ripple/beast/core/PlatformConfig.h>
#include <ripple/beast/core/SemanticVersion.h>
#include <ripple/beast/unit_test.h>
#include <beast/unit_test/dstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>
#ifdef BOOST_MSVC
# ifndef WIN32_LEAN_AND_MEAN // VC_EXTRALEAN
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  undef WIN32_LEAN_AND_MEAN
# else
#  include <windows.h>
# endif
#endif

//------------------------------------------------------------------------------
char const* const versionString =

    //--------------------------------------------------------------------------
    //  The build version number. You must edit this for each release
    //  and follow the format described at http://semver.org/
    //
        "0.2.1"

#if defined(DEBUG) || defined(SANITIZER)
       "+"
#ifdef DEBUG
        "DEBUG"
#ifdef SANITIZER
        "."
#endif
#endif

#ifdef SANITIZER
        BEAST_PP_STR1_(SANITIZER)
#endif
#endif

    //--------------------------------------------------------------------------
    ;

static int runUnitTests ()
{
    using namespace beast::unit_test;
    beast::unit_test::dstream dout{std::cout};
    reporter r{dout};
    bool const anyFailed = r.run_each(global_suites());
    if(anyFailed)
        return EXIT_FAILURE;    //LCOV_EXCL_LINE
    return EXIT_SUCCESS;
}

void createKeyFile (boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (exists (keyFile))
        throw std::runtime_error (
            "Refusing to overwrite existing key file: " +
                keyFile.string ());

    ValidatorKeys const keys (KeyType::ed25519);
    keys.writeToFile (keyFile);

    std::cout << "Validator keys stored in " <<
        keyFile.string() <<
        "\n\nThis file should be stored securely and not shared.\n\n";
}

void createToken (boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys (keyFile);

    if (keys.revoked ())
        throw std::runtime_error (
            "Validator keys have been revoked.");

    auto const token = keys.createValidatorToken ();

    if (! token)
        throw std::runtime_error (
            "Maximum number of tokens have already been generated.\n"
            "Revoke validator keys if previous token has been compromised.");

    // Update key file with new token sequence
    keys.writeToFile (keyFile);

    std::cout << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: " <<
        toBase58 (TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_token]\n";

    auto const tokenStr = token->toString();
    auto const len = 72;
    for (auto i = 0; i < tokenStr.size(); i += len)
        std::cout << tokenStr.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void createRevocation (boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys (keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have already been revoked!\n\n";
    else
        std::cout << "WARNING: This will revoke your validator keys!\n\n";

    auto const revocation = keys.revoke ();

    // Update key file with new token sequence
    keys.writeToFile (keyFile);

    std::cout << "Update rippled.cfg file with these values and restart rippled:\n\n";
    std::cout << "# validator public key: " <<
        toBase58 (TokenType::NodePublic, keys.publicKey()) << "\n\n";
    std::cout << "[validator_key_revocation]\n";

    auto const len = 72;
    for (auto i = 0; i < revocation.size(); i += len)
        std::cout << revocation.substr(i, len) << std::endl;

    std::cout << std::endl;
}

void signData (std::string const& data,
    boost::filesystem::path const& keyFile)
{
    using namespace ripple;

    if (data.empty())
        throw std::runtime_error (
            "Syntax error: Must specify data string to sign");

    auto keys = ValidatorKeys::make_ValidatorKeys (keyFile);

    if (keys.revoked())
        std::cout << "WARNING: Validator keys have been revoked!\n\n";

    std::cout << keys.sign (data) << std::endl;
    std::cout << std::endl;
}

int runCommand (std::string const& command,
    std::vector <std::string> const& args,
    boost::filesystem::path const& keyFile)
{
    using namespace std;

    static map<string, vector<string>::size_type> const commandArgs = {
        { "create_keys", 0 },
        { "create_token", 0 },
        { "revoke_keys", 0 },
        { "sign", 1 }};

    auto const iArgs = commandArgs.find (command);

    if (iArgs == commandArgs.end ())
        throw std::runtime_error ("Unknown command: " + command);

    if (args.size() != iArgs->second)
        throw std::runtime_error ("Syntax error: Wrong number of arguments");

    if (command == "create_keys")
        createKeyFile (keyFile);
    else if (command == "create_token")
        createToken (keyFile);
    else if (command == "revoke_keys")
        createRevocation (keyFile);
    else if (command == "sign")
        signData (args[0], keyFile);

    return 0;
}

//LCOV_EXCL_START
static
std::string
getEnvVar (char const* name)
{
    std::string value;

    auto const v = getenv (name);

    if (v != nullptr)
        value = v;

    return value;
}

void printHelp (const boost::program_options::options_description& desc)
{
    std::cerr
        << "validator-keys [options] <command> [<argument> ...]\n"
        << desc << std::endl
        << "Commands: \n"
           "     create_keys        Generate validator keys.\n"
           "     create_token       Generate validator token.\n"
           "     revoke_keys        Revoke validator keys.\n"
           "     sign <data>        Sign string with validator key.\n";
}
//LCOV_EXCL_STOP

std::string const&
getVersionString ()
{
    static std::string const value = [] {
        std::string const s = versionString;
        beast::SemanticVersion v;
        if (!v.parse (s) || v.print () != s)
            throw std::logic_error (s + ": Bad version string"); //LCOV_EXCL_LINE
        return s;
    }();
    return value;
}

int main (int argc, char** argv)
{
#if defined(__GNUC__) && !defined(__clang__)
    auto constexpr gccver = (__GNUC__ * 100 * 100) +
                            (__GNUC_MINOR__ * 100) +
                            __GNUC_PATCHLEVEL__;

    static_assert (gccver >= 50100,
        "GCC version 5.1.0 or later is required to compile validator-keys.");
#endif

    static_assert (BOOST_VERSION >= 105700,
        "Boost version 1.57 or later is required to compile validator-keys");

    namespace po = boost::program_options;

    po::variables_map vm;

    // Set up option parsing.
    //
    po::options_description general ("General Options");
    general.add_options ()
    ("help,h", "Display this message.")
    ("keyfile", po::value<std::string> (), "Specify the key file.")
    ("unittest,u", "Perform unit tests.")
    ("version", "Display the build version.")
    ;

    po::options_description hidden("Hidden options");
    hidden.add_options()
    ("command", po::value< std::string > (), "Command.")
    ("arguments",po::value< std::vector<std::string> > ()->default_value(
        std::vector <std::string> (), "empty"), "Arguments.")
    ;
    po::positional_options_description p;
    p.add ("command", 1).add ("arguments", -1);

    po::options_description cmdline_options;
    cmdline_options.add(general).add(hidden);

    // Parse options, if no error.
    try
    {
        po::store (po::command_line_parser (argc, argv)
            .options (cmdline_options)    // Parse options.
            .positional (p)
            .run (),
            vm);
        po::notify (vm);                  // Invoke option notify functions.
    }
    //LCOV_EXCL_START
    catch (std::exception const&)
    {
        std::cerr << "validator-keys: Incorrect command line syntax." << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return EXIT_FAILURE;
    }
    //LCOV_EXCL_STOP

    // Run the unit tests if requested.
    // The unit tests will exit the application with an appropriate return code.
    if (vm.count ("unittest"))
        return runUnitTests();

    //LCOV_EXCL_START
    if (vm.count ("version"))
    {
        std::cout << "validator-keys version " <<
            getVersionString () << std::endl;
        return 0;
    }

    if (vm.count ("help") || ! vm.count ("command"))
    {
        printHelp (general);
        return EXIT_SUCCESS;
    }

    std::string const homeDir = getEnvVar ("HOME");
    std::string const defaultKeyFile =
        (homeDir.empty () ?
            boost::filesystem::current_path ().string () : homeDir) +
        "/.ripple/validator-keys.json";

    try
    {
        using namespace boost::filesystem;
        path keyFile = vm.count ("keyfile") ?
            vm["keyfile"].as<std::string> () :
            defaultKeyFile;

        return runCommand (
            vm["command"].as<std::string>(),
            vm["arguments"].as<std::vector<std::string>>(),
            keyFile);
    }
    catch(std::exception const& e)
    {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
    //LCOV_EXCL_STOP
}
