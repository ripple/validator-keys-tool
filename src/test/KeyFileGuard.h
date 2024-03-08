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

#include <ripple/beast/unit_test.h>
#include <boost/filesystem.hpp>
#include <fstream>

namespace ripple {

/**
   Write a key file dir and remove when done.
 */
class KeyFileGuard
{
private:
    using path = boost::filesystem::path;
    path subDir_;
    beast::unit_test::suite& test_;

    auto
    rmDir(path const& toRm)
    {
        if (is_directory(toRm))
            remove_all(toRm);
        else
            test_.log << "Expected " << toRm.string()
                      << " to be an existing directory." << std::endl;
    };

public:
    KeyFileGuard(beast::unit_test::suite& test, std::string const& subDir)
        : subDir_(subDir), test_(test)
    {
        using namespace boost::filesystem;

        if (!exists(subDir_))
            create_directory(subDir_);
        else
            // Cannot run the test. Someone created a file or directory
            // where we want to put our directory
            throw std::runtime_error(
                "Cannot create directory: " + subDir_.string());
    }
    ~KeyFileGuard()
    {
        try
        {
            using namespace boost::filesystem;

            rmDir(subDir_);
        }
        catch (std::exception& e)
        {
            // if we throw here, just let it die.
            test_.log << "Error in ~KeyFileGuard: " << e.what() << std::endl;
        };
    }
};

}  // namespace ripple
