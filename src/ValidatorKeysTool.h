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

#include <boost/optional.hpp>

#include <vector>

namespace boost {
namespace filesystem {
class path;
}
}  // namespace boost

std::string const&
getVersionString();

void
createKeyFile(boost::filesystem::path const& keyFile);

void
createToken(boost::filesystem::path const& keyFile);

void
createRevocation(boost::filesystem::path const& keyFile);

/*****************************************/
/* External signing support              */
void
createExternal(std::string const& data, boost::filesystem::path const& keyFile);

void
startToken(boost::filesystem::path const& keyFile);

void
finishToken(std::string const& data, boost::filesystem::path const& keyFile);

void
startRevocation(boost::filesystem::path const& keyFile);

void
finishRevocation(
    std::string const& data,
    boost::filesystem::path const& keyFile);

/*****************************************/

void
signData(std::string const& data, boost::filesystem::path const& keyFile);

void
signHexData(std::string const& data, boost::filesystem::path const& keyFile);

int
runCommand(
    std::string const& command,
    std::vector<std::string> const& arg,
    boost::filesystem::path const& keyFile);
