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
