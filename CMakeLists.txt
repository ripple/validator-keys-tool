cmake_minimum_required (VERSION 3.11)
project (validator-keys-tool)

#[===========================================[
  The signer exe depends on the xrpl_core
  library which is defined by the rippled
  project. This looks for installed rippled
  libs and, if not found, pulls them in with
  FetchContent.
#]===========================================]
find_package(Ripple QUIET)

if (NOT TARGET Ripple::xrpl_core)
  # rippled_tag is cache string and can be overriden when configuring
  # with -Drippled_tag=commit_or_tag in order to pick a specific
  # rippled version to download. Default tag/version is the
  # value here:
  set (rippled_tag "1.2.4" CACHE STRING
    "tag/commit of rippled to fetch from \
    if a local install is not found")
  message(STATUS "Installed rippled not found... \
    using local copy from tag/commit [${rippled_tag}]")
  include (FetchContent)
  FetchContent_Declare(
    rippled_src
    GIT_REPOSITORY https://github.com/ripple/rippled.git
    GIT_TAG ${rippled_tag}
  )
  FetchContent_GetProperties(rippled_src)
  if(NOT rippled_src_POPULATED)
    message (STATUS "Pausing to download rippled source...")
    FetchContent_Populate(rippled_src)
  endif()
  add_subdirectory(${rippled_src_SOURCE_DIR} xrpl_core)
endif ()

add_executable (validator-keys
  src/ValidatorKeys.cpp
  src/ValidatorKeysTool.cpp
  ## UNIT TESTS:
  src/test/ValidatorKeys_test.cpp
  src/test/ValidatorKeysTool_test.cpp)
target_include_directories (validator-keys PRIVATE src)
target_link_libraries (validator-keys Ripple::xrpl_core)

