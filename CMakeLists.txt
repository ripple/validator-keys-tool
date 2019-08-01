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
  message(STATUS "Installed rippled not found...using local FC")
  include (FetchContent)
  FetchContent_Declare(
    rippled_src
    GIT_REPOSITORY https://github.com/ripple/rippled.git
    GIT_TAG "1.3.1"
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

