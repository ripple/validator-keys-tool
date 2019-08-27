cmake_minimum_required (VERSION 3.9)

#[===========================================[
  The tool depends on the xrpl_core
  library which is defined by the rippled
  project. This looks for installed rippled
  libs and, if not found, pulls them in with
  FetchContent.
#]===========================================]
get_directory_property(has_parent PARENT_DIRECTORY)
if (NOT has_parent)
  project (validator-keys-tool)
  find_package(Ripple QUIET)
  if (NOT TARGET Ripple::xrpl_core)
    message(STATUS "Installed rippled not found...using local FC")
    include (FetchContent)
    FetchContent_Declare(
      rippled_src
      GIT_REPOSITORY https://github.com/ripple/rippled.git
      # this is pre-release 1.4
      GIT_TAG 5834fbbc5d5f7354f2ba4e8426391f8ff112c744
      # TODO:
      # GIT_TAG "1.4.0"
    )
    FetchContent_GetProperties(rippled_src)
    if(NOT rippled_src_POPULATED)
      message (STATUS "Pausing to download rippled source...")
      FetchContent_Populate(rippled_src)
    endif()
    add_subdirectory(${rippled_src_SOURCE_DIR} xrpl_core)
  endif ()
endif ()

add_executable (validator-keys
  src/ValidatorKeys.cpp
  src/ValidatorKeysTool.cpp
  ## UNIT TESTS:
  src/test/ValidatorKeys_test.cpp
  src/test/ValidatorKeysTool_test.cpp)
target_include_directories (validator-keys PRIVATE src)
target_link_libraries (validator-keys Ripple::xrpl_core)

if (has_parent)
  set_target_properties (validator-keys PROPERTIES EXCLUDE_FROM_ALL ON)
  set_target_properties (validator-keys PROPERTIES EXCLUDE_FROM_DEFAULT_BUILD ON)
endif ()



