cmake_minimum_required (VERSION 3.11)

project (validator-keys-tool)
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
    find_package(Git)

    if (NOT GIT_FOUND)
      message (FATAL_ERROR "git is required to determine branch name")
    endif ()

    execute_process (COMMAND ${GIT_EXECUTABLE} "rev-parse" "--abbrev-ref" "HEAD"
                     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                     RESULT_VARIABLE _git_exit_code
                     OUTPUT_VARIABLE _branch
                     OUTPUT_STRIP_TRAILING_WHITESPACE
                     ERROR_QUIET)
    if (NOT _git_exit_code EQUAL 0)
      message (WARNING "git command failed - deduced branch might be incorrect")
    endif ()

    # rippled_tag is cache string and can be overriden when configuring
    # with -Drippled_tag=commit_or_tag in order to pick a specific
    # rippled version to download. Default tag is develop/master/release as 
    # determined by the branch of this project
    if (NOT (_branch STREQUAL "master" OR _branch STREQUAL "release"))
      set (rippled_tag "develop" CACHE STRING
        "tag/commit of rippled to fetch from if a local install is not found")
    else ()
      set (rippled_tag "${_branch}" CACHE STRING
        "tag/commit of rippled to fetch from if a local install is not found")
    endif ()
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



