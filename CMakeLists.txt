cmake_minimum_required(VERSION 3.11)
project(validator-keys-tool)

#[===========================================[
  The tool depends on the libxrpl
  library which is defined by the rippled
  project. This looks for installed rippled
  libs and, if not found, pulls them in with
  FetchContent.
#]===========================================]
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

get_directory_property(has_parent PARENT_DIRECTORY)

if(NOT has_parent)
  find_package(xrpl REQUIRED)
endif()

include(KeysSanity)
include(KeysCov)
include(KeysInterface)

add_executable(validator-keys
  src/ValidatorKeys.cpp
  src/ValidatorKeysTool.cpp
  # UNIT TESTS:
  src/test/ValidatorKeys_test.cpp
  src/test/ValidatorKeysTool_test.cpp)
target_include_directories(validator-keys PRIVATE src)
target_link_libraries(validator-keys xrpl::libxrpl Keys::opts)

if(has_parent)
  set_target_properties(validator-keys PROPERTIES EXCLUDE_FROM_ALL ON)
  set_target_properties(validator-keys PROPERTIES EXCLUDE_FROM_DEFAULT_BUILD ON)
endif()

include(CTest)
if(BUILD_TESTING)
  add_test(test validator-keys --unittest)
endif()
