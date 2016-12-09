cmake_minimum_required(VERSION 3.1.0)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/extras/ripple-libpp/extras/rippled/Builds/CMake")
include(CMakeFuncs)

set(openssl_min 1.0.1)

parse_target()

if (nonunity)
  set(target "" CACHE STRING "Build target. Nounity not supported" FORCE)
  message(FATAL_ERROR "Nonunity builds not supported")
endif()

setup_build_cache()

project(validator-keys)

############################################################

determine_build_type()

check_gcc4_abi()

############################################################

include_directories(
  src/
  SYSTEM
  extras/ripple-libpp/extras/rippled/src
  extras/ripple-libpp/extras/rippled/src/beast/include
  extras/ripple-libpp/extras/rippled/src/beast/extras)

special_build_flags()

############################################################

use_boost(
  filesystem
  program_options
  regex
  system
  thread)

use_pthread()

use_openssl(${openssl_min})

setup_build_boilerplate()

############################################################

add_with_props(lib_src extras/ripple-libpp/src/unity/ripple-libpp.cpp
  -I"${CMAKE_SOURCE_DIR}/"extras/ripple-libpp/extras/rippled/src/secp256k1
  ${no_unused_w}
  )

add_with_props(lib_src extras/ripple-libpp/extras/rippled/src/ripple/unity/ed25519_donna.c
  -I"${CMAKE_SOURCE_DIR}/"extras/ripple-libpp/extras/rippled/src/ed25519-donna)

############################################################

prepend(app_src
  src/
  ValidatorKeys.cpp
  ValidatorKeysTool.cpp
  test/ValidatorKeys_test.cpp
  test/ValidatorKeysTool_test.cpp)

############################################################

if (WIN32 OR is_xcode)
  # Rippled sources
  foreach(curdir
      beast/core
      beast/hash
      beast/utility
      basics
      core
      crypto
      json
      protocol)
    file(GLOB_RECURSE cursrcs extras/ripple-libpp/extras/rippled/src/ripple/${curdir}/*.h
      extras/ripple-libpp/extras/rippled/src/ripple/${curdir}/*.cpp)
    list(APPEND rippled_src "${cursrcs}")
    list(APPEND non_unity_srcs "${cursrcs}")
  endforeach()

  file(GLOB_RECURSE all_headers src/*.hpp extras/*.hpp)
  list(APPEND rippled_src "${all_headers}")

  # Properties
  set_property(
    SOURCE ${non_unity_srcs}
    APPEND
    PROPERTY HEADER_FILE_ONLY
    true)
  set_property(
    SOURCE ${all_headers}
    APPEND
    PROPERTY HEADER_FILE_ONLY
    true)
    # Doesn't work
    # $<OR:$<CONFIG:Debug>,$<CONFIG:Release>>)
endif()

############################################################

if (NOT is_msvc)
  set(no_unused_w -Wno-unused-function)
else()
  unset(no_unused_w)
endif()

############################################################

if (WIN32 OR is_xcode)
  group_sources(src)
  group_sources(extras/ripple-libpp/extras/rippled/src)
endif()

add_library(ripplelibpp OBJECT ${lib_src} ${rippled_src})

add_executable(validator-keys ${app_src} $<TARGET_OBJECTS:ripplelibpp> ${rippled_src})

set_startup_project(validator-keys)

target_link_libraries(validator-keys
  ${OPENSSL_LIBRARIES} ${SANITIZER_LIBRARIES})

link_common_libraries(validator-keys)
