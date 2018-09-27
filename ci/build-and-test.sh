#!/bin/bash -u
# We use set -e and bash with -u to bail on first non zero exit code of any
# processes launched or upon any unbound variable.
# We use set -x to print commands before running them to help with
# debugging.
set -ex
__dirname=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo "using CC: ${CC}"
"${CC}" --version
export CC
COMPNAME=$(basename $CC)
echo "using CXX: ${CXX:-notset}"
if [[ $CXX ]]; then
  "${CXX}" --version
  export CXX
fi
: ${BUILD_TYPE:=Debug}
echo "BUILD TYPE: ${BUILD_TYPE}"

: ${APP:=validator-keys}
echo "using APP: ${APP}"

JOBS=${NUM_PROCESSORS:-2}
if [[ ${TRAVIS:-false} != "true" ]]; then
  JOBS=$((JOBS+1))
fi

if [ -x /usr/bin/time ] ; then
  : ${TIME:="Duration: %E"}
  export TIME
  time=/usr/bin/time
else
  time=
fi

if [[ -z "${MAX_TIME:-}" ]] ; then
  timeout_cmd=""
else
  timeout_cmd="timeout ${MAX_TIME}"
fi

echo "cmake building ${APP}"
: ${CMAKE_EXTRA_ARGS:=""}

: ${COVERAGE:=false}
if [[ ${COVERAGE} == true ]]; then
    echo "coverage option detected."
    export PATH=$PATH:${LCOV_ROOT}/usr/bin
fi

#
# allow explicit setting of the name of the build
# dir, otherwise default to the compiler.build_type
#
: "${BUILD_DIR:=${COMPNAME}.${BUILD_TYPE}}"
BUILDARGS=" -j${JOBS}"
if [[ ${VERBOSE_BUILD:-} == true ]]; then
  CMAKE_EXTRA_ARGS+=" -DCMAKE_VERBOSE_MAKEFILE=ON"
  # TODO: if we use a different generator, this
  # option to build verbose would need to change:
  BUILDARGS+=" verbose=1"
fi
if [ -d "build/${BUILD_DIR}" ]; then
  rm -rf "build/${BUILD_DIR}"
fi

mkdir -p "build/${BUILD_DIR}"
pushd "build/${BUILD_DIR}"
# generate
${time} cmake ../.. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${CMAKE_EXTRA_ARGS}
# build
export DESTDIR=$(pwd)/_INSTALLED_
time ${timeout_cmd} cmake --build . -- $BUILDARGS
popd
export APP_PATH="$PWD/build/${BUILD_DIR}/${APP}"
echo "using APP_PATH: ${APP_PATH}"

# See what we've actually built
ldd ${APP_PATH}

if [[ ${COVERAGE} == true ]]; then
  # Push the results (lcov.info) to codecov
  codecov -X gcov # don't even try and look for .gcov files ;)
  find . -name "*.gcda" | xargs rm -f
fi

${timeout_cmd} ${APP_PATH} ${APP_ARGS}


