# validator-keys-tool

Rippled validator key generation tool

## Introduction

C++ library to create, sign, and serialize
[Ripple](https://ripple.com) transactions
before submission to the Ripple Consensus Ledger
([rippled](https://github.com/ripple/rippled)).
Duplicates much of the functionality of the
[`sign`](https://ripple.com/build/rippled-apis/#sign)
RPC function without the overhead of a JSON library,
network delays, needing to trust a 3rd party's rippled,
nor needing to run your own rippled.

## Table of contents

* [Dependencies](#dependencies)
  * [ripple-libpp submodule](#ripple-libpp-submodule)
  * [Other dependencies](#other-dependencies)
* [Installation](#installation)
* [Demo](#demo)
  * [Additional dependencies](#additional-dependencies)
  * [Build and run](#build-and-run)

## Dependencies

### ripple-libpp submodule

This includes a git submodule to the ripple-libpp source code, which is not cloned by default. To get the ripple-libpp source, either clone this repository using
```
$ git clone --recursive <location>
```
or after cloning, run the following commands
```
$ git submodule init
$ git submodule update
```

### Other dependencies

* C++14 or greater
* [Boost](http://www.boost.org/)
* [OpenSSL](https://www.openssl.org/)

### Additional dependencies

In addition to the Usage [dependencies](#dependencies), building
the demo requires

* [cmake](https://cmake.org)

### Build and run

For linux and other unix-like OSes, run the following commands:

```
$ cd ${YOUR_RIPPLE_LIBPP_DIRECTORY}
$ mkdir -p build/gcc.debug
$ cd build/gcc.debug
$ cmake ../..
$ cmake --build .
$ ./validator-keys
```

For 64-bit Windows, open a MSBuild Command Prompt for Visual Studio
and run the following commands:

```
> cd %YOUR_RIPPLE_LIBPP_DIRECTORY%
> mkdir build
> cd build
> cmake -G"Visual Studio 14 2015 Win64" ..
> cmake --build .
> .\Debug\validator-keys.exe
```

32-bit Windows builds are not officially supported.
