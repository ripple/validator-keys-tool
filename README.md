# validator-keys-tool

Rippled validator key generation tool


## Build

If you do not have package `xrpl` in your local Conan cache,
you can add the Ripple remote to download it:

```
conan remote add ripple http://18.143.149.228:8081/artifactory/api/conan/conan-non-prod
```

The build requirements and commands are the exact same as
[those](https://github.com/XRPLF/rippled/blob/develop/BUILD.md) for rippled.
In short:

```
mkdir .build
cd .build
conan install .. --output-folder . --build missing
cmake -DCMAKE_TOOLCHAIN_FILE:FILEPATH=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
./validator-keys --unittest # or ctest --test-dir .
```


## Guide

[Validator Keys Tool Guide](doc/validator-keys-tool-guide.md)
