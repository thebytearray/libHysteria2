# libHysteria2



This is a wrapper around [Hysteria2](https://github.com/apernet/hysteria) to improve the client development experience.

# Note

1. This repository has few maintainers. If you do not report a bug or initiate a PR, your issue will be ignored.
2. This repository does not guarantee API stability, you need to adapt it yourself.
3. This repository is only compatible with the latest release of Hysteria2.

# Features

## build

Compile script. It is recommended to always use this script to compile libHysteria2. We will not answer questions caused by using other compilation methods.

### Usage

```shell
python3 build/main.py android
python3 build/main.py apple gomobile
python3 build/main.py apple go
python3 build/main.py linux
python3 build/main.py windows
```

### Android

use [gomobile](https://github.com/golang/mobile) .

### iOS && macOS

#### 1. use gomobile

Need "iOS Simulator Runtime".

This is the best choice for general scenarios and will not conflict with other frameworks.

Supports iOS, iOSSimulator, macOS, macCatalyst.

But it is not possible to set the minimum macOS version, which will cause some warnings when compiling. And it does not support tvOS.

#### 2. use cgo

Need "iOS Simulator Runtime" and "tvOS Simulator Runtime".

Support more compilation options, output c header files.

This works well when you use ffi for integration. For example, integration with swift, kotlin, dart.

Support iOS, iOSSimulator, macOS, tvOS.

Note: The product `LibHysteria2.xcframework` does not contain **module.modulemap**. When using swift, you need to create a bridge file.

### Linux

depend on clang and clang++.

### Windows

depend on [LLVM MinGW](https://github.com/mstorsjo/llvm-mingw), you can install it using winget.

```shell
winget install MartinStorsjo.LLVM-MinGW.UCRT
```

## controller

Used to solve the socket protect problem on Android.

## main

Test config on your computer

## memory

Only executed on iOS, GC is initiated once a second. This can alleviate memory pressure on iOS.

## nodep

### hysteria2

Start and stop hysteria2 instances.

## nodep_wrapper

export nodep.

### hysteria2_wrapper

export hysteria2.

# Credits

[Hysteria2](https://github.com/apernet/hysteria)

[libXray](https://github.com/XTLS/libXray/)

# License

This repository is based on the Apache 2.0 License.
