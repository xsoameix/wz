# wz

wz is a library for reading the wz files.

wz focus on these features:

* Minimal Dependency
    * only 1 dependency: zlib
* Light Weight but Powerful
    * ~ 2000 lines of code
    * fully extract any data from any wz files
* Convenient
    * the APIs are intuitive and easy to use
    * search a node/variable by specifying the path
    * the descendant of the freed node/variable are also be freed
* Small
    * minimal size in bytes of all structures
    * store node/variable's type as 1 byte integer instead of string
* Fast
    * C is fast to compile and run
    * node/variable's type comparison is simply integer comparison
* Secure
    * return if any error occurs
    * no memory leak
    * no buffer overflow
* Robust
    * ~ 1000 lines of code of unit test
* Modern
    * cross platform
    * written in C99 and easy to maintain
* Multiple Programming Language Support
    * easy to bind with C++, C#, Java, Python, Ruby, Nodejs and so on
* Long Term Support
    * keeping support any data of any wz files in the future

## Environment

* Supported Platforms: Windows, Linux, Mac and other Unix-like platforms
* Supported Compilers:
    * Visual Studio 2013 with Update 5
    * Visual Studio 2015
    * GCC >= 3.1
    * Xcode >= 3.1
* Dependencies: [zlib](http://www.zlib.net/)
* Unit Test: [check](https://libcheck.github.io/check/)
* Using C Standard Revision: C99

## Installation

### Windows

#### Visual Studio

1. Install [cmake](https://cmake.org/download/) and select "Add CMake to the system PATH for all users" when installing.

2. Download source code of these 3 libraries: [wz](https://github.com/xsoameix/wz/archive/master.zip), [zlib](http://www.zlib.net/) and [check](https://github.com/libcheck/check/archive/master.zip). Extract these zip files to `wz`, `zlib` and `check` folders. The directory structure should likes this:

        ▸ wz/
        ▸ zlib/
        ▸ check/

3. Press the shift key and right click the `wz` folder. Select the option "Open Command Window Here" which popped up. Run this command in the command window:

        > make all "Visual Studio 2013"
        or
        > make all "Visual Studio 2015"

4. The headers and dlls are installed in `local` folders. Now you can use this library in your applications !

        ▾ wz/
          ▾ local/
            ▾ include/
              ▾ wz/
                  file.h
            ▾ bin/
                wz.dll
            ▾ lib
                wz.lib
        ▾ zlib/
          ▾ local/
            ▾ bin/
                zlibd.dll
        ▸ check

### Linux

1. Install cmake, zlib and check.

        # Debian / Ubuntu / Mint
        $ sudo apt-get install cmake zlib1g-dev check

2. Download source code of this library: [wz](https://github.com/xsoameix/wz/archive/master.zip). Extract this zip file to `wz` folder and enter this directory.

        $ mkdir build && cd build
        $ cmake .. && make && sudo make install

3. The headers, shared library and wz.pc are installed in `/usr/local` folders. Now you can use this library in your applications !

        ▾ /usr/local/
          ▾ include/
            ▾ wz/
                file.h
          ▾ lib/
              libwz.so
          ▾ share/
            ▾ pkgconfig/
                wz.pc

### Mac

#### Xcode

1. Install [homebrew](http://brew.sh/), pkg-config, cmake and check.

        $ brew install pkg-config cmake check

2. Download source code of this library: [wz](https://github.com/xsoameix/wz/archive/master.zip). Extract this zip file to `wz` folder and enter this directory.

        $ mkdir build && cd build
        $ cmake .. && make && make install

3. The headers, shared library and wz.pc are installed in `/usr/local` folders. Now you can use this library in your applications !

        ▾ /usr/local/
          ▾ include/
            ▾ wz/
                file.h
          ▾ lib/
              libwz.dylib
          ▾ share/
            ▾ pkgconfig/
                wz.pc

## Tutorial

* [Reading from wz file](https://github.com/xsoameix/wz/wiki/Reading-from-wz-file)
* [Encryption used in wz file](https://github.com/xsoameix/wz/wiki/Encryption-used-in-wz-file)

## Unit Test

    $ cd build && ctest

## Share and Feedback

This library is totally open source. You can modify or share the source code to anyone. All suggestions are welcomed.

## Reference

* [Golang](https://github.com/diamondo25/go-wz/blob/master/directory.go)
* [C](https://code.google.com/p/cmsc/source/browse/trunk/wzlibc/wzlibc.c)
* [C++](https://github.com/NoLifeDev/NoLifeStory/blob/master/src/wz/wzmain.cpp)
* [C#](https://github.com/haha01haha01/MapleLib/blob/master/WzLib/WzFile.cs)
* [C#](https://github.com/Kagamia/WzComparerR2/blob/master/WzComparerR2.WzLib/Wz_Sound.cs)
* [C#](https://github.com/angelsl/ms-reWZ/blob/master/WZProperties/WZAudioProperty.cs)
