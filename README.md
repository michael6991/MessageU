# MessageU
Instant messaging software. (Maman 15, Defensive Systems Programming).
- Client code written in C++.
- Server code written in Python.

# Project Configuration
## Client
- Client code written with ISO C++14 Standard. (Default by Visual Studio 2019).
- Boost Library 1.77.0 is used. https://www.boost.org
- Crypto++ Library 8.5 is used. https://www.cryptopp.com

## Client project configuration:
Both libraries Boost & Crypto++ are statically built in this guide.

## 1. Boost 1.77.0 Installation & Configuration
  Boost 1.77.0 Installation Instructions are based on Pattarapol Koosalapeerom's Boost Installation Instructions.

1.1. Get Boost
- Download the copy of Boost for Windows platform via http://www.boost.org/users/history/version_1_7_0.html. Either .7z or .zip is fine.
- Extract the archive file to your directory of choice. Example path: "D:\boost_1_77_0"

1.2. Complie Boost library
- Run CMD as administrator inside boost folder.
- The following commands will take a while to build:
- Run bootstrap.bat
- Run b2 link=static runtime-link=static

1.3. Include Boost library in Visual Studio's C++ Project
- Open Client's Project Properties.
- Add "D:\boost_1_77_0" under Project > Properties > C/C++ > General > Additional Include Directories
- Add "D:\boost_1_77_\stage\lib under Project > Properties > Linker > General > Additional Library.
- Define _WIN32_WINNT=0x0A00 under Project > Properties > C/C++ > Preprocessor > Preprocessor Definitions (Windows 10. For other OS see this link).

## 2. Crypto++ 8.5 Installation & Configuration

2.1. Get Crypto++
- Download the copy of Crypto++ for Windows platform via https://www.cryptopp.com/#download. (ZIP).
- Extract the archive file to your directory of choice. Example path: "D:\cryptopp850"

2.2. Complie Crypto++ library
- Open "D:\cryptopp850\cryptest.sln" with Visual Studio.
- Build the solution. Make sure build configuration matches. (For example, Debug, Win32).
- Close the solution.
- We will use the static library cryptlib.lib. (If Win32, Debug was built, the library will be located within Win32
\Output\Debug).

2.3. Include Crypto++ library in Visual Studio's C++ Project
- Open Client's Project Properties.
- Add "D:\cryptopp850" under Project > Properties > C/C++ > General > Additional Include Directories
- Add "D:\cryptopp850\Win32\Output\Debug\cryptlib.lib" under Project > Properties > Linker > Input > Additional Dependencies
- Make sure the project's Runtime Library is Project > Properties > C/C++ > Code Generation > Runtime > Library > Multi-threaded Debug (/MTd)


## 3. Additional configurations
The following configurations already set within the sln. Unlike above libraries, it doesn't need external references
hence probably shouldn't be modifed.
- Not using precompiled headers.
- Added additional include path $(ProjectDir)\cryptopp_wrapper\



## Server
- Developed with PyCharm 2021.1.2.
- Server code written with Python 3.9.6.

## Server project onfiguration
No special packages were required. Only the language's standard
