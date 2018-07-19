# Breakpad

Holds the prebuild library breakpad.


## Building
We could automate this potentially, see
  https://github.com/desura/Desurium/blob/master/cmake/modules/BuildGoogleBreakpad.cmake

git clone https://chromium.googlesource.com/breakpad/breakpad/
git clone https://chromium.googlesource.com/external/gyp

  1. Install python 2
  2. Put gyp.bat in your path
  3. breakpad/src/breadkpad_client.sln
  4. Build Debug / Release builds
  5. copy to this directory

