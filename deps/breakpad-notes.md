# Breakpad

## Reasons for breakpad.
  
  1. It's cross platform: Works on Windows, Linux, and macOS.
  2. It's written and used by Google (and Mozilla) in production on countless machines.
  3. It's very well written and tested.
  4. It's has a thought-out exploitability feature that includes disassembly.
  5. It has a stackwalker.
  6. It supports symbols, including pdbs. 
  7. Can parse minidumps, and ever convert to corefiles.
  8. It has it's own exception handlers (although we probably don't care about this)



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


