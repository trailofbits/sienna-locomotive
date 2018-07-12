cmake_minimum_required(VERSION 3.10)
project(SL2 VERSION 0.0.1 LANGUAGES CXX C)

set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )

# TODO(ww): Track down where we're messing the CRT linkage up.
foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
  string(REPLACE "/MTd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

include_directories(include include/common)
add_subdirectory(common)
add_subdirectory(fuzz_dynamorio)
add_subdirectory(server)
add_subdirectory(triage_dynamorio)
add_subdirectory(wizard)
add_subdirectory(corpus/test_application)

target_compile_definitions(server PRIVATE -DUNICODE)
