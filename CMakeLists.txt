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

# include(ExternalProject)

################################################################################################
# Breakpad stuff for triage/minidump/exploitability/etc...
# This checks out the src for the header files only
# set(  BREAKPAD_DIR        ${CMAKE_SOURCE_DIR}/breakpad/src/breakpad/src)
# # the library is prebuilt here
# file( GLOB BREAKPAD_LIBS  ${CMAKE_SOURCE_DIR}/deps/Release/*.lib )

# ExternalProject_Add(
#   breakpad
#   GIT_REPOSITORY     https://github.com/google/breakpad.git
#   CONFIGURE_COMMAND  ""
#   BUILD_COMMAND      ""
#   INSTALL_COMMAND    ""
#   TEST_COMMAND       ""
#   PREFIX             "../breakpad"
#  )


include_directories(include)
add_subdirectory(common)
add_subdirectory(fuzz_dynamorio)
add_subdirectory(server)
add_subdirectory(triage_dynamorio)
add_subdirectory(wizard)
add_subdirectory(corpus/test_application)


add_subdirectory(triage)
target_compile_definitions(server PRIVATE -DUNICODE)
