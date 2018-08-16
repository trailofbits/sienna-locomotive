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
set(  CONFIGMODE         "Release")
set(  BREAKPAD_DIR        ${CMAKE_SOURCE_DIR}/breakpad/src )
file( GLOB BREAKPAD_LIBS  ${BREAKPAD_DIR}/client/windows/${CONFIGMODE}/lib/*.lib ${BREAKPAD_DIR}/tools/windows/${CONFIGMODE}/lib/*.lib )


# TODO:  This should work, but I can't get them to build in Release mode, which is the only mode that
# links correctly.
#
# include_external_msproject( bpad ${BREAKPAD_DIR}/client/windows/common.vcxproj PLATFORM x64 )
# include_external_msproject( bpad ${BREAKPAD_DIR}/common/windows/common_windows_lib.vcxproj PLATFORM x64 )
# include_external_msproject( bpad ${BREAKPAD_DIR}/tools/windows/dump_syms/dump_syms.vcxproj PLATFORM x64 )
# include_external_msproject( bpad ${BREAKPAD_DIR}/client/windows/unittests/processor_bits.vcxproj PLATFORM x64 )
# set_target_properties(bpad PROPERTIES
# 	MAP_IMPORTED_CONFIG_RELEASE "${CONFIGMODE}"
#   MAP_IMPORTED_CONFIG_RELWITHDEBINFO "${CONFIGMODE}")

# ExternalProject_Add(
#   breakpad
#   GIT_REPOSITORY     https://github.com/google/breakpad.git
#   CONFIGURE_COMMAND  ""
#   BUILD_COMMAND      ""
#   INSTALL_COMMAND    ""
#   TEST_COMMAND       ""
#   PREFIX             "../breakpad"
#  )



################################################################################################
include_directories(include)
add_subdirectory(common)
add_subdirectory(fuzz_dynamorio)
add_subdirectory(server)
add_subdirectory(triage_dynamorio)
add_subdirectory(wizard)
add_subdirectory(corpus/test_application)
add_subdirectory(triage)
add_subdirectory(fuzzgoat)
add_subdirectory(winchecksec)

target_compile_definitions(server PRIVATE -DUNICODE)
