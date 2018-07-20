cmake_minimum_required(VERSION 3.9)

find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(fuzzer SHARED fuzzer.cpp mutation.cpp)
target_compile_definitions(fuzzer PRIVATE -DUNICODE)

target_link_libraries(fuzzer Dbghelp)
target_link_libraries(fuzzer slcommon)

configure_DynamoRIO_client(fuzzer)

use_DynamoRIO_extension(fuzzer drmgr)
use_DynamoRIO_extension(fuzzer drwrap)
use_DynamoRIO_extension(fuzzer droption)
