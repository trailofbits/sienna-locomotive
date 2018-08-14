cmake_minimum_required(VERSION 3.9)

find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(slcommon mutation.cpp uuid.c sl2_dr_client.cpp sl2_server_api.cpp)
configure_DynamoRIO_client(slcommon)

use_DynamoRIO_extension(slcommon drmgr)
use_DynamoRIO_extension(slcommon drreg)
use_DynamoRIO_extension(slcommon drwrap)
use_DynamoRIO_extension(slcommon droption)

target_compile_definitions(slcommon PRIVATE -DUNICODE)
