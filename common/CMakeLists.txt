cmake_minimum_required(VERSION 3.9)

find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(slcommon uuid.c sl2_dr_client.cpp sl2_server_api.cpp)
configure_DynamoRIO_client(slcommon)

target_compile_definitions(slcommon PRIVATE -DUNICODE)
