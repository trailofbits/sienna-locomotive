cmake_minimum_required(VERSION 3.9)

add_library(slcommon uuid.c sl2_dr_client.cpp sl2_server_api.cpp)

target_compile_definitions(slcommon PRIVATE -DUNICODE)
