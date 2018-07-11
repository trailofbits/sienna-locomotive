cmake_minimum_required(VERSION 3.9)

# NOTE(ww): We link slcommon as static here for a reason: DynamoRIO
# seems to have a persistent bug where dynamic linkages within clients
# don't get resolved correctly.
# Background: https://github.com/DynamoRIO/dynamorio/issues/1883
# Background: https://github.com/DynamoRIO/dynamorio/issues/1866
add_library(slcommon STATIC uuid.c sl2_dr_client.cpp)

# NOTE(ww): The linkage and definition below are needed because
# of some weirdness that happens with the version of VS that
# DynamoRIO links to -- removing them causes a good chunk of
# stdio to get inlined, which results in missing symbols
# during linkage.
target_link_libraries(slcommon legacy_stdio_definitions)
target_compile_definitions(slcommon PRIVATE -D_NO_CRT_STDIO_INLINE)

target_compile_definitions(slcommon PRIVATE -DUNICODE)
