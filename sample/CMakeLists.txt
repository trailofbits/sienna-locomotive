cmake_minimum_required (VERSION 3.0)
project (sample)

file(GLOB_RECURSE sources src/main/*.cpp src/main/*.h)

add_executable(sample ${sources})

add_subdirectory(.fuzzci/target_parse)