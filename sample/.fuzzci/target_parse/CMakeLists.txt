cmake_minimum_required (VERSION 3.1)
project (target_parse)

set(BASE ../..)
set(MAIN_SRC_DIR ${BASE}/src/main)
set(FUZZCI_DIR ${BASE}/.fuzzci)
set(ENTRY_SRC_DIR ${FUZZCI_DIR}/target_parse)
set(TARGET_SOURCES ${MAIN_SRC_DIR}/parse.cpp ${ENTRY_SRC_DIR}/entry.cc ${FUZZCI_DIR}/libFuzzer.a)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_library(FUZZER_LIB NAMES Fuzzer PATHS ${FUZZCI_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize-coverage=bb -fsanitize=address -fsanitize=undefined")

add_executable(fuzz_target_parse EXCLUDE_FROM_ALL ${TARGET_SOURCES})
target_link_libraries(fuzz_target_parse Threads::Threads ${FUZZER_LIB})