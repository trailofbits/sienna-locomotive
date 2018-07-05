cmake_minimum_required(VERSION 3.10)
project(SL2 VERSION 0.0.1 LANGUAGES CXX C)

include_directories(include include/common)
add_subdirectory(common)
add_subdirectory(fuzz_dynamorio)
add_subdirectory(server)
add_subdirectory(triage_dynamorio)
add_subdirectory(wizard)
add_subdirectory(corpus/test_application)
set(DynamoRIO_LOG_COMPATIBILITY on)

target_compile_definitions(server PRIVATE -DUNICODE)
