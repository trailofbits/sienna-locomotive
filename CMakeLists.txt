cmake_minimum_required(VERSION 3.9)

add_subdirectory(fuzz_dynamorio)
add_subdirectory(server)
add_subdirectory(triage_dynamorio)
add_subdirectory(wizard)
add_subdirectory(corpus/test_application)