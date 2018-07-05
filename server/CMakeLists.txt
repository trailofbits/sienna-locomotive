cmake_minimum_required(VERSION 3.10)
add_executable(server server.cpp)
target_compile_definitions(server PRIVATE -DUNICODE)
target_link_libraries(server Pathcch Rpcrt4)
