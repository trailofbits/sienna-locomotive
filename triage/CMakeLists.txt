file(
    GLOB SOURCES "*.cc"    
    GLOB SOURCES ${BREAKPAD_DIR}/third_party/libdisasm/*.c
)

#GLOB SOURCES ${BREAKPAD_DIR}/processor/*.cc

# include(ExternalProject)
# ExternalProject_Add(googletest
#     URL https://github.com/google/googletest/archive/release-1.7.0.zip
#     INSTALL_COMMAND ""
# )
# ExternalProject_Get_Property(googletest binary_dir)
# add_library(gtest UNKNOWN IMPORTED)
# #add_library(gtest_main UNKNOWN IMPORTED)
# set_target_properties(gtest PROPERTIES
#     IMPORTED_LOCATION ${binary_dir}/libgtest.a
# )
# # set_target_properties(gtest_main PROPERTIES
# #     IMPORTED_LOCATION ${binary_dir}/libgtest_main.a
# # )
# add_dependencies(gtest googletest)
# #add_dependencies(gtest_main googletest)



include_directories( 
    ${BREAKPAD_DIR}
    ${BREAKPAD_DIR}/processor
)

add_executable(triager ${SOURCES})

target_link_libraries(triager ${BREAKPAD_LIBS})
