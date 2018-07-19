file(GLOB SOURCES "*.cc")


include_directories( ${BREAKPAD_DIR} )

add_executable(triage ${SOURCES})

target_link_libraries(triage ${BREAKPAD_LIBS})


#add_library( breakpad STATIC common.lib  )
#target_link_libraries(triage breakpad)