project (crashes)

set (CMAKE_C_FLAGS "${CMAKE_CFLAGS} -fno-stack-protector -g2")

add_executable(crash00 crash00_nocrash.c)
add_executable(crash01 crash01_stack.c)
add_executable(crash02 crash02_heap.c)
add_executable(crash03 crash03_nullderef.c)
add_executable(crash04 crash04_memaccess.c)
