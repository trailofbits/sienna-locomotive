yasm -f elf64 test.asm; clang-3.8 -o test test.o
# yasm -f elf64 -p nasm test.asm -a x86 ; ld test.o -o test
