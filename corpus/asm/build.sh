python generate_main.py
yasm -f elf64 crash.asm
clang-3.8 -o crashy_mccrashface crash.o
