#include "instruction.h"

VOID Instruction::add_flag(Flags flag) {
    std::cout << "add " << flags << " " << flag << std::endl;
    flags = (Instruction::Flags) (flags | flag);
    std::cout << "add " << flags << " " << flag << std::endl;
}

BOOL Instruction::has_flag(Flags flag) {
    std::cout << "has " << flags << " " << flag << std::endl;
    return flags & flag;
}

Instruction::Instruction() : ip(0), disas(""), flags(NONE) { };
    
Instruction::Instruction(ADDRINT ip, string disas) 
    : ip(ip), disas(disas), flags(NONE) { };