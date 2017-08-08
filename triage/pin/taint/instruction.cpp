#include "instruction.h"

VOID Instruction::add_flag(Flags flag) {
    std::cout << "FLAGS (" << ip << ") " << flags << std::endl;
    std::cout << "SETTING FLAG " << flag << std::endl;
    flags = (Instruction::Flags) (flags | flag);
    std::cout << "FLAGS (" << ip << ") " << flags << std::endl;
}

BOOL Instruction::has_flag(Flags flag) {
    std::cout << "HAS FLAGS (" << ip << ") " << flags << " " << flag << " " << (flags & flag) << std::endl;
    return flags & flag;
}

Instruction::Instruction() : ip(0), disas(""), flags(NONE) { };
    

Instruction::Instruction(ADDRINT ip, INS ins, string disas, Flags flags) 
    : ip(ip), ins(ins), disas(disas), flags(flags) { };