#include "instruction.h"

VOID Instruction::add_flag(Flags flag) {
    flags = (Instruction::Flags) (flags | flag);
}

VOID Instruction::remove_flag(Flags flag) {
    flags = (Instruction::Flags) (flags & ~flag);
}

BOOL Instruction::has_flag(Flags flag) {
    return flags & flag;
}

Instruction::Instruction() : ip(0), disas(""), flags(NONE) { };
    
Instruction::Instruction(ADDRINT ip, string disas) 
    : ip(ip), disas(disas), flags(NONE) { };