#include "instruction.h"

VOID Instruction::add_flag(Flags flag, std::ostream *out) {
	//*out << "add_flag(" << flag << ")" << std::endl << std::flush;
    flags = (Instruction::Flags) (flags | flag);
}

VOID Instruction::remove_flag(Flags flag, std::ostream *out) {
	//*out << "remove_flag(" << flag << ")" << std::endl << std::flush;
    flags = (Instruction::Flags) (flags & ~flag);
}

VOID Instruction::clear_flags() {
    flags = NONE;
}

BOOL Instruction::has_flag(Flags flag) {
    return flags & flag;
}

Instruction::Instruction() : ip(0), disas(""), flags(NONE) { };
    
Instruction::Instruction(ADDRINT ip, string disas)
    : ip(ip), disas(disas), flags(NONE) { };