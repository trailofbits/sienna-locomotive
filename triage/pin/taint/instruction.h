#include "pin.H"
#include <iostream>

class Instruction {
public:
    ADDRINT ip;
    INS ins;
    string disas;

    enum Flags {
        NONE            = 0,
        DEP             = 1 << 0,
        USE_AFTER_FREE  = 1 << 1,
        DOUBLE_FREE     = 1 << 2,
        PC_TAINT        = 1 << 3,
        TAINTED_READ    = 1 << 4,
        TAINTED_WRITE   = 1 << 5,
    };

    Flags flags;
    Instruction();
    Instruction(ADDRINT ip, INS ins, string disas, Flags flags);
    VOID add_flag(Flags flag);
    BOOL has_flag(Flags flag);
/* 
address
mnemonic
operands

attrs 
    mem read
    mem written
    double free
    use after free
    indirect branch
*/
};