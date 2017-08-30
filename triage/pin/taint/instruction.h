#include "pin.H"
#include <iostream>

class Instruction {
public:
    ADDRINT ip;
    string disas;

    enum Flags {
        NONE            = 0,
        DEP             = 1 << 0,
        USE_AFTER_FREE  = 1 << 1,
        PC_TAINT        = 1 << 2,
        TAINTED_READ    = 1 << 3,
        TAINTED_WRITE   = 1 << 4,
    };

    Flags flags;
    Instruction();
    Instruction(ADDRINT ip, string disas);
    VOID add_flag(Flags flag);
    VOID remove_flag(Flags flag);
    BOOL has_flag(Flags flag);
    VOID clear_flags();
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