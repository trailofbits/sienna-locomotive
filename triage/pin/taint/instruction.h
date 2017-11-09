#include "pin.H"
#include <iostream>
#include <set>

class Instruction {
public:
    ADDRINT ip;
    string disas;
    std::set<UINT64> potential_uaf_sizes;

    enum Flags {
        NONE            = 0,
        DEP             = 1 << 0,
        USE_AFTER_FREE  = 1 << 1,
        POTENTIAL_UAF   = 1 << 2,
        PC_TAINT        = 1 << 3,
        TAINTED_READ    = 1 << 4,
        TAINTED_WRITE   = 1 << 5
    };

    Flags flags;
    Instruction();
    Instruction(ADDRINT ip, string disas);
    VOID add_flag(Flags flag, std::ostream *out);
    VOID remove_flag(Flags flag, std::ostream *out);
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