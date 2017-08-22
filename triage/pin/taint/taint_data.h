#include "pin.H"
#include <set>
#include <iostream>

class TaintData {
public:
    UINT id;
    ADDRINT addr;
    SIZE size;
    bool freed;
    bool debug;
    std::ostream *out;

    std::set<ADDRINT> tainted_addrs;
    std::set<LEVEL_BASE::REG> tainted_regs;

    TaintData(UINT id, ADDRINT addr, SIZE size);

    bool reg_is_tainted(LEVEL_BASE::REG reg);
    VOID reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    VOID reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    
    bool mem_is_tainted(ADDRINT mem);
    VOID mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID dump();
};