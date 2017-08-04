#include "pin.H"
#include "instruction.h"

extern "C" {
#include "xed-interface.h"
}
#include <set>
#include <list>
#include <iostream>

class CrashData {
public:
    string signal;
    ADDRINT location;
    ADDRINT hint;
    std::set<ADDRINT> tainted_addrs;
    std::set<LEVEL_BASE::REG> tainted_regs;
    std::map<ADDRINT, Instruction> insns;


    #define RECORD_COUNT 5
    std::list<ADDRINT> last_addrs;
    std::list<INS> last_insns;
    std::list<ADDRINT> last_calls;

    std::ostream *out;
    bool debug;

    CrashData() : hint(0), out(&std::cout), debug(false) { };
    bool reg_is_tainted(LEVEL_BASE::REG reg);
    VOID reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    VOID reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    bool mem_is_tainted(ADDRINT mem);
    VOID mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID examine();
    VOID dump_info();

private:
    BOOL xed_at(xed_decoded_inst_t *xedd, ADDRINT ip);
};