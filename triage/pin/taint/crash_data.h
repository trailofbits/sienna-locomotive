#include "pin.H"
#include "instruction.h"

extern "C" {
#include "xed-interface.h"
}

#include <set>
#include <list>
#include <iostream>
#include <signal.h>

class CrashData {
public:
    enum Verdict {
        EXPLOITABLE,
        LIKELY,
        UNLIKELY,
        UNKNOWN
    };

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

    Verdict verdict;

    CrashData() : hint(0), out(&std::cout), debug(false), verdict(UNKNOWN) { };
    bool reg_is_tainted(LEVEL_BASE::REG reg);
    VOID reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    VOID reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    bool mem_is_tainted(ADDRINT mem);
    VOID mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    BOOL xed_at(xed_decoded_inst_t *xedd, ADDRINT ip);
    VOID examine();
    VOID dump_info();
    string verdict_string();
};