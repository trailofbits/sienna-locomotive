#include "pin.H"
#include <set>
#include <list>
#include <iostream>

class CrashData {
public:
    string type;
    ADDRINT location;
    std::set<ADDRINT> tainted_addrs;
    std::set<LEVEL_BASE::REG> tainted_regs;

    #define RECORD_COUNT 5
    std::list<ADDRINT> last_addrs;
    std::list<ADDRINT> last_calls;

    std::ostream *out;

    CrashData() : out(&std::cout) { };
    bool reg_is_tainted(LEVEL_BASE::REG reg);
    VOID reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    VOID reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg);
    bool mem_is_tainted(ADDRINT mem);
    VOID mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size);
    VOID dump_info();
};;