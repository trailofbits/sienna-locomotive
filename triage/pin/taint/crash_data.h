#include "pin.H"
#include "instruction.h"
#include "taint_data.h"
#include "memory_manager.h"

#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

extern "C" {
#include "xed-interface.h"
}

#include <set>
#include <list>
#include <climits>
#include <iostream>
#include <signal.h>
#include <string>

class CrashData {
public:
    std::string signal;
    ADDRINT location;
    ADDRINT hint;
    std::map<ADDRINT, Instruction> insns;
    std::list<TaintData*> taint_data_list;

    #define RECORD_COUNT 5
    std::list<ADDRINT> last_addrs;
    std::list<INS> last_insns;
    std::list<ADDRINT> last_calls;

    std::ostream *out;
    bool debug;

    uint32_t score;
    std::string *reason;

    CrashData();

    VOID pointer_add(ADDRINT addr, SIZE size);
    UINT pointer_active_id(ADDRINT mem);
    VOID pointer_free(ADDRINT mem);

    VOID mem_to_reg(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
    VOID regs_to_regs(ADDRINT ip, MemoryManager *memory_manager);
    VOID regs_to_mem(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
    VOID taint_indirect(ADDRINT ip, 
        MemoryManager *memory_manager, 
        LEVEL_BASE::REG reg, ADDRINT regval, 
        std::map<ADDRINT, ADDRINT> execd, BOOL isRet);

    BOOL xed_at(xed_decoded_inst_t *xedd, ADDRINT ip);
    VOID examine();
    VOID dump_info();

private:
    bool is_branching(xed_iclass_enum_t xedi);
    bool is_ret(xed_iclass_enum_t xedi);
};