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

#define DBG_OUT if(debug) *out << "DEBUG: " <<
#undef DBG_OUT_ID0 
#define DBG_OUT_ID0 if(debug && ptr_taint_data->id == 0) *out << "DEBUG: " <<

struct AllocInfo {
    UINT32 size:31;
    bool free:1;
} __attribute__ ((packed));

class CrashData {
public:
    std::string signal;
    ADDRINT location;
    ADDRINT hint;
    std::map<ADDRINT, Instruction> insns;
    std::list<TaintData*> taint_data_list;

    std::map<ADDRINT, std::set<ADDRINT> > alloc_addr_map;
    std::map<ADDRINT, std::list<struct AllocInfo> > alloc_info_map;

    #define RECORD_COUNT 5
    ADDRINT last_addrs[RECORD_COUNT];
	UINT32 last_addrs_head;
	ADDRINT last_calls[RECORD_COUNT];
	UINT32 last_calls_head;

    std::ostream *out;
    bool debug;

    UINT32 score;
    std::string *reason;

    CrashData();

    VOID pointer_add(ADDRINT addr, SIZE size);
    UINT pointer_active_id(ADDRINT mem);
    VOID pointer_free(ADDRINT mem);

    VOID mem_to_reg(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
    VOID regs_to_regs(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager);
    VOID regs_to_mem(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
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