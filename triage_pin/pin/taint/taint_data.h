#include "pin.H"
#include "memory_manager.h"
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

    BOOL reg_is_tainted(LEVEL_BASE::REG reg);
    VOID reg_taint(ADDRINT ip, MemoryManager *memory_manager, LEVEL_BASE::REG reg);
    VOID reg_untaint(ADDRINT ip, MemoryManager *memory_manager, LEVEL_BASE::REG reg);
    
    BOOL mem_is_tainted(ADDRINT mem);
    VOID mem_taint(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
    VOID mem_untaint(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size);
    BOOL intersects(ADDRINT mem, UINT32 size);

    VOID dump();
};