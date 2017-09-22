#include "pin.H"

#include <map>
#include <set>
#include <list>
#include <iostream>

#ifndef MEM_MGR
#define MEM_MGR

#define LRU_TARGET_SIZE 500

class MemoryManager {
public:
    std::map<ADDRINT, string*> disas;
    std::map<ADDRINT, std::list<LEVEL_BASE::REG>*> regs_r;
    std::map<ADDRINT, std::list<LEVEL_BASE::REG>*> regs_w;
    std::map<ADDRINT, std::set<ADDRINT> > trace_insn;
    std::map<ADDRINT, std::set<ADDRINT> > insn_trace;
    std::list<ADDRINT> trace_lru;

    BOOL has_insn(ADDRINT insn_addr);
    VOID add_trace(TRACE trace);
    VOID add_disas(INS ins);
    VOID add_regs_r(INS ins);
    VOID add_regs_rw(INS ins);
    VOID add_regs_rw_pop(INS ins);
    VOID update_lru(ADDRINT insn_addr);
    VOID free_memory();
};

#endif