#include "memory_manager.h"

BOOL MemoryManager::has_insn(ADDRINT insn_addr) {
    return regs_r.count(insn_addr) != 0;
}

VOID MemoryManager::add_disas(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);

    if(disas.count(insn_addr)) {
        return;
    }

    string insn_disas = INS_Disassemble(ins);
    disas[insn_addr] = new std::string(insn_disas);
}

VOID MemoryManager::add_regs_r(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);

    if(regs_r.count(insn_addr)) {
        return;
    }

    regs_r[insn_addr] = new std::list<LEVEL_BASE::REG>();

    for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
        regs_r[insn_addr]->push_back(INS_RegR(ins, i));
    }
}

VOID MemoryManager::add_regs_rw(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);

    if(regs_r.count(insn_addr)) {
        return;
    }
    
    regs_r[insn_addr] = new std::list<LEVEL_BASE::REG>();
    regs_w[insn_addr] = new std::list<LEVEL_BASE::REG>();

    for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
        regs_r[insn_addr]->push_back(INS_RegR(ins, i));
    }

    for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
        regs_w[insn_addr]->push_back(INS_RegW(ins, i));
    }
}

VOID MemoryManager::add_regs_rw_pop(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);

    if(regs_r.count(insn_addr)) {
        return;
    }

    regs_r[insn_addr] = new std::list<LEVEL_BASE::REG>();
    regs_w[insn_addr] = new std::list<LEVEL_BASE::REG>();

    for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
        regs_r[insn_addr]->push_back(INS_RegR(ins, i));
    }

    for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
        if(INS_RegW(ins, i) == REG_STACK_PTR)
            continue; 

        regs_w[insn_addr]->push_back(INS_RegW(ins, i));
    }
}