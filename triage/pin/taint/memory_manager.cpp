#include "memory_manager.h"

BOOL MemoryManager::has_insn(ADDRINT insn_addr) {
    return regs_r.count(insn_addr) != 0;
}

VOID MemoryManager::add_trace(TRACE trace) {
    ADDRINT trace_addr = TRACE_Address(trace);

    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            ADDRINT insn_addr = INS_Address(ins);
            trace_insn[trace_addr].insert(insn_addr);
            insn_trace[insn_addr].insert(trace_addr);
        }
    }
}

VOID MemoryManager::add_disas(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);
    string insn_disas = INS_Disassemble(ins);

    disas[insn_addr] = insn_disas;
}

VOID MemoryManager::add_regs_rw(INS ins) {
    ADDRINT insn_addr = INS_Address(ins);
    for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
        regs_r[insn_addr].push_back(INS_RegR(ins, i));
    }

    for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
        regs_w[insn_addr].push_back(INS_RegW(ins, i));
    }
}

VOID MemoryManager::update_lru(ADDRINT insn_addr) {
    std::set<ADDRINT>::iterator trace_it;
    std::set<ADDRINT> trace_addr_set = insn_trace[insn_addr];

    for(trace_it = trace_addr_set.begin(); trace_it != trace_addr_set.end(); trace_it++) {
        ADDRINT trace_addr = *trace_it;
        trace_usage.remove(trace_addr);
        trace_usage.push_back(trace_addr);
    }
}

VOID MemoryManager::free_memory() {
    while(trace_usage.size() > TRACE_TARGET_SIZE) {
        ADDRINT trace_addr = trace_usage.front();
        trace_usage.pop_front();

        std::set<ADDRINT>::iterator insn_it;
        std::set<ADDRINT> insn_addr_set = trace_insn[trace_addr];
        
        for(insn_it = insn_addr_set.begin(); insn_it != insn_addr_set.end(); insn_it++) {
            ADDRINT insn_addr = *insn_it;

            std::set<ADDRINT>::iterator trace_it = insn_trace[insn_addr].find(trace_addr);
            if(trace_it != insn_trace[insn_addr].end()) {
                insn_trace[insn_addr].erase(trace_it);
            } else {
                std::cout << "ASSUMPTION FAIL: TRACE NOT FOUND ASSOCIATED WITH INSN" << std::endl;
            }

            if(insn_trace[insn_addr].size() == 0) {
                insn_trace.erase(insn_addr);
                regs_r.erase(insn_addr);
                regs_w.erase(insn_addr);
                disas.erase(insn_addr);
            }
        }

        trace_insn.erase(trace_addr);
        CODECACHE_InvalidateTraceAtProgramAddress(trace_addr);
    }
}
