#include "taint_data.h"

TaintData::TaintData(UINT id, ADDRINT addr, SIZE size) 
        : id(id), addr(addr), size(size), freed(false), debug(false), out(&std::cout) { 
    REG fullReg = REG_FullRegName(LEVEL_BASE::REG_EAX);
    tainted_regs.insert(fullReg);
}

bool TaintData::reg_is_tainted(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
    bool tainted = tainted_regs.find(fullReg) != tainted_regs.end();

    return tainted;
}

VOID TaintData::reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    if(debug && !id) {
        *out << std::hex << ip << " (" << id << "): " << *ptr_disas << std::endl;
        *out << "REG TAINT: " << REG_StringShort(reg) << std::endl;
    }

    REG fullReg = REG_FullRegName(reg);
    tainted_regs.insert(fullReg);
}

VOID TaintData::reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    if(debug && !id) {
        *out << std::hex << ip << " (" << id << "): " << *ptr_disas << std::endl;
        *out << "REG UNTAINT: " << REG_StringShort(reg) << std::endl;
    }
    
    REG fullReg = REG_FullRegName(reg);
    std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
    if(it != tainted_regs.end()) {
        tainted_regs.erase(it);
    }
}

bool TaintData::mem_is_tainted(ADDRINT mem) {
    bool tainted = tainted_addrs.find(mem) != tainted_addrs.end();
    return tainted;
}

VOID TaintData::mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    if(debug && !id) {
        *out << std::hex << ip << " (" << id << "): " << *ptr_disas << std::endl;
    }

    for(UINT32 i=0; i<size; i++) {
        if(debug && !id) {
            *out << "MEM TAINT: " << mem+i << std::endl;
        }
        tainted_addrs.insert(mem+i);
    }
}

VOID TaintData::mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    if(debug && !id) {
        *out << std::hex << ip << " (" << id << "): " << *ptr_disas << std::endl;
        *out << "TAINTED REGS:" << std::endl;
        std::set<LEVEL_BASE::REG>::iterator sit;
        for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
            *out << REG_StringShort(*sit) << std::endl;
        }
    }
    
    for(UINT32 i=0; i<size; i++) {
        std::set<ADDRINT>::iterator it = tainted_addrs.find(mem+i);   
        if(debug && !id) {
            *out << "MEM UNTAINT: " << mem+i << std::endl;
        }

        if(it != tainted_addrs.end()) {
            tainted_addrs.erase(it);
        }
    }
    
}



