#include "taint_data.h"

TaintData::TaintData(UINT id, ADDRINT addr, SIZE size) 
        : id(id), addr(addr), size(size), freed(false), debug(false), out(&std::cout) {
    if(id != 0) {
        REG fullReg = REG_FullRegName(LEVEL_BASE::REG_EAX);
        tainted_regs.insert(fullReg);
    }
}

BOOL TaintData::reg_is_tainted(LEVEL_BASE::REG reg) {
	if (debug && id == 0) {
		*out << "RIT: " << reg << " " << REG_StringShort(reg) << std::endl << std::flush;
	}
    REG fullReg = REG_FullRegName(reg);
    bool tainted = tainted_regs.find(fullReg) != tainted_regs.end();

    return tainted;
}

VOID TaintData::reg_taint(ADDRINT ip, MemoryManager *memory_manager, LEVEL_BASE::REG reg) {
    if(debug && id == 0) {
        *out << std::hex << ip << " (" << id << "): " << memory_manager->disas[ip] << std::endl << std::flush;
        *out << "REG TAINT: " << REG_StringShort(reg) << std::endl << std::flush;
    }

    REG fullReg = REG_FullRegName(reg);
    tainted_regs.insert(fullReg);
}

VOID TaintData::reg_untaint(ADDRINT ip, MemoryManager *memory_manager, LEVEL_BASE::REG reg) {
    if(debug && id == 0) {
        *out << std::hex << ip << " (" << id << "): " << memory_manager->disas[ip] << std::endl << std::flush;
        *out << "REG UNTAINT: " << REG_StringShort(reg) << std::endl << std::flush;
    }
    
    REG fullReg = REG_FullRegName(reg);
    std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
    if(it != tainted_regs.end()) {
        tainted_regs.erase(it);
    }
}

BOOL TaintData::mem_is_tainted(ADDRINT mem) {
    bool tainted = tainted_addrs.find(mem) != tainted_addrs.end();
    return tainted;
}

VOID TaintData::mem_taint(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size) {
    if(debug && id == 0) {
        *out << std::hex << ip << " (" << id << "): " << memory_manager->disas[ip] << std::endl << std::flush;
    }
    
    if(debug && id == 0) {
        *out << "MEM TAINT: " << std::hex << mem << ", " << size << std::endl << std::flush;
    }

    for(UINT32 i=0; i<size; i++) {
        tainted_addrs.insert(mem+i);
    }
}

VOID TaintData::mem_untaint(ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size) {
    if(debug && id == 0) {
        *out << std::hex << ip << " (" << id << "): " << memory_manager->disas[ip] << std::endl << std::flush;
        *out << "TAINTED REGS:" << std::endl << std::flush;
        std::set<LEVEL_BASE::REG>::iterator sit;
        for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
            *out << REG_StringShort(*sit) << std::endl << std::flush;
        }
    }
    
    if(debug && id == 0) {
        *out << "MEM UNTAINT: " << mem << ", " << size << std::endl << std::flush;
    }

    for(UINT32 i=0; i<size; i++) {
        std::set<ADDRINT>::iterator it = tainted_addrs.find(mem+i);   

        if(it != tainted_addrs.end()) {
            tainted_addrs.erase(it);
        }
    }
    
}

BOOL TaintData::intersects(ADDRINT mem, UINT32 size) {
    if(this->addr <= mem+size && mem <= this->addr+this->size) {
        return true;
    }
    
    return false;
}

VOID TaintData::dump() {
    *out << "ID: " << id << std::endl << std::flush;
    *out << "ADDR: " << addr << std::endl << std::flush;
    *out << "SIZE: " << size << std::endl << std::flush;

    *out << "TAINTED REGS: " << std::endl << std::flush;
    std::set<LEVEL_BASE::REG>::iterator sit;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        *out << REG_StringShort(*sit).c_str() << std::endl << std::flush;
    }

    *out << "TAINTED MEMS: " << std::endl << std::flush;
    if(tainted_addrs.size() > 0) {
        std::set<ADDRINT>::iterator mit = tainted_addrs.begin();
        ADDRINT start = *mit;
        UINT64 size = 1;

        mit++;
        for( ; mit != tainted_addrs.end(); mit++) {
            if(*mit > (start+size)) {
                *out << "\t" << start << ", " << size << std::endl << std::flush;
                start = *mit;
                size = 0;
            }
            size++;
        }

        *out << "\t" << start << ", " << size << std::endl << std::flush;
    }
}

