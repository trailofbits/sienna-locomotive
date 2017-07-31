#include "crash_data.h"

bool CrashData::reg_is_tainted(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
    bool tainted = tainted_regs.find(fullReg) != tainted_regs.end();

    return tainted;
}

VOID CrashData::reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    if(debug) {
        *out << std::hex << ip << ": " << *ptr_disas << std::endl;
        *out << "REG TAINT: " << REG_StringShort(reg) << std::endl;
    }

    REG fullReg = REG_FullRegName(reg);
    tainted_regs.insert(fullReg);
}

VOID CrashData::reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    if(debug) {
        *out << std::hex << ip << ": " << *ptr_disas << std::endl;
        *out << "REG UNTAINT: " << REG_StringShort(reg) << std::endl;
    }
    
    REG fullReg = REG_FullRegName(reg);
    std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
    if(it != tainted_regs.end()) {
        tainted_regs.erase(it);
    }
}

bool CrashData::mem_is_tainted(ADDRINT mem) {
    bool tainted = tainted_addrs.find(mem) != tainted_addrs.end();
    return tainted;
}

VOID CrashData::mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    if(debug) {
        *out << std::hex << ip << ": " << *ptr_disas << std::endl;
        *out << "TAINTED REGS:" << std::endl;
    }

    std::set<LEVEL_BASE::REG>::iterator sit;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        *out << REG_StringShort(*sit) << std::endl;
    }
    
    for(UINT32 i=0; i<size; i++) {
        std::set<ADDRINT>::iterator it = tainted_addrs.find(mem+i);   
        if(debug) {
            *out << "MEM UNTAINT: " << mem+i << std::endl;
        }

        if(it != tainted_addrs.end()) {
            tainted_addrs.erase(it);
        }
    }
}

VOID CrashData::mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    if(debug) {
        *out << std::hex << ip << ": " << *ptr_disas << std::endl;
    }

    for(UINT32 i=0; i<size; i++) {
        if(debug) {
            *out << "MEM TAINT: " << mem+i << std::endl;
        }
        tainted_addrs.insert(mem+i);
    }
}

VOID CrashData::dump_info() {
    *out << "{" << std::endl;
    *out << "\t\"signal\": \"" << signal << "\"," << std::endl;
    *out << "\t\"location\": 0x" << std::hex << location << "," << std::endl;

    std::set<LEVEL_BASE::REG>::iterator sit;
    *out << "\t\"tainted_regs\": [" << std::endl;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        *out << "\t\t\"" << REG_StringShort(*sit) << "\"," << std::endl;
    }
    *out << "\t]," << std::endl;

    *out << "\t\"tainted_addrs\": [" << std::endl;
    if(tainted_addrs.size() > 0) {
        std::set<ADDRINT>::iterator mit = tainted_addrs.begin();
        ADDRINT start = *mit;
        UINT64 size = 1;
        mit++;
        for( ; mit != tainted_addrs.end(); mit++) {
            if(*mit > (start+size)) {
                *out << "\t\t{ \"start\": 0x" << start << ", \"size\": 0x" << size << " }," << std::endl;
                start = *mit;
                size = 0;
            }
            size++;
        }

        *out << "\t\t{\"start\": 0x" << start << ", \"size\": 0x" << size << " }," << std::endl;
    }
    *out << "\t]," << std::endl;

    *out << "\t\"last_addrs\": [" << std::endl;
    std::list<ADDRINT>::iterator lit;
    for(lit=last_addrs.begin(); lit != last_addrs.end(); lit++) {
        *out << "\t\t0x" << *lit << "," << std::endl;
    }
    *out << "\t]," << std::endl;

    *out << "\t\"last_call\": [" << std::endl;
    for(lit=last_calls.begin(); lit != last_calls.end(); lit++) {
        *out << "\t\t0x" << *lit << "," << std::endl;
    }
    *out << "\t]," << std::endl;
    *out << "}" << std::endl;
}