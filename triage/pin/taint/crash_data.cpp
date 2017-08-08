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

/*** CRASH ANALYSIS ***/

BOOL CrashData::xed_at(xed_decoded_inst_t *xedd, ADDRINT ip) {
#if defined(TARGET_IA32E)
    static const xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    static const xed_state_t dstate = {XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif
    
    xed_decoded_inst_zero_set_mode(xedd, &dstate);

    const unsigned int max_inst_len = 15;

    xed_error_enum_t xed_code = xed_decode(xedd, reinterpret_cast<UINT8*>(ip), max_inst_len);
    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
    if (xed_ok) {
        *out << std::hex << ip << " ";
        char buf[2048];

        // set the runtime adddress for disassembly 
        xed_uint64_t runtime_address = static_cast<xed_uint64_t>(ip); 

        xed_decoded_inst_dump_xed_format(xedd, buf, 2048, runtime_address);
        *out << buf << std::endl;
    } else {
        return false;
    }

    return true;
}

VOID CrashData::examine() {
    ADDRINT last_insn = last_addrs.back();

    if(location != last_insn && hint != 0) {
        bool contains_hint = false;

        std::list<ADDRINT>::iterator it;
        for(it = last_addrs.begin(); it != last_addrs.end(); it++) {
            if(*it == hint) {
                contains_hint = true;
                break;
            }
        }

        if(contains_hint) {
            last_insn = hint;
        }
    }

    if(signal == "SIGFPE") {
        verdict = UNLIKELY;
        return;
    }

    if(signal == "SIGTRAP") {
        verdict = UNLIKELY;
        return;
    }

    if(!insns.count(last_insn)) {
        *out << "CAN'T FIND INSN AT " << last_insn << std::endl;
        verdict = LIKELY;
        return;
    }
    
    Instruction insn = insns[last_insn];
    // INS ins = insn.ins;
    string disas = insn.disas; 

    *out << "CRASH ON: " << disas << std::endl;

    xed_decoded_inst_t xedd;
    if(!xed_at(&xedd, last_insn)) {
        *out << "UNABLE TO DECODE" << std::endl;
        verdict = LIKELY;
        return;
    } 

    xed_iclass_enum_t insn_iclass = xed_decoded_inst_get_iclass(&xedd);
    *out << "ICLASS " << xed_iclass_enum_t2str(insn_iclass) << std::endl;

    UINT mem_nops = xed_decoded_inst_number_of_memory_operands(&xedd);

    bool written = false;
    bool read = false;

    for(UINT i = 0; i < mem_nops; i++) {
        if(xed_decoded_inst_mem_written(&xedd, i)) {
            written = true;
        }

        if(xed_decoded_inst_mem_read(&xedd, i)) {
            read = true;
        }
    }

    if(written) {
        *out << "WRITE" << std::endl;
        if(insn.has_flag(Instruction::TAINTED_WRITE)) {
            verdict = LIKELY;
        } else {
            verdict = UNLIKELY;
        }

        return;
    }

    if(read) {
        *out << "READ" << std::endl;
        if(insn.has_flag(Instruction::TAINTED_READ)) {
            verdict = LIKELY;
        } else {
            verdict = UNLIKELY;
        }

        return;
    }

    if(insn.has_flag(Instruction::DEP)) {
        *out << "DEP" << std::endl;
        verdict = LIKELY;
        return;
    }
}

string CrashData::verdict_string() {
    string lookup[] = { "EXPLOITABLE", "LIKELY", "UNLIKELY", "UNKNOWN" };
    return lookup[verdict];
}

/* TODO: json or serialization library */

VOID CrashData::dump_info() {
    *out << "{" << std::endl;
    *out << "\t\"verdict\": \"" << verdict_string() << "\"," << std::endl;

    *out << "\t\"signal\": \"" << signal << "\"," << std::endl;
    *out << "\t\"location\": 0x" << std::hex << location << "," << std::endl;
    *out << "\t\"hint\": 0x" << std::hex << hint << "," << std::endl;

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

        *out << "\t\t{ \"start\": 0x" << start << ", \"size\": 0x" << size << " }," << std::endl;
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