#include "crash_data.h"

CrashData::CrashData() : hint(0), out(&std::cout), debug(false), score(50) {
    TaintData *ptr_taint_data = new TaintData(0, 0, 0);
    taint_data_list.push_back(ptr_taint_data);
    reason = new std::string;
    *reason = "unknown";
}

VOID CrashData::mem_to_reg(ADDRINT ip, MemoryManager memory_manager, ADDRINT mem, UINT32 size) {
    std::cout << "IN CALLBACK FOR " << ip << std::endl;

    std::list<LEVEL_BASE::REG> regs_r = memory_manager.regs_r[ip];
    std::list<LEVEL_BASE::REG> regs_w = memory_manager.regs_w[ip];

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        if(debug && ptr_taint_data->id == 0) {
            *out << "M2R " << ip << " " << memory_manager.disas[ip] << std::endl;
        }

        bool tainted = false;
        for(UINT32 i=0; i<size; i++) {
            if(ptr_taint_data->mem_is_tainted(mem+i)) {
                tainted = true;
                break;
            }
        }

        std::list<LEVEL_BASE::REG>::iterator it;
        for(it=regs_r.begin(); it != regs_r.end() && !tainted; it++) {
            if(ptr_taint_data->reg_is_tainted(*it)) {
                tainted = true;
            }
        }

        for(it=regs_w.begin(); it != regs_w.end(); it++) {
            REG reg = *it;
            
            if(tainted) {
                if(ptr_taint_data->id == 0) {
                    insns[ip].add_flag(Instruction::TAINTED_READ);
                } else if(ptr_taint_data->freed && ptr_taint_data->intersects(mem, size)) {
                    if(debug) {
                        *out << "HINT: USE AFTER FREE: (r) ";
                        *out << mem << " at " << ip << std::endl;
                    }
                    insns[ip].add_flag(Instruction::USE_AFTER_FREE);
                }

                if(debug && ptr_taint_data->id == 0) {
                    *out << "TAINTED READ AT " << std::hex << ip << " OF " << mem << std::endl;
                    *out << "REGm TAINT: " << REG_StringShort(reg) << std::endl;
                }

                ptr_taint_data->reg_taint(ip, memory_manager, reg);

                if(debug && ptr_taint_data->id == 0) {
                    *out << "TAINTED REGS:" << std::endl;
                    std::set<LEVEL_BASE::REG>::iterator sit;
                    for(sit=ptr_taint_data->tainted_regs.begin(); sit != ptr_taint_data->tainted_regs.end(); sit++) {
                        *out << REG_StringShort(*sit) << std::endl;
                    }
                }
                
            } else {
                if(debug && ptr_taint_data->id == 0) {
                    *out << "REGm UNTAINT: " << REG_StringShort(reg) << std::endl;
                }

                if(ptr_taint_data->id == 0) {
                    insns[ip].remove_flag(Instruction::TAINTED_READ);
                }

                ptr_taint_data->reg_untaint(ip, memory_manager, reg);

            }
        }
    }
}

VOID CrashData::regs_to_regs(ADDRINT ip, std::string *ptr_disas, 
        std::list<LEVEL_BASE::REG> *ptr_regs_r, 
        std::list<LEVEL_BASE::REG> *ptr_regs_w) {

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        if(debug && ptr_taint_data->id == 0) {
            *out << "R2R " << std::hex << ip << " " << *ptr_disas << std::endl;
        }

        std::list<LEVEL_BASE::REG>::iterator reg_it;
        bool tainted = false;

        for(reg_it = ptr_regs_r->begin(); reg_it != ptr_regs_r->end(); reg_it++) {
            tainted |= ptr_taint_data->reg_is_tainted(*reg_it);
        }

        for(reg_it=ptr_regs_w->begin(); reg_it != ptr_regs_w->end(); reg_it++) {
            if(tainted) {
                ptr_taint_data->reg_taint(ip, ptr_disas, *reg_it);
            } else {
                ptr_taint_data->reg_untaint(ip, ptr_disas, *reg_it);
            }
        }
    }
}

VOID CrashData::regs_to_mem(ADDRINT ip, std::string *ptr_disas, 
        std::list<LEVEL_BASE::REG> *ptr_regs, ADDRINT mem, UINT32 size) {
    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;

        if(debug && ptr_taint_data->id == 0) {
            *out << "R2M " << ip << " " << *ptr_disas << std::endl;
            std::set<LEVEL_BASE::REG>::iterator sit;
            *out << "REGS " << std::endl;
            for(sit=ptr_taint_data->tainted_regs.begin(); sit != ptr_taint_data->tainted_regs.end(); sit++) {
                *out << REG_StringShort(*sit) << std::endl;
            }
        }

        std::list<LEVEL_BASE::REG>::iterator reg_it;
        bool tainted = false;

        for(reg_it = ptr_regs->begin(); reg_it != ptr_regs->end(); reg_it++) {
            tainted |= ptr_taint_data->reg_is_tainted(*reg_it);
        }

        if(tainted) {
            if(ptr_taint_data->id == 0) {
                if(debug) {
                    *out << "TAINTED WRITE AT " << ip << std::endl;
                }

                insns[ip].add_flag(Instruction::TAINTED_WRITE);
            } else if(ptr_taint_data->freed && ptr_taint_data->intersects(mem, size)) {
                if(debug) {
                    *out << "HINT: USE AFTER FREE: (w) ";
                    *out << mem << " at " << ip << std::endl;
                }

                insns[ip].add_flag(Instruction::USE_AFTER_FREE);
            }

            ptr_taint_data->mem_taint(ip, ptr_disas, mem, size);
        } else {
            if(ptr_taint_data->id == 0) {
                insns[ip].remove_flag(Instruction::TAINTED_WRITE);
            }
            ptr_taint_data->mem_untaint(ip, ptr_disas, mem, size);
        }
    }
}

VOID CrashData::taint_indirect(ADDRINT ip, std::string *ptr_disas, 
        LEVEL_BASE::REG reg, ADDRINT regval, std::map<ADDRINT, ADDRINT> execd, BOOL isRet) {
    TaintData *ptr_taint_data = taint_data_list.front();

    if(debug && ptr_taint_data->id == 0) {
        *out << "M2R " << ip << " " << *ptr_disas << std::endl;
        *out << "M2R " << REG_StringShort(reg) << std::endl;
    }

    bool mmapd = false;
    ADDRINT target_addr = regval;
    
    if(ptr_taint_data->reg_is_tainted(reg)) {
        if(debug && ptr_taint_data->id == 0) {
            *out << "REG IS TAINTED" << std::endl;
        }
        ptr_taint_data->reg_taint(ip, ptr_disas, REG_INST_PTR);
        if(insns.count(ip)) {
            if(debug && ptr_taint_data->id == 0) {
                *out << "PC TAINT FLAG" << std::endl;
            }
            insns[ip].add_flag(Instruction::PC_TAINT);
        }
    } else {
        if(insns.count(ip)) {
            insns[ip].remove_flag(Instruction::PC_TAINT);
        }
    }

    if(reg == REG_STACK_PTR) {
        if(ptr_taint_data->mem_is_tainted(regval)) {
            ptr_taint_data->reg_taint(ip, ptr_disas, REG_INST_PTR);
            if(insns.count(ip)) {
                insns[ip].add_flag(Instruction::PC_TAINT);
            }
        } else {
            if(insns.count(ip)) {
                insns[ip].remove_flag(Instruction::PC_TAINT);
            }
        }
        
        PIN_SafeCopy(&target_addr, (ADDRINT *)regval, sizeof(ADDRINT));    
    }

    PIN_LockClient();
    bool invalid = IMG_FindByAddress(target_addr) == IMG_Invalid();
    PIN_UnlockClient();

    if(invalid) {
        std::map<ADDRINT, ADDRINT>::iterator it;
        for(it=execd.begin(); it != execd.end(); it++) {
            ADDRINT mmap_start = it->first;
            ADDRINT mmap_size = it->second;
            ADDRINT mmap_end = mmap_start + mmap_size;
            if(target_addr >= mmap_start && target_addr < mmap_end) {
                mmapd = true;
                break;
            }
        }

        if(!mmapd) {
            if(debug && ptr_taint_data->id == 0) {
                *out << "HINT: POSSIBLE BRANCH OR RET TO NON-EXECUTABLE MEMORY: ";
                *out << std::hex << target_addr << " at " << ip << std::endl;
            }
            hint = ip;
            
            if(insns.count(ip)) {
                insns[ip].add_flag(Instruction::DEP);
            }
        } else {
            if(insns.count(ip)) {
                insns[ip].remove_flag(Instruction::DEP);
            }
        }
    }

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end() && !isRet; taint_it++) {
        ptr_taint_data = *taint_it;

        if(ptr_taint_data->id == 0) {
            continue;
        }

        if(ptr_taint_data->freed) {
            if((ptr_taint_data->reg_is_tainted(reg) || ptr_taint_data->mem_is_tainted(regval))
                && ptr_taint_data->intersects(regval, sizeof(ADDRINT))) {

                if(debug) {
                    *out << "HINT: USE AFTER FREE: (e) ";
                    *out << std::hex << target_addr << " at " << ip << std::endl;
                }

                insns[ip].add_flag(Instruction::USE_AFTER_FREE);
            }
        }
    }
}

VOID CrashData::pointer_add(ADDRINT addr, SIZE size) {
    TaintData *ptr_taint_data = new TaintData(taint_data_list.size(), addr, size);
    ptr_taint_data->debug = debug;
    taint_data_list.push_back(ptr_taint_data);
}

UINT CrashData::pointer_active_id(ADDRINT addr) {
    std::list<TaintData*>::iterator it;
    for(it = taint_data_list.begin(); it != taint_data_list.end(); it++) {
        TaintData *ptr_taint_data = *it;
        if(ptr_taint_data->addr == addr) {
            return ptr_taint_data->id;
        }
    }
    return UINT_MAX;
}

VOID CrashData::pointer_free(ADDRINT addr) {
    std::list<TaintData*>::iterator it;
    for(it = taint_data_list.begin(); it != taint_data_list.end(); it++) {
        TaintData *ptr_taint_data = *it;
        if(ptr_taint_data->addr == addr && !ptr_taint_data->freed) {
            ptr_taint_data->freed = true;
            break;
        }
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
        char buf[2048];

        // set the runtime adddress for disassembly 
        xed_uint64_t runtime_address = static_cast<xed_uint64_t>(ip); 

        xed_decoded_inst_dump_xed_format(xedd, buf, 2048, runtime_address);
        if(debug) {
            *out << std::hex << ip << " " << buf << std::endl;
        }
    } else {
        return false;
    }

    return true;
}

bool CrashData::is_branching(xed_iclass_enum_t insn_iclass) {
    switch(insn_iclass) {
        case XED_ICLASS_CALL_FAR:
        case XED_ICLASS_CALL_NEAR:
        case XED_ICLASS_JB:
        case XED_ICLASS_JBE:
        case XED_ICLASS_JL:
        case XED_ICLASS_JLE:
        case XED_ICLASS_JMP:
        case XED_ICLASS_JMP_FAR:
        case XED_ICLASS_JNB:
        case XED_ICLASS_JNBE:
        case XED_ICLASS_JNL:
        case XED_ICLASS_JNLE:
        case XED_ICLASS_JNO:
        case XED_ICLASS_JNP:
        case XED_ICLASS_JNS:
        case XED_ICLASS_JNZ:
        case XED_ICLASS_JO:
        case XED_ICLASS_JP:
        case XED_ICLASS_JRCXZ:
        case XED_ICLASS_JS:
        case XED_ICLASS_JZ:
            return true;
        default:
            break;
    }

    return false;
}

bool CrashData::is_ret(xed_iclass_enum_t insn_iclass) {
    switch(insn_iclass) {
        case XED_ICLASS_RET_FAR:
        case XED_ICLASS_RET_NEAR:
            return true;
        default:
            break;
    }

    return false;
}

VOID CrashData::examine() {
    ADDRINT last_insn = last_addrs.back();

    if(hint != 0) {
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

    if(signal == "SIGILL") {
        if(debug) {
            *out << "DECISION SIGILL" << std::endl;
        }
        
        *reason = "illegal instruction";
        score = 100;
        return;
    }

    if(signal == "SIGFPE") {
        if(debug) {
            *out << "DECISION SIGFPE" << std::endl;
        }
        
        *reason = "floating point exception";
        score = 0;
        return;
    }

    if(signal == "SIGTRAP") {
        if(debug) {
            *out << "DECISION SIGTRAP" << std::endl;
        }

        *reason = "breakpoint";
        score = 25;
        return;
    }

    if(!insns.count(last_insn)) {
        if(debug) {
            *out << "DECISION INSN404" << std::endl;
        }

        *reason = "instruction not found";
        score = 75;
        return;
    }
    
    Instruction insn = insns[last_insn];
    // INS ins = insn.ins;
    string disas = insn.disas; 

    if(debug) {
        *out << "CRASH ON: " << disas << " AT " << last_insn << std::endl;
    }

    xed_decoded_inst_t xedd;
    if(!xed_at(&xedd, last_insn)) {
        if(debug) {
            *out << "DECISION NODECODE" << std::endl;
        }

        *reason = "undecodable instruction";
        score = 75;
        return;
    } 

    xed_iclass_enum_t insn_iclass = xed_decoded_inst_get_iclass(&xedd);
    if(debug) {
        *out << "ICLASS " << xed_iclass_enum_t2str(insn_iclass) << std::endl;
    }

    if(insn.has_flag(Instruction::USE_AFTER_FREE)) {
        if(debug) {
            *out << "DECISION UAF" << std::endl;
        }
        *reason = "use after free";
        score = 100;
        return;   
    }

    if(is_branching(insn_iclass)) {
        if(debug) {
            *out << "DECISION BRANCHING" << std::endl;
        }
        if(insn.has_flag(Instruction::PC_TAINT)) {
            *reason = "branching tainted pc";
            score = 75;
        } else {
            *reason = "branching";
            score = 25;
        }
        return;
    }

    if(is_ret(insn_iclass)) {
        if(debug) {
            *out << "DECISION RET" << std::endl;
        }

        if(insn.has_flag(Instruction::PC_TAINT) || taint_data_list.front()->tainted_regs.count(LEVEL_BASE::REG_STACK_PTR)) {
            score = 100;
            *reason = "return with taint";
        } else {
            *reason = "return";
            score = 75;
        }

        return;
    }

    if(insn.has_flag(Instruction::DEP)) {
        if(debug) {
            *out << "DECISION DEP" << std::endl;
        }
        
        *reason = "data execution prevention";
        score = 75;
        return;
    }

    xed_inst_t *p_xedi = (xed_inst_t *)xed_decoded_inst_inst(&xedd);
    UINT nops = xed_decoded_inst_noperands(&xedd);

    bool written = false;
    bool read = false;

    for(UINT i = 0; i < nops; i++) {
        xed_operand_t *p_xedo = (xed_operand_t *)xed_inst_operand(p_xedi, i);
        switch (xed_operand_name(p_xedo)) {
            case XED_OPERAND_MEM0:
            case XED_OPERAND_MEM1:
                if(xed_operand_operand_visibility(p_xedo) == XED_OPVIS_EXPLICIT) {
                    if(xed_operand_read(p_xedo)) {
                        read = true;
                    }

                    if(xed_operand_written(p_xedo)) {
                        written = true;
                    }
                }
                if(debug) {
                    *out << "MEM OP " << i << " " << xed_operand_name(p_xedo) << std::endl;
                }
                break;
            default:
                continue;
        }
    }

    if(written) {
        if(insn.has_flag(Instruction::TAINTED_WRITE)) {
            if(debug) {
                *out << "DECISION WRITE TAINT" << std::endl;
            }

            *out << __LINE__ << std::endl;
            *reason = "write with taint";
            *out << __LINE__ << std::endl;
            score = 75;
            *out << __LINE__ << std::endl;
        } else {
            if(debug) {
                *out << "DECISION WRITE NOTAINT" << std::endl;
            }

            *reason = "write with no taint";
            score = 50;
        }

        *out << __LINE__ << std::endl;
        return;
    }

    if(read) {
        if(insn.has_flag(Instruction::TAINTED_READ)) {
            if(debug) {
                *out << "DECISION READ TAINT" << std::endl;
            }

            *reason = "read with taint";
            score = 75;
        } else {
            if(debug) {
                *out << "DECISION READ NOTAINT" << std::endl;
            }

            *reason = "read with no taint";
            score = 25;
        }

        return;
    }

    
    if(debug) {
        *out << "DECISION UNKNOWN" << std::endl;
    }

    *reason = "unknown";
    score = 50;
}

/* TODO: json or serialization library */

VOID CrashData::dump_info() {
    rapidjson::StringBuffer s;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(s);

    writer.StartObject();

    writer.Key("score");
    writer.Uint(score);

    writer.Key("reason");
    writer.String(reason->c_str());
    
    writer.Key("signal");
    writer.String(signal.c_str());

    writer.Key("location");
    writer.Uint64(location);

    writer.Key("hint");
    writer.Uint64(hint);


    writer.Key("tainted_regs");
    writer.StartArray();
    std::set<LEVEL_BASE::REG> tainted_regs = taint_data_list.front()->tainted_regs;
    std::set<LEVEL_BASE::REG>::iterator sit;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        writer.String(REG_StringShort(*sit).c_str());
    }
    writer.EndArray();


    writer.Key("tainted_addrs");
    writer.StartArray();
    std::set<ADDRINT> tainted_addrs = taint_data_list.front()->tainted_addrs;
    if(tainted_addrs.size() > 0) {
        std::set<ADDRINT>::iterator mit = tainted_addrs.begin();
        ADDRINT start = *mit;
        UINT64 size = 1;

        mit++;
        for( ; mit != tainted_addrs.end(); mit++) {
            if(*mit > (start+size)) {
                writer.StartObject();
                writer.Key("start");
                writer.Uint64(start);
                writer.Key("size");
                writer.Uint64(size);
                writer.EndObject();

                start = *mit;
                size = 0;
            }
            size++;
        }

        writer.StartObject();
        writer.Key("start");
        writer.Uint64(start);
        writer.Key("size");
        writer.Uint64(size);
        writer.EndObject();
    }
    writer.EndArray();

    writer.Key("last_addrs");
    writer.StartArray();
    std::list<ADDRINT>::iterator lit;
    for(lit=last_addrs.begin(); lit != last_addrs.end(); lit++) {
        writer.Uint64(*lit);
    }
    writer.EndArray();

    writer.Key("last_calls");
    writer.StartArray();
    for(lit=last_calls.begin(); lit != last_calls.end(); lit++) {
        writer.Uint64(*lit);
    }
    writer.EndArray();

    writer.EndObject();

    *out << "#### BEGIN CRASH DATA JSON" << std::endl;
    *out << s.GetString() << std::endl;
    *out << "#### END CRASH DATA JSON" << std::endl;
}