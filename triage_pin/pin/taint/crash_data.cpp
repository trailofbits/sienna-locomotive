#include "crash_data.h"

CrashData::CrashData() : hint(0), out(&std::cout), debug(false), score(50) {
    TaintData *ptr_taint_data = new TaintData(0, 0, 0);
    taint_data_list.push_back(ptr_taint_data);

    last_addrs_head = 0;
    last_calls_head = 0;

    reason = new std::string;
    *reason = "unknown";
}

VOID CrashData::mem_to_reg(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size) {
    std::list<LEVEL_BASE::REG> regs_r = *memory_manager->regs_r[ip];
    std::list<LEVEL_BASE::REG> regs_w = *memory_manager->regs_w[ip];

    std::set<ADDRINT>::iterator alloc_addr_it;
    for(alloc_addr_it = alloc_addr_map[mem].begin(); alloc_addr_it != alloc_addr_map[mem].end(); alloc_addr_it++) {
        std::list<struct AllocInfo>::iterator alloc_info_it;
        for(alloc_info_it = alloc_info_map[*alloc_addr_it].begin(); 
            alloc_info_it != alloc_info_map[*alloc_addr_it].end(); 
            alloc_info_it++) 
        {
            if((*alloc_info_it).free) {
                insns[ip].add_flag(Instruction::POTENTIAL_UAF, out);
                insns[ip].potential_uaf_sizes.insert((*alloc_info_it).size);
            }
        }
    }

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        DBG_OUT_ID0 "M2R " << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;

        bool tainted = false;
        for(UINT32 i=0; i<size; i++) {
            if(ptr_taint_data->mem_is_tainted(mem+i)) {
                tainted = true;
                break;
            }
        }

        std::list<LEVEL_BASE::REG>::iterator it;
        for(it=regs_r.begin(); it != regs_r.end() && !tainted; it++) {
            if(REG_valid(*it) && ptr_taint_data->reg_is_tainted(*it)) {
                if(ptr_taint_data->id == 0) {
                    tainted = true;
                } else if(REG_is_gr(*it) && ptr_taint_data->intersects(PIN_GetContextReg(ctx, *it), 1)) {
                    tainted = true;
                }
            }
        }

        for(it=regs_w.begin(); it != regs_w.end(); it++) {
            REG reg = *it;
            
            if(tainted) {
                if(ptr_taint_data->id == 0) {
                    insns[ip].add_flag(Instruction::TAINTED_READ, out);
                } else if(ptr_taint_data->freed && ptr_taint_data->intersects(mem, size)) {
                    DBG_OUT "HINT: USE AFTER FREE: (r) " << mem << " at " << ip << std::endl << std::flush;
                    insns[ip].add_flag(Instruction::USE_AFTER_FREE, out);
                }

                DBG_OUT_ID0 "TAINTED READ AT " << std::hex << ip << " OF " << mem << std::endl << std::flush;
                DBG_OUT_ID0 "REGm TAINT: " << REG_StringShort(reg) << std::endl << std::flush;

                ptr_taint_data->reg_taint(ip, memory_manager, reg);

                if(debug && ptr_taint_data->id == 0) {
                    DBG_OUT_ID0 "TAINTED REGS:" << std::endl << std::flush;
                    set<LEVEL_BASE::REG>::iterator sit;
                    for(sit=ptr_taint_data->tainted_regs.begin(); sit != ptr_taint_data->tainted_regs.end(); sit++) {
						DBG_OUT_ID0 REG_StringShort(*sit) << std::endl << std::flush;
                    }
                }
                
            } else {
				DBG_OUT_ID0 "M2R2 " << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;
				DBG_OUT_ID0 "REGm UNTAINT: " << reg << " " << REG_StringShort(reg) << std::endl << std::flush;

                if(ptr_taint_data->id == 0) {
                    insns[ip].remove_flag(Instruction::TAINTED_READ, out);
                }

                ptr_taint_data->reg_untaint(ip, memory_manager, reg);

            }
        }
    }
}

VOID CrashData::regs_to_regs(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager) {
    std::list<LEVEL_BASE::REG> regs_r = *memory_manager->regs_r[ip];
    std::list<LEVEL_BASE::REG> regs_w = *memory_manager->regs_w[ip];

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        DBG_OUT_ID0 "R2R " << std::hex << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;

        std::list<LEVEL_BASE::REG>::iterator reg_it;
        bool tainted = false;

        for(reg_it = regs_r.begin(); reg_it != regs_r.end(); reg_it++) {
            if(ptr_taint_data->reg_is_tainted(*reg_it)) {
                if(ptr_taint_data->id == 0) {
                    tainted = true;
                    break;
                } else if(REG_is_gr(*reg_it) && ptr_taint_data->intersects(PIN_GetContextReg(ctx, *reg_it), 1)) {
                    tainted = true;
                    break;
                }
            }
        }

        for(reg_it = regs_w.begin(); reg_it != regs_w.end(); reg_it++) {
            if(tainted) {
                ptr_taint_data->reg_taint(ip, memory_manager, *reg_it);
            } else {
                ptr_taint_data->reg_untaint(ip, memory_manager, *reg_it);
            }
        }
    }
}

VOID CrashData::regs_to_mem(CONTEXT *ctx, ADDRINT ip, MemoryManager *memory_manager, ADDRINT mem, UINT32 size) {
    std::list<LEVEL_BASE::REG> regs_r = *memory_manager->regs_r[ip];

    for(UINT32 i = 0; i < size; i++) {
        std::set<ADDRINT>::iterator alloc_addr_it;
        for(alloc_addr_it = alloc_addr_map[mem+size].begin(); 
            alloc_addr_it != alloc_addr_map[mem+size].end(); 
            alloc_addr_it++) 
        {
            std::list<struct AllocInfo>::iterator alloc_info_it;
            for(alloc_info_it = alloc_info_map[*alloc_addr_it].begin(); 
                alloc_info_it != alloc_info_map[*alloc_addr_it].end(); 
                alloc_info_it++) 
            {
                if((*alloc_info_it).free) {
                    insns[ip].add_flag(Instruction::POTENTIAL_UAF, out);
                    insns[ip].potential_uaf_sizes.insert((*alloc_info_it).size);
                }
            }
        }
    }

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = taint_data_list.begin(); taint_it != taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;

        DBG_OUT_ID0 "R2M " << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;

        std::list<LEVEL_BASE::REG>::iterator reg_it;
        bool tainted = false;

        for(reg_it = regs_r.begin(); reg_it != regs_r.end(); reg_it++) {
            if(ptr_taint_data->reg_is_tainted(*reg_it)) {
                if(ptr_taint_data->id == 0) {
                    tainted = true;
                    break;
                } else if(REG_is_gr(*reg_it) && ptr_taint_data->intersects(PIN_GetContextReg(ctx, *reg_it), 1)) {
                    tainted = true;
                    break;
                }
            }
        }

        if(tainted) {
            if(ptr_taint_data->id == 0) {
                DBG_OUT "TAINTED WRITE AT " << ip << std::endl << std::flush;

                insns[ip].add_flag(Instruction::TAINTED_WRITE, out);
            } else if(ptr_taint_data->freed && ptr_taint_data->intersects(mem, size)) {
                DBG_OUT "HINT: USE AFTER FREE: (w) ";
                DBG_OUT mem << " at " << ip << std::endl << std::flush;

                insns[ip].add_flag(Instruction::USE_AFTER_FREE, out);
            }

            ptr_taint_data->mem_taint(ip, memory_manager, mem, size);
        } else {
            if(ptr_taint_data->id == 0) {
                insns[ip].remove_flag(Instruction::TAINTED_WRITE, out);
            }
            ptr_taint_data->mem_untaint(ip, memory_manager, mem, size);
        }
    }
}

VOID CrashData::taint_indirect(ADDRINT ip, MemoryManager *memory_manager,
    LEVEL_BASE::REG reg, ADDRINT target_addr, std::map<ADDRINT, ADDRINT> execd, BOOL isRet) {
    TaintData *ptr_taint_data = taint_data_list.front();

    DBG_OUT_ID0 "M2R (ind) " << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;
	DBG_OUT_ID0 "M2R (reg) " << REG_StringShort(reg) << std::endl << std::flush;

    bool mmapd = false;
    
    if(ptr_taint_data->reg_is_tainted(reg)) {
        DBG_OUT_ID0 "REG IS TAINTED" << std::endl << std::flush;
        ptr_taint_data->reg_taint(ip, memory_manager, REG_INST_PTR);
        if(insns.count(ip)) {
            DBG_OUT_ID0 "PC TAINT FLAG" << std::endl << std::flush;
            insns[ip].add_flag(Instruction::PC_TAINT, out);
        }
    } else {
        if(insns.count(ip)) {
            insns[ip].remove_flag(Instruction::PC_TAINT, out);
        }
    }

    if(reg == REG_STACK_PTR && !insns[ip].has_flag(Instruction::PC_TAINT)) {
        if(ptr_taint_data->mem_is_tainted(target_addr)) {
            ptr_taint_data->reg_taint(ip, memory_manager, REG_INST_PTR);
            if(insns.count(ip)) {
                insns[ip].add_flag(Instruction::PC_TAINT, out);
            }
        } else {
            if(insns.count(ip)) {
                insns[ip].remove_flag(Instruction::PC_TAINT, out);
            }
        }
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
            DBG_OUT_ID0 "HINT: POSSIBLE BRANCH OR RET TO NON-EXECUTABLE MEMORY: " << std::hex << 
				target_addr << " at " << ip << std::endl << std::flush;
            hint = ip;
            
            if(insns.count(ip)) {
                insns[ip].add_flag(Instruction::DEP, out);
            }
        } else {
            if(insns.count(ip)) {
                insns[ip].remove_flag(Instruction::DEP, out);
            }
        }
    }

    std::set<ADDRINT>::iterator alloc_addr_it;
    for(alloc_addr_it = alloc_addr_map[target_addr].begin(); 
        alloc_addr_it != alloc_addr_map[target_addr].end(); 
        alloc_addr_it++) 
    {
        std::list<struct AllocInfo>::iterator alloc_info_it;
        for(alloc_info_it = alloc_info_map[*alloc_addr_it].begin(); 
            alloc_info_it != alloc_info_map[*alloc_addr_it].end(); 
            alloc_info_it++) 
        {
            if((*alloc_info_it).free) {
                insns[ip].add_flag(Instruction::POTENTIAL_UAF, out);
                insns[ip].potential_uaf_sizes.insert((*alloc_info_it).size);
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
            if((ptr_taint_data->reg_is_tainted(reg) || ptr_taint_data->mem_is_tainted(target_addr))
                && ptr_taint_data->intersects(target_addr, sizeof(ADDRINT))) {

                DBG_OUT "HINT: USE AFTER FREE: (e) ";
                DBG_OUT std::hex << target_addr << " at " << ip << std::endl << std::flush;

                insns[ip].add_flag(Instruction::USE_AFTER_FREE, out);
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
        DBG_OUT std::hex << ip << " " << buf << std::endl << std::flush;
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
    ADDRINT last_insn = last_addrs[last_addrs_head];

    if(hint != 0) {
        bool contains_hint = false;

		for (uint32_t i = 0; i < RECORD_COUNT; i++) {
            if(last_addrs[(last_addrs_head+i)%RECORD_COUNT] == hint) {
                contains_hint = true;
                break;
            }
        }

        if(contains_hint) {
            last_insn = hint;
        }
    }

    location = last_insn;

    if(signal == "SIGILL") {
        DBG_OUT "DECISION SIGILL" << std::endl << std::flush;
        
        *reason = "illegal instruction";
        score = 100;
        return;
    }

    if(signal == "SIGFPE") {
        DBG_OUT "DECISION SIGFPE" << std::endl << std::flush;
        
        *reason = "floating point exception";
        score = 0;
        return;
    }

    if(signal == "SIGTRAP") {
        DBG_OUT "DECISION SIGTRAP" << std::endl << std::flush;

        *reason = "breakpoint";
        score = 25;
        return;
    }

    if(!insns.count(last_insn)) {
        DBG_OUT "DECISION INSN404" << std::endl << std::flush;

        *reason = "instruction not found";
        score = 75;
        return;
    }
    
    Instruction insn = insns[last_insn];
    string disas = insn.disas; 

    DBG_OUT "CRASH ON: " << disas << " AT " << last_insn << std::endl << std::flush;

    xed_decoded_inst_t xedd;
    if(!xed_at(&xedd, last_insn)) {
        DBG_OUT "DECISION NODECODE" << std::endl << std::flush;

        *reason = "undecodable instruction";
        score = 75;
        return;
    } 

    xed_iclass_enum_t insn_iclass = xed_decoded_inst_get_iclass(&xedd);
    DBG_OUT "ICLASS " << xed_iclass_enum_t2str(insn_iclass) << std::endl << std::flush;

    if(insn.has_flag(Instruction::USE_AFTER_FREE)) {
        DBG_OUT "DECISION UAF" << std::endl << std::flush;
        *reason = "use after free";
        score = 100;
        return;   
    }

    if(is_branching(insn_iclass)) {
        DBG_OUT "DECISION BRANCHING" << std::endl << std::flush;
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
        DBG_OUT "DECISION RET" << std::endl << std::flush;

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
        DBG_OUT "DECISION DEP" << std::endl << std::flush;
        
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
                DBG_OUT "MEM OP " << i << " " << xed_operand_name(p_xedo) << std::endl << std::flush;
                break;
            default:
                continue;
        }
    }

    if(written) {
        if(insn.has_flag(Instruction::TAINTED_WRITE)) {
            DBG_OUT "DECISION WRITE TAINT" << std::endl << std::flush;

            *reason = "write with taint";
            score = 75;
        } else {
            DBG_OUT "DECISION WRITE NOTAINT" << std::endl << std::flush;

            *reason = "write with no taint";
            score = 50;
        }

        return;
    }

    if(read) {
        if(insn.has_flag(Instruction::TAINTED_READ)) {
            DBG_OUT "DECISION READ TAINT" << std::endl << std::flush;

            *reason = "read with taint";
            score = 75;
        } else {
            DBG_OUT "DECISION READ NOTAINT" << std::endl << std::flush;

            *reason = "read with no taint";
            score = 25;
        }

        return;
    }

    
    DBG_OUT "DECISION UNKNOWN" << std::endl << std::flush;

    *reason = "unknown";
    score = 50;
}

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
    set<LEVEL_BASE::REG> tainted_regs = taint_data_list.front()->tainted_regs;
    set<LEVEL_BASE::REG>::iterator sit;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        writer.String(REG_StringShort(*sit).c_str());
    }
    writer.EndArray();


    writer.Key("tainted_addrs");
    writer.StartArray();
    set<ADDRINT> tainted_addrs = taint_data_list.front()->tainted_addrs;
    if(tainted_addrs.size() > 0) {
        set<ADDRINT>::iterator mit = tainted_addrs.begin();
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
	for (uint32_t i = 0; i < RECORD_COUNT; i++) {
		writer.Uint64(last_addrs[(last_addrs_head - i) % RECORD_COUNT]);
	}
    writer.EndArray();

    writer.Key("last_calls");
    writer.StartArray();
	for (uint32_t i = 0; i < RECORD_COUNT; i++) {
		writer.Uint64(last_calls[(last_calls_head - i) % RECORD_COUNT]);
	}
    writer.EndArray();

    writer.EndObject();

    *out << "#### BEGIN CRASH DATA JSON" << std::endl << std::flush;
    *out << s.GetString() << std::endl << std::flush;
    *out << "#### END CRASH DATA JSON" << std::endl << std::flush;

    string uaf_reason = "use after free";
    if(insns[location].has_flag(Instruction::POTENTIAL_UAF) && reason->compare(uaf_reason) != 0) {
        *out << "#### POTENTIAL UAF DETECTED - RERUN WITH FLAG(S): ";
        std::set<UINT64>::iterator potential_uaf_it;
        for(potential_uaf_it = insns[location].potential_uaf_sizes.begin(); 
            potential_uaf_it != insns[location].potential_uaf_sizes.end(); 
            potential_uaf_it++) 
        {
            *out << "-uaf " << *potential_uaf_it << " ";
        }
        *out << std::endl << std::flush;
    }
}