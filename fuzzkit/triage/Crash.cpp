#include "Crash.h"

BOOL Crash::xed_at(xed_decoded_inst_t *xedd) {
#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif

	xed_decoded_inst_zero_set_mode(xedd, &dstate);

	xed_error_enum_t xed_err = xed_decode(xedd, insnBytes, insnLength);
	if (xed_err == XED_ERROR_NONE) {
		char buf[2048];

		// set the runtime adddress for disassembly 
		xed_uint64_t runtime_address = static_cast<xed_uint64_t>(exceptionAddr);

		xed_decoded_inst_dump_xed_format(xedd, buf, 2048, runtime_address);
	}
	else {
		return false;
	}

	return true;
}

bool Crash::is_branching(xed_iclass_enum_t insn_iclass) {
	switch (insn_iclass) {
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

bool Crash::is_ret(xed_iclass_enum_t insn_iclass) {
	switch (insn_iclass) {
	case XED_ICLASS_RET_FAR:
	case XED_ICLASS_RET_NEAR:
		return true;
	default:
		break;
	}

	return false;
}

Crash::Crash(triton::API &api, triton::arch::Instruction *insn, UINT8 insnBytes[], BYTE insnLength, UINT64 exceptionAddr, DWORD exceptionCode)
	: insn(insn), insnLength(insnLength), exceptionAddr(exceptionAddr), exceptionCode(exceptionCode)
{
	if (insnLength > 15) {
		LOG_F(ERROR, "Initialization with insn length > buf size");
		exit(1);
	}
	
	memcpy(this->insnBytes, insnBytes, insnLength);
	reason = "unknown";
	score = 50;

	std::set<const triton::arch::Register *> pTaintedRegs = api.getTaintedRegisters();
	std::set<const triton::arch::Register *>::iterator regIt;
	for (regIt = pTaintedRegs.begin(); regIt != pTaintedRegs.end(); regIt++) {
		taintedRegs.emplace(*(*regIt));
	}

	std::set<UINT64> taintedMems = api.getTaintedMemory();
	std::set<UINT64>::iterator memIt;
	for (memIt = taintedMems.begin(); memIt != taintedMems.end(); memIt++) {
		taintedAddrs.insert(*memIt);
	}

	examine(api);
}

VOID Crash::examine(triton::API &api) {
	if (exceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		reason = "illegal instruction";
		score = 100;
		return;
	}

	if (exceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
		reason = "floating point exception";
		score = 0;
		return;
	}

	if (exceptionCode == EXCEPTION_BREAKPOINT) {
		reason = "breakpoint";
		score = 25;
		return;
	}

	xed_decoded_inst_t xedd;
	if (!xed_at(&xedd)) {
		reason = "undecodable instruction";
		score = 75;
		return;
	}

	xed_iclass_enum_t insn_iclass = xed_decoded_inst_get_iclass(&xedd);
	BOOL pcTaint = api.isRegisterTainted(api.getRegister(triton::arch::ID_REG_RIP));
	BOOL stackTaint = api.isRegisterTainted(api.getRegister(triton::arch::ID_REG_RSP));

	if (is_branching(insn_iclass)) {
		if (pcTaint) {
			reason = "branching tainted pc";
			score = 75;
		}
		else {
			reason = "branching";
			score = 25;
		}
		return;
	}

	if (is_ret(insn_iclass)) {
		if (pcTaint || stackTaint) {
			score = 100;
			reason = "return with taint";
		}
		else {
			reason = "return";
			score = 75;
		}

		return;
	}

	xed_inst_t *p_xedi = (xed_inst_t *)xed_decoded_inst_inst(&xedd);
	UINT nops = xed_decoded_inst_noperands(&xedd);

	bool written = insn->isMemoryWrite();
	bool read = insn->isMemoryRead();
	bool tainted = false;

	std::set<std::pair<triton::arch::Register, triton::ast::AbstractNode *>>::iterator regIt;
	std::set<std::pair<triton::arch::MemoryAccess, triton::ast::AbstractNode *>>::iterator memIt;

	std::set<std::pair<triton::arch::Register, triton::ast::AbstractNode *>> readRegs = insn->getReadRegisters();
	for (regIt = readRegs.begin(); regIt != readRegs.end(); regIt++) {
		if (api.isRegisterTainted(regIt->first)) {
			tainted = true;
		}
	}

	std::set<std::pair<triton::arch::MemoryAccess, triton::ast::AbstractNode *>> storeAccesses = insn->getStoreAccess();
	for (memIt = storeAccesses.begin(); memIt != storeAccesses.end(); memIt++) {
		if (api.isMemoryTainted(memIt->first) || 
			api.isRegisterTainted(memIt->first.getConstBaseRegister()) || 
			api.isRegisterTainted(memIt->first.getConstSegmentRegister()) || 
			api.isRegisterTainted(memIt->first.getConstIndexRegister())) 
		{
			tainted = true;
		}
	}

	std::set<std::pair<triton::arch::MemoryAccess, triton::ast::AbstractNode *>> loadAccesses = insn->getLoadAccess();
	for (memIt = loadAccesses.begin(); memIt != loadAccesses.end(); memIt++) {
		if (api.isMemoryTainted(memIt->first) ||
			api.isRegisterTainted(memIt->first.getConstBaseRegister()) ||
			api.isRegisterTainted(memIt->first.getConstSegmentRegister()) ||
			api.isRegisterTainted(memIt->first.getConstIndexRegister())) 
		{
			tainted = true;
		}
	}

	if (written) {
		if (tainted) {
			reason = "write with taint";
			score = 75;
		}
		else {
			reason = "write with no taint";
			score = 50;
		}

		return;
	}

	if (read) {
		if (tainted) {
			reason = "read with taint";
			score = 75;
		}
		else {
			reason = "read with no taint";
			score = 25;
		}

		return;
	}

	reason = "unknown";
	score = 50;
}

std::string Crash::exceptionToString() {
	std::string exceptionStr = "UNKNOWN";
	switch (exceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			exceptionStr = "EXCEPTION_ACCESS_VIOLATION";
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			exceptionStr = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
			break;
		case EXCEPTION_BREAKPOINT:
			exceptionStr = "EXCEPTION_BREAKPOINT";
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			exceptionStr = "EXCEPTION_DATATYPE_MISALIGNMENT";
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			exceptionStr = "EXCEPTION_FLT_DENORMAL_OPERAND";
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			exceptionStr = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			exceptionStr = "EXCEPTION_FLT_INEXACT_RESULT";
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			exceptionStr = "EXCEPTION_FLT_INVALID_OPERATION";
			break;
		case EXCEPTION_FLT_OVERFLOW:
			exceptionStr = "EXCEPTION_FLT_OVERFLOW";
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			exceptionStr = "EXCEPTION_FLT_STACK_CHECK";
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			exceptionStr = "EXCEPTION_FLT_UNDERFLOW";
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			exceptionStr = "EXCEPTION_ILLEGAL_INSTRUCTION";
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			exceptionStr = "EXCEPTION_IN_PAGE_ERROR";
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			exceptionStr = "EXCEPTION_INT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_INT_OVERFLOW:
			exceptionStr = "EXCEPTION_INT_OVERFLOW";
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			exceptionStr = "EXCEPTION_INVALID_DISPOSITION";
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			exceptionStr = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			exceptionStr = "EXCEPTION_PRIV_INSTRUCTION";
			break;
		case EXCEPTION_SINGLE_STEP:
			exceptionStr = "EXCEPTION_SINGLE_STEP";
			break;
		case EXCEPTION_STACK_OVERFLOW:
			exceptionStr = "EXCEPTION_STACK_OVERFLOW";
			break;
		default:
			break;
	}

	return exceptionStr;
}

std::string Crash::dumpInfo() {
	rapidjson::StringBuffer s;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(s);

	writer.StartObject();

	writer.Key("score");
	writer.Uint(score);

	writer.Key("reason");
	writer.String(reason.c_str());

	writer.Key("exception");
	writer.String(exceptionToString().c_str());

	writer.Key("location");
	writer.Uint64(exceptionAddr);

	writer.Key("disassembly");
	writer.String(insn->getDisassembly().c_str());

	writer.Key("tainted_regs");
	writer.StartArray();
	std::set<triton::arch::Register>::iterator taintedRegsIt;
	for (taintedRegsIt = taintedRegs.begin(); taintedRegsIt != taintedRegs.end(); taintedRegsIt++) {
		writer.String(taintedRegsIt->getName().c_str());
	}
	writer.EndArray();

	writer.Key("tainted_addrs");
	writer.StartArray();
	if (taintedAddrs.size() > 0) {
		std::set<UINT64>::iterator mit = taintedAddrs.begin();
		UINT64 start = *mit;
		UINT64 size = 1;

		mit++;
		for (; mit != taintedAddrs.end(); mit++) {
			if (*mit > (start + size)) {
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

	// TODO: dump register values

	writer.EndObject();

	std::cout << "#### BEGIN CRASH DATA JSON" << std::endl;
	std::cout << s.GetString() << std::endl;
	std::cout << "#### END CRASH DATA JSON" << std::endl;
	LOG_F(INFO, s.GetString());
	return s.GetString();
}