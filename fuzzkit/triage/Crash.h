#pragma once

#include <set>
#include <utility>
#include <string>
#include <Windows.h>

#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "triton/api.hpp"
#include "triton/x86Specifications.hpp"

extern "C" {
#include "xed-interface.h"
}

class Crash {
public:
	Crash(triton::API &api, triton::arch::Instruction *insn, UINT8 insnBytes[], BYTE insnLength, UINT64 exceptionAddr, DWORD exceptionCode);
	VOID dumpInfo();
private:
	triton::arch::Instruction *insn;
	UINT8 insnBytes[15] = { 0 };
	BYTE insnLength;
	UINT64 exceptionAddr;
	DWORD exceptionCode;

	std::set<triton::arch::Register> taintedRegs;
	std::set<UINT64> taintedAddrs;
	std::string reason;
	BYTE score;

	VOID examine(triton::API &api);
	BOOL xed_at(xed_decoded_inst_t * xedd);
	bool is_branching(xed_iclass_enum_t insn_iclass);
	bool is_ret(xed_iclass_enum_t insn_iclass);
	std::string exceptionToString();
};