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
	UINT64 exceptionAddr;
	DWORD exceptionCode;
	UINT8 insnBytes[15] = { 0 };
	BYTE insnLength;
	triton::arch::Instruction *insn;

	std::string reason;
	BYTE score;

	Crash(triton::arch::Instruction *insn, UINT8 insnBytes[], BYTE insnLength, UINT64 exceptionAddr, DWORD exceptionCode);
	VOID examine(triton::API & api);
	VOID dumpInfo();
private:
	BOOL xed_at(xed_decoded_inst_t * xedd);
	bool is_branching(xed_iclass_enum_t insn_iclass);
	bool is_ret(xed_iclass_enum_t insn_iclass);
	std::string exceptionToString();
};