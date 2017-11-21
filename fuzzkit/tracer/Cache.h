#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <map>
#include <list>

struct Instruction {
	BYTE bytes[15];
	BYTE length;
};

struct BasicBlock {
	UINT64 head;
	UINT64 tail;
	std::list<struct Instruction> insnList;
};

class Cache {
public:
	Cache();
	BOOL AddBB(struct BasicBlock bb);
	BOOL HasBB(UINT64 address);
	struct BasicBlock FetchBB(UINT64 address);
private:
	std::map<UINT64, struct BasicBlock> cache;
};