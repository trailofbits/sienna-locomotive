#pragma once
#include <Windows.h>
#include <unordered_map>
#include <list>

struct Instruction {
	BYTE bytes[15];
	BYTE length;
};

struct BasicBlock {
	UINT64 head;
	UINT64 tail;
	BYTE *bbTrace;
	DWORD traceSize;
};

class Cache {
public:
	Cache();
	BOOL AddBB(struct BasicBlock bb);
	BOOL HasBB(UINT64 address);
	struct BasicBlock FetchBB(UINT64 address);
private:
	std::unordered_map<UINT64, struct BasicBlock> cache;
};