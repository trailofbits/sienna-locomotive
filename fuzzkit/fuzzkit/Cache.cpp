#include "stdafx.h"
#include "Cache.h"

Cache::Cache()
{
}

BOOL Cache::AddBB(struct BasicBlock bb)
{
	cache[bb.head] = bb;
	return true;
}

BOOL Cache::HasBB(UINT64 address)
{
	return cache.find(address) != cache.end();
}

struct BasicBlock Cache::FetchBB(UINT64 address)
{
	return cache[address];
}
