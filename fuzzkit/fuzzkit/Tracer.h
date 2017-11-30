#include "Windows.h"
#include <list>
#include <unordered_map>
#include "Cache.h"
extern "C" {
#include "xed-interface.h"
}

class Tracer {
public:
	Tracer(LPCTSTR traceName);
	DWORD TraceMainLoop(DWORD runId);
	DWORD Tracer::addThread(DWORD dwThreadId, HANDLE hThread);
private:
	std::unordered_map<LPVOID, BYTE> restoreBytes;
	HANDLE hTraceFile;
	Cache cache;
	HANDLE hHeap;
	std::unordered_map<DWORD, HANDLE> threadMap;
	UINT64 trace(HANDLE hProcess, PVOID address);
	DWORD singleStep(HANDLE hThread);
	DWORD setBreak(HANDLE hProcess, UINT64 address);
	BOOL restoreBreak(HANDLE hProcess, HANDLE hThread);
	BOOL isTerminator(xed_decoded_inst_t xedd);
};