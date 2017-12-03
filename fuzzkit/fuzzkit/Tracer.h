#include <Windows.h>
#include <DbgHelp.h>
#include <list>
#include <unordered_map>
#include <map>
#include "Cache.h"
#include "Injector.h"
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
	//HANDLE hTraceFile;
	Cache cache;
	HANDLE hHeap;
	std::unordered_map<DWORD, HANDLE> threadMap;
	HANDLE hPipeInsn;

	HANDLE tracerGetPipeInsn(DWORD runId);
	DWORD traceInit(DWORD runId, HANDLE hProc, DWORD procId);
	DWORD traceInsn(DWORD runId, UINT64 addr, UINT64 traceSize, BYTE * trace);
	DWORD traceCrash(DWORD runId, UINT64 exceptionAddr, DWORD exceptionCode);
	UINT64 trace(HANDLE hProcess, PVOID address, DWORD runId);
	DWORD singleStep(HANDLE hThread);
	DWORD setBreak(HANDLE hProcess, UINT64 address);
	BOOL restoreBreak(HANDLE hProcess, HANDLE hThread);
	BOOL isTerminator(xed_decoded_inst_t xedd);
	HANDLE tracerGetPipe();
};