// tracer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <list>
#include <map>
#include "Cache.h"
extern "C" {
#include "include/xed-interface.h"
}

// TODO: ascii art tracer

/*
Trace:
	Single step instructions
	At each address get instruction context
	Use value in PC to get instruction bytes
	If non-branching maybe save some time by using next insn address to get length
	Alt: Pass bytes to xed to get opcode length
	Log address, opcode, and length (for Triton inst)
*/

/*
Profiler:
	Break on start
	Restore breakpoint
loop:
	Check have basic block at address
	If have address:
		Set break on end of bb
		Record trace (bb)
		Restore breakpoint
		Set single step for branch
	Don't have address:
		Single step until control flow insn 
		OR Walk forward through memory until control flow insn
		Store bb by address
		Record trace (bb)
		Set single step for branch
	
	GOTO loop

*/

// cache:
	// address head (lookup)
	// list addresses and lengths
	// address tail (break)
	// note: make base address agnostic for speed after first run

std::map<LPVOID, BYTE> restoreBytes;
HANDLE hTraceFile;

int singleStep(HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &context);
	context.EFlags = context.EFlags | (1 << 8);

	if (!SetThreadContext(hThread, &context)) {
		printf("ERROR: SetThreadContext (%x)\n", GetLastError());
		return 1;
	}

	ResumeThread(hThread);
	return 0;
}

int setBreak(HANDLE hProcess, UINT64 address) {
	BYTE breakByte = 0xCC;
	BYTE startByte;
	ReadProcessMemory(hProcess, (LPVOID)address, &startByte, sizeof(BYTE), NULL);
	WriteProcessMemory(hProcess, (LPVOID)address, &breakByte, sizeof(BYTE), NULL);
	restoreBytes[(LPVOID)address] = startByte;
	//printf("INFO: setBreak at %x\n", address);
	return 0;
}

BOOL restoreBreak(HANDLE hProcess, HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	//printf("RIP: %x\n", context.Rip);
	
	context.Rip -= 1;

	if (restoreBytes.find((LPVOID)context.Rip) == restoreBytes.end()) {
		printf("ERROR: restoreBytes miss at %x\n", context.Rip);
		return false;
	}
		
	SetThreadContext(hThread, &context);
	WriteProcessMemory(hProcess, (LPVOID)context.Rip, &restoreBytes[(LPVOID)context.Rip], sizeof(BYTE), NULL);
	
	return true;
}

BOOL isTerminator(xed_decoded_inst_t xedd) {
	xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xedd);

	switch (iclass) {
		case XED_ICLASS_RET_NEAR:
		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_AMD:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_BOUND:
		case XED_ICLASS_CALL_NEAR:
		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_JMP:
		case XED_ICLASS_JMP_FAR:
		case XED_ICLASS_XEND:
		case XED_ICLASS_XABORT:
		case XED_ICLASS_HLT:
		case XED_ICLASS_UD2:
		case XED_ICLASS_INVALID:
			return true;
		default:
			break;
	}

	if (XED_ICLASS_IRET <= iclass && XED_ICLASS_IRETQ >= iclass) {
		return true;
	}

	xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
	if (XED_CATEGORY_COND_BR == cat ||
		XED_CATEGORY_NOP == cat ||
		XED_CATEGORY_WIDENOP == cat) 
	{
		return true;
	}

	return false;
}

Cache cache;

UINT64 trace(HANDLE hProcess, PVOID address) {
	// check cache

	//If have address:
	//	Set break on end of bb
	//	Record trace (bb)
	struct BasicBlock bb;
	if (cache.HasBB((UINT64)address)) {
		//printf("HIT: found bb at %x\n", address);
		bb = cache.FetchBB((UINT64)address);
	}
	else {
		bb.head = (UINT64)address;
		
		xed_decoded_inst_t xedd;
		xedd._decoded_length = 0;
		UINT64 currAddr = (UINT64)address;
		
		do {
			currAddr += xedd._decoded_length;
			struct Instruction insn;
			xed_error_enum_t xed_err;
			ReadProcessMemory(hProcess, (LPVOID)currAddr, insn.bytes, 15, NULL);

			xed_decoded_inst_zero(&xedd);
			xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
			xed_err = xed_decode(&xedd, insn.bytes, 15);
			insn.length = xedd._decoded_length;
			bb.insnList.push_back(insn);
			
			//CHAR outBuf[1024];
			//xed_decoded_inst_dump(&xedd, outBuf, 1024);
			//xed_format_context(XED_SYNTAX_INTEL, &xedd, outBuf, 1024, 0, 0, 0);
			//printf("%s\n", outBuf);
		} while (!isTerminator(xedd));
		
		bb.tail = currAddr;
		cache.AddBB(bb);
		//printf("MISS: new bb at %x to %x\n", address, currAddr);
	}
	//Don't have address:
	//	Walk forward through memory until control flow insn
	//	Set break on end of bb
	//	Store bb by address
	//	Record trace (bb)

	std::list<struct Instruction>::iterator insnIt;
	for (insnIt = bb.insnList.begin(); insnIt != bb.insnList.end(); insnIt++) {
		DWORD bytesWritten;
		WriteFile(hTraceFile, &(insnIt->length), 1, &bytesWritten, NULL);
		WriteFile(hTraceFile, insnIt->bytes, insnIt->length, &bytesWritten, NULL);
	}

	return bb.tail;
}

std::map<DWORD, HANDLE> threadMap;

int debug_main_loop() {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	xed_tables_init();
	for (;;)
	{
		DEBUG_EVENT dbgev;
		WaitForDebugEvent(&dbgev, INFINITE);
		UINT64 tail;

		//printf("DEBUG EVENT: %d\n", dbgev.dwDebugEventCode);

		switch (dbgev.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			PVOID address;
			address = dbgev.u.Exception.ExceptionRecord.ExceptionAddress;
			switch (dbgev.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				printf("SEGGY AT %x\n", address);
				return 0;
				break;
			case EXCEPTION_BREAKPOINT:
				//printf("BREAK AT %x\n", address);
				if (address == cpdi.lpStartAddress) {
					printf("!!! AT START: %x\n", address);
				}
				if (restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId])) {
					tail = trace(cpdi.hProcess, address);
					if (tail == (UINT64)address) {
						singleStep(threadMap[dbgev.dwThreadId]);
					}
					else {
						setBreak(cpdi.hProcess, tail);
					}
				}
				break;
			case EXCEPTION_DATATYPE_MISALIGNMENT:
				break;
			case EXCEPTION_SINGLE_STEP:
				tail = trace(cpdi.hProcess, address);
				if (tail == (UINT64)address) {
					singleStep(threadMap[dbgev.dwThreadId]);
				}
				else {
					setBreak(cpdi.hProcess, tail);
				}
				break;
			case DBG_CONTROL_C:
				break;
			default:
				break;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			threadMap[dbgev.dwThreadId] = dbgev.u.CreateThread.hThread;
			//trap_card(threadMap);
			printf("CREATE THREAD\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf("CREATE PROC\n");
			cpdi = dbgev.u.CreateProcessInfo;
			setBreak(cpdi.hProcess, (UINT64)cpdi.lpStartAddress);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			printf("EXIT THREAD\n");
			threadMap.erase(dbgev.dwThreadId);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("EXIT PROC\n");
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			return 0;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		case RIP_EVENT:
			break;
		}

		ContinueDebugEvent(dbgev.dwProcessId,
			dbgev.dwThreadId,
			dwContinueStatus);
	}
	return 0;
}

int run(LPCTSTR name, LPCTSTR traceName) {
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	// TODO: use args
	BOOL success = CreateProcess(
		name,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS | CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (!success) {
		printf("ERROR: CreateProcess (%x)\n", GetLastError());
		return 1;
	}

	hTraceFile = CreateFile(traceName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTraceFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}

	threadMap[pi.dwThreadId] = pi.hThread;
	DebugBreakProcess(pi.hProcess);
	//trap_card(threadMap);

	ResumeThread(pi.hThread);
	debug_main_loop();

	CloseHandle(hTraceFile);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}

int getTime() {
	SYSTEMTIME st;

	GetSystemTime(&st);
	printf("TIME (MM:SS:MS): %02d:%02d:%02d\n", st.wMinute, st.wSecond, st.wMilliseconds);

	return 0;
}

int main()
{
	int argc;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if (argc < 2) {
		printf("USAGE: \t%S TARGET_PROGRAM.EXE \"[ARGUMENTS]\"\n", argv[0]);
		return 1;
	}

	LPCTSTR name = argv[1];
	LPTSTR args = L"";

	if (argc > 2) {
		args = argv[2];
	}

	// TODO: why is it a non-deterministic amount of runtime after end of main?
	// can we detect and kill the process after core functionality has been executed?
	// this issue may be largely addressed with a program that crashes
	// investigation may prove useful for fuzzing loops though
	printf("RUN 1\n");
	getTime();
	run(name, L"trace1.bin");
	getTime();
	printf("RUN 2\n");
	getTime();
	run(name, L"trace2.bin");
	getTime();
	return 0;
}
