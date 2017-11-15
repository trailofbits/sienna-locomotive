// tracer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <list>
/*
Trace:
	Single step instructions
	At each address get instruction context
	Use value in PC to get instruction bytes
	If non-branching maybe save some time by using next insn address to get length
	Alt: Pass bytes to xed to get opcode length
	Log address, opcode, and length (for Triton inst)
*/

int trap_card(std::list<HANDLE> threads) {
	std::list<HANDLE>::iterator threadIt;
	CONTEXT context;
	
	for (threadIt = threads.begin(); threadIt != threads.end(); threadIt++) {
		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(*threadIt, &context);
		context.EFlags = context.EFlags | (1 << 8);
		if (!SetThreadContext(*threadIt, &context)) {
			printf("ERROR: SetThreadContext (%x)\n", GetLastError());
		}
	}
	
	return 0;
}

int debug_main_loop() {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	std::list<HANDLE> threads;
	UINT64 count = 0;
	for (;;)
	{
		DEBUG_EVENT dbgev;

		WaitForDebugEvent(&dbgev, INFINITE);
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
				exit(1);
				break;
			case EXCEPTION_BREAKPOINT:
				printf("BREAK AT %x\n", address);
				//threads.clear();
				//threads.push_back(cpdi.hThread);
				trap_card(threads);
				break;
			case EXCEPTION_DATATYPE_MISALIGNMENT:
				printf("DATA AT %x\n", address);
				break;
			case EXCEPTION_SINGLE_STEP:
				//printf("SINGLE STEP AT %x\n", address);
				count++;
				trap_card(threads);
				if (count % 10000 == 0) {
					printf("COUNT: %x\n", count);
				}
				break;
			case DBG_CONTROL_C:
				printf("DBG AT %x\n", address);
				break;
			default:
				break;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			threads.push_back(dbgev.u.CreateThread.hThread);
			printf("CREATE THREAD\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf("CREATE PROC\n");
			cpdi = dbgev.u.CreateProcessInfo;
			//DebugBreakProcess(cpdi.hProcess);
			// TODO: set the trap eflag every instruction ?
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			printf("EXIT THREAD\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("EXIT PROC (%x)\n", count);
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			exit(0);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			printf("LOAD DLL\n");
			LOAD_DLL_DEBUG_INFO lddi = dbgev.u.LoadDll;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			printf("UNLOAD DLL\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			printf("OUT DBG\n");
			break;
		case RIP_EVENT:
			printf("RIP\n");
			break;
		}

		ContinueDebugEvent(dbgev.dwProcessId,
			dbgev.dwThreadId,
			dwContinueStatus);
	}
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

	ResumeThread(pi.hThread);
	debug_main_loop();

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}