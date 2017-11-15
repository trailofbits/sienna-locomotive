// tracer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <list>
#include <map>
extern "C" {
#include "include/xed-interface.h"
}

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

std::map<LPVOID, BYTE> restoreBytes;

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

int setBreak(CREATE_PROCESS_DEBUG_INFO cpdi) {
	BYTE breakByte = 0xCC;
	BYTE startByte;
	ReadProcessMemory(cpdi.hProcess, cpdi.lpStartAddress, &startByte, sizeof(BYTE), NULL);
	WriteProcessMemory(cpdi.hProcess, cpdi.lpStartAddress, &breakByte, sizeof(BYTE), NULL);
	restoreBytes[cpdi.lpStartAddress] = startByte;
	return 0;
}

int restoreBreak(HANDLE hProcess, HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	printf("RIP: %x\n", context.Rip);
	context.Rip -= 1;
	SetThreadContext(hThread, &context);
	
	WriteProcessMemory(hProcess, (LPVOID)context.Rip, &restoreBytes[(LPVOID)context.Rip], sizeof(BYTE), NULL);

	return 0;
}

int getLength(HANDLE hProcess, PVOID address) {
	xed_decoded_inst_t xedd;
	BYTE buf[15];
	xed_error_enum_t xed_err;
	ReadProcessMemory(hProcess, address, buf, 15, NULL);
	
	xed_decoded_inst_zero(&xedd);
	xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
	xed_err = xed_decode(&xedd, buf, 15);

	//printf("INSN: %x %x\n", address, xedd._decoded_length);
	//for (int i = 0; i < 15; i++) {
	//	printf("%x ", buf[i]);
	//}
	//printf("\n");
	//printf("ERR: %s\n", xed_error_enum_t2str(xed_err));
	//
	//CHAR outBuf[1024];
	////xed_decoded_inst_dump(&xedd, outBuf, 1024);
	//xed_format_context(XED_SYNTAX_INTEL, &xedd, outBuf, 1024, 0, 0, 0);
	//printf("%s\n\n", outBuf);

	return xedd._decoded_length;
}

int debug_main_loop() {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	std::map<DWORD, HANDLE> threadMap;
	xed_tables_init();
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
				if (address == cpdi.lpStartAddress) {
					printf("!!! AT START: %x\n", address);
					restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId]);
					singleStep(threadMap[dbgev.dwThreadId]);
					getLength(cpdi.hProcess, address);
				}
				break;
			case EXCEPTION_DATATYPE_MISALIGNMENT:
				break;
			case EXCEPTION_SINGLE_STEP:
				singleStep(threadMap[dbgev.dwThreadId]);
				getLength(cpdi.hProcess, address);
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
			setBreak(cpdi);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			printf("EXIT THREAD\n");
			threadMap.erase(dbgev.dwThreadId);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("EXIT PROC\n");
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			exit(0);
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

	DebugBreakProcess(pi.hProcess);
	//trap_card(threadMap);

	ResumeThread(pi.hThread);
	debug_main_loop();

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}