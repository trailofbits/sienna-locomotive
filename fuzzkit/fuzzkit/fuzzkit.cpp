// fuzzkit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <stdlib.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <string> 
#include <map>
#include <list>

#include "ImportHandler.h"
#include "Injector.h"

// TODO: check return of every call
// TODO: support 32bit

#define IFNERR(call) if(!call) { printf("ERROR: %s:%d %d\n", __FILE__, __LINE__, GetLastError()); exit(1); }

int walk_imports(HANDLE hProcess, PVOID lpBaseOfImage) {
	ImportHandler importHandler(hProcess, lpBaseOfImage);
	while (1) {
		std::string moduleName = importHandler.GetNextModule();
		if (moduleName == "") {
			break;
		}
		printf("%s\n", moduleName.c_str());

		while (1) {
			std::string functionName = importHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}

			printf("\t%x\t%s\n", importHandler.GetFunctionAddr(), functionName.c_str());
		}
	}
	return 0;
}

DWORD handleInjection(CREATE_PROCESS_DEBUG_INFO cpdi, DWORD runId) {
	std::map<std::string, std::string> hookMap;
	hookMap["ReadFileHook"] = "ReadFile";
	Injector injector(cpdi.hProcess, cpdi.lpBaseOfImage, "injectable.dll", hookMap);
	injector.Inject(runId);

	// TODO: 
	// while have missing
		// get map<base, missing modules>
		// search for dlls
		// load each
		// add child missing to map
		// fixup
	// ALT: recursion?

	return 0;
}

int debug_main_loop(DWORD runId) {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;

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
					printf("EAV: winning\n");
					// TODO: log crash
					exit(1);
					break;
				case EXCEPTION_BREAKPOINT:
					// TODO: breakpoint on start address
					handleInjection(cpdi, runId);
					break;
				case EXCEPTION_DATATYPE_MISALIGNMENT:
					break;
				case EXCEPTION_SINGLE_STEP:
					break;
				case DBG_CONTROL_C:
					break;
				default:
					break;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			cpdi = dbgev.u.CreateProcessInfo;
			//printf("START ADDR %x\n", cpdi.lpStartAddress);
			DebugBreakProcess(cpdi.hProcess);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			// TODO: exit when all processes have exited
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

DWORD getRunID(HANDLE hPipe) {
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	
	BYTE eventId = 0;
	DWORD runId = 0;
	TransactNamedPipe(hPipe, &eventId, sizeof(BYTE), &runId, sizeof(DWORD), &bytesRead, NULL);
	printf("INFO: runId %x\n", runId);
	return runId;
}

HANDLE getPipe() {
	HANDLE hPipe = CreateFile(
		L"\\\\.\\pipe\\fuzz_server",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		// TODO: fallback mutations?
		printf("ERROR: could not connect to server\n");
		exit(1);
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hPipe,
		&readMode,
		NULL,
		NULL);

	return hPipe;
}

DWORD printUsage(LPWSTR *argv) {
	printf("USAGE: \t%S [-r ID] TARGET_PROGRAM.EXE \"[ARGUMENTS]\"\n", argv[0]);
	return 0;
}

struct parsedArgs {
	LPCTSTR targetName;
	LPTSTR targetArgs;
	BOOL replay;
	DWORD runId;
};

struct parsedArgs parseArgs(LPWSTR *argv, int argc) {
	struct parsedArgs args;
	
	if (argc < 2) {
		printUsage(argv);
		exit(1);
	}

	DWORD progIdx = 1;
	if (lstrcmp(argv[1], L"-r") == 0) {
		if (argc < 4) {
			printUsage(argv);
			exit(1);
		}

		args.replay = true;
		args.runId = wcstoul(argv[2], NULL, NULL);
		progIdx = 3;
	}
	else {
		args.replay = false;
		args.runId = 0;
	}

	args.targetName = argv[progIdx];

	if (argc > progIdx+1) {
		args.targetArgs = argv[progIdx + 1];

		HANDLE hHeap = GetProcessHeap();
		SIZE_T fullLen = lstrlen(args.targetName) + lstrlen(args.targetArgs) + 2; // 1 for the space, 1 for the terminator
		SIZE_T fullSize = fullLen * sizeof(TCHAR);

		// TODO: free this
		TCHAR *fullArgs = (TCHAR *)HeapAlloc(hHeap, 0, fullSize);
		fullArgs[fullLen - 1] = 0;
		wsprintf(fullArgs, L"%S %S", args.targetName, args.targetArgs);

		args.targetArgs = fullArgs;
	}
	else {
		args.targetArgs = argv[progIdx];
	}

	return args;
}

int main()
{
	printf("Welcome to fuzzkit!\n");

	int argc;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	struct parsedArgs args = parseArgs(argv, argc);

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	
	BOOL success = CreateProcess(
		args.targetName,
		args.targetArgs,
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

	HANDLE hPipe = getPipe();

	if (!args.replay) {
		args.runId = getRunID(hPipe);
	}
	else {
		// use high bit of runId to indicate replay
		args.runId |= 1 << 31;
	}

	ResumeThread(pi.hThread);
	debug_main_loop(args.runId);

	CloseHandle(hPipe);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
    return 0;
}

