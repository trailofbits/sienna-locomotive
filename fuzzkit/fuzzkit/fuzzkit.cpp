// fuzzkit.cpp : Defines the entry point for the console application.
//
#define NOMINMAX
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
#include "Tracer.h"

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"


// TODO: check return of every call
// TODO: support 32bit

DWORD handleInjection(CREATE_PROCESS_DEBUG_INFO cpdi, DWORD runId) {
	std::map<std::string, std::string> hookMap;
	hookMap["ReadFileHook"] = "ReadFile";
	Injector *injector = new Injector(cpdi.hProcess, cpdi.lpBaseOfImage, "C:\\Users\\dgoddard\\Documents\\GitHub\\sienna-locomotive\\fuzzkit\\x64\\Release\\injectable.dll", hookMap);
	injector->Inject(runId);

	std::set<std::string> missingModules = injector->MissingModules();
	if (injector->MissingModules().size() == 0) {
		return 0;
	}

	std::map<std::string, LPVOID> loadedModules;
	std::set<Injector *> injectors;
	injectors.insert(injector);

	std::set<std::string> missingMaster;
	missingMaster.insert(missingModules.begin(), missingModules.end());
	std::map<std::string, std::string> emptyMap;
	while (missingMaster.size() > 0) {
		// TODO: add more intelligent search, maybe a dependencies folder
		// open C:\Windows\System32\file.dll
		std::string missing = *(missingMaster.begin());
		std::string path = "C:\\Windows\\System32\\" + missing;
		
		// inject
		LOG_F(1, "Injecting dependency: %s", missing.c_str());
		injector = new Injector(cpdi.hProcess, cpdi.lpBaseOfImage, path, emptyMap);
		injector->Inject();

		// add injector to list
		injectors.insert(injector);

		// have missing?
		missingModules = injector->MissingModules();
		if (missingModules.size() > 0) {
			// add missing to missing master
			missingMaster.insert(missingModules.begin(), missingModules.end());
		}
		
		loadedModules[missing] = injector->BaseOfInjected();
		std::set<Injector *>::iterator injectorIt;
		// for injector in injectors
		for (injectorIt = injectors.begin(); injectorIt != injectors.end(); injectorIt++) {
			// missing newly injected?
			missingModules = (*injectorIt)->MissingModules();
			if (missingModules.size() == 0) {
				continue;
			}
			(*injectorIt)->ResolveImports(loadedModules);
		}

		missingMaster.erase(missing);
	}

	return 0;
}

BOOL debug_main_loop(DWORD runId) {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	BOOL injected = false;

	for (;;)
	{
		DEBUG_EVENT dbgev;

		WaitForDebugEvent(&dbgev, INFINITE);
		BOOL crashed = true;

		switch (dbgev.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			PVOID address;
			address = dbgev.u.Exception.ExceptionRecord.ExceptionAddress;
			switch (dbgev.u.Exception.ExceptionRecord.ExceptionCode)
			{
				case EXCEPTION_ACCESS_VIOLATION:
					LOG_F(INFO, "EXCEPTION_ACCESS_VIOLATION");
					break;
				case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
					LOG_F(INFO, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
					break;
				case EXCEPTION_BREAKPOINT:
					LOG_F(INFO, "EXCEPTION_BREAKPOINT");
					if (!injected) {
						LOG_F(1, "Injecting hook dll into process");
						handleInjection(cpdi, runId);
						crashed = false;
						injected = true;
					}
					break;
				case EXCEPTION_DATATYPE_MISALIGNMENT:
					LOG_F(INFO, "EXCEPTION_DATATYPE_MISALIGNMENT");
					break;
				case EXCEPTION_FLT_DENORMAL_OPERAND:
					LOG_F(INFO, "EXCEPTION_FLT_DENORMAL_OPERAND");
					break;
				case EXCEPTION_FLT_DIVIDE_BY_ZERO:
					LOG_F(INFO, "EXCEPTION_FLT_DIVIDE_BY_ZERO");
					break;
				case EXCEPTION_FLT_INEXACT_RESULT:
					LOG_F(INFO, "EXCEPTION_FLT_INEXACT_RESULT");
					break;
				case EXCEPTION_FLT_INVALID_OPERATION:
					LOG_F(INFO, "EXCEPTION_FLT_INVALID_OPERATION");
					break;
				case EXCEPTION_FLT_OVERFLOW:
					LOG_F(INFO, "EXCEPTION_FLT_OVERFLOW");
					break;
				case EXCEPTION_FLT_STACK_CHECK:
					LOG_F(INFO, "EXCEPTION_FLT_STACK_CHECK");
					break;
				case EXCEPTION_FLT_UNDERFLOW:
					LOG_F(INFO, "EXCEPTION_FLT_UNDERFLOW");
					break;
				case EXCEPTION_ILLEGAL_INSTRUCTION:
					LOG_F(INFO, "EXCEPTION_ILLEGAL_INSTRUCTION");
					break;
				case EXCEPTION_IN_PAGE_ERROR:
					LOG_F(INFO, "EXCEPTION_IN_PAGE_ERROR");
					break;
				case EXCEPTION_INT_DIVIDE_BY_ZERO:
					LOG_F(INFO, "EXCEPTION_INT_DIVIDE_BY_ZERO");
					break;
				case EXCEPTION_INT_OVERFLOW:
					LOG_F(INFO, "EXCEPTION_INT_OVERFLOW");
					break;
				case EXCEPTION_INVALID_DISPOSITION:
					LOG_F(INFO, "EXCEPTION_INVALID_DISPOSITION");
					break;
				case EXCEPTION_NONCONTINUABLE_EXCEPTION:
					LOG_F(INFO, "EXCEPTION_NONCONTINUABLE_EXCEPTION");
					break;
				case EXCEPTION_PRIV_INSTRUCTION:
					LOG_F(INFO, "EXCEPTION_PRIV_INSTRUCTION");
					break;
				case EXCEPTION_SINGLE_STEP:
					LOG_F(INFO, "EXCEPTION_SINGLE_STEP");
					break;
				case EXCEPTION_STACK_OVERFLOW:
					LOG_F(INFO, "EXCEPTION_STACK_OVERFLOW");
					break;
				default:
					break;
			}

			if (crashed) {
				return crashed;
			}

			break;
		case CREATE_THREAD_DEBUG_EVENT:
			LOG_F(1, "Thread started with id %x", dbgev.dwThreadId);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			LOG_F(INFO, "Process started with id %x", dbgev.dwProcessId);
			cpdi = dbgev.u.CreateProcessInfo;
			DebugBreakProcess(cpdi.hProcess);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			LOG_F(1, "Thread exited with id %x", dbgev.dwThreadId);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			// TODO: exit when all processes have exited
			LOG_F(INFO, "Process exited with id %x", dbgev.dwProcessId);
			return false;
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

		ContinueDebugEvent(
			dbgev.dwProcessId,
			dbgev.dwThreadId,
			dwContinueStatus);
	}
	return false;
}

DWORD getRunInfo(HANDLE hPipe, DWORD runId, LPCTSTR *targetName, LPTSTR *targetArgs) {
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	HANDLE hHeap = GetProcessHeap();

	BYTE eventId = 3;
	if (!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}
	
	DWORD size = 0;
	
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &bytesRead, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}
	
	*targetName = (LPCTSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size + sizeof(TCHAR));
	if(*targetName == NULL) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hPipe, (LPVOID)*targetName, size, &bytesRead, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}

	size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &bytesRead, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}

	*targetArgs = (LPTSTR)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size + sizeof(TCHAR));

	if (*targetArgs == NULL) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hPipe, (LPVOID)*targetArgs, size, &bytesRead, NULL)) {
		LOG_F(ERROR, "Error getting run info (%x)", GetLastError());
		exit(1);
	}

	return runId;
}

DWORD getRunID(HANDLE hPipe, LPCTSTR targetName, LPTSTR targetArgs) {
	LOG_F(INFO, "Requesting run id");
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;

	BYTE eventId = 0;
	DWORD runId = 0;
	if (!TransactNamedPipe(hPipe, &eventId, sizeof(BYTE), &runId, sizeof(DWORD), &bytesRead, NULL)) {
		LOG_F(ERROR, "Error getting run id (%x)", GetLastError());
		exit(1);
	}

	DWORD size = lstrlen(targetName) * sizeof(TCHAR);
	if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run id (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hPipe, targetName, size, &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run id (%x)", GetLastError());
		exit(1);
	}

	size = lstrlen(targetArgs) * sizeof(TCHAR);
	if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run id (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, targetArgs, size, &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error getting run id (%x)", GetLastError());
		exit(1);
	}

	LOG_F(INFO, "Run id %x", runId);

	return runId;
}

HANDLE getPipe() {
	HANDLE hPipe;
	while (1) {
		hPipe = CreateFile(
			L"\\\\.\\pipe\\fuzz_server",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (hPipe != INVALID_HANDLE_VALUE) {
			break;
		}

		DWORD err = GetLastError();
		if (err != ERROR_PIPE_BUSY) {
			LOG_F(ERROR, "Could not open pipe (%x)", err);
			return hPipe;
		}
		
		if (!WaitNamedPipe(L"\\\\.\\pipe\\fuzz_server", 5000)) {
			LOG_F(ERROR, "Could not connect, timeout");
			// TODO: fallback mutations?
			exit(1);
		}
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
	LOG_F(INFO, "USAGE:");
	LOG_F(INFO, "\trun: \t%S TARGET_PROGRAM.EXE [ARGUMENTS, ...]\n", argv[0]);
	LOG_F(INFO, "\treplay: \t%S -r ID\n", argv[0]);
	LOG_F(INFO, "\trace: \t%S -t TARGET_PROGRAM.EXE [ARGUMENTS, ...]\n", argv[0]);
	return 0;
}

DWORD finalize(HANDLE hPipe, DWORD runId, BOOL crashed) {
	if (crashed) {
		LOG_F(INFO, "Crash found for run id %d!", runId);
	}
	DWORD bytesWritten;
	BYTE eventId = 4;
	
	if(!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error finalizing (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error finalizing (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &crashed, sizeof(BOOL), &bytesWritten, NULL)) {
		LOG_F(ERROR, "Error finalizing (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

enum InjectFlags {
	REPLAY = 1,
	TRACE = 2
};

int main(int mArgc, char **mArgv)
{
	loguru::g_stderr_verbosity = loguru::Verbosity_WARNING;
	loguru::init(mArgc, mArgv);
	loguru::add_file("log\\fuzzkit.log", loguru::Append, loguru::Verbosity_MAX);
	LOG_F(INFO, "Fuzzkit started!");

	BOOL replay = false;
	BOOL trace = false;
	DWORD runId = 0;
	DWORD flags = 0;
	LPCTSTR targetName;
	LPTSTR targetArgs;
	HANDLE hHeap = GetProcessHeap();

	int argc;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 2) {
		printUsage(argv);
		exit(1);
	}

	if (lstrcmp(argv[1], L"-r") == 0) {
		HANDLE hPipe = getPipe();
		replay = true;
		trace = true;

		if (argc > 2) {
			runId = wcstoul(argv[2], NULL, NULL);
		}
		else {
			printUsage(argv);
			exit(1);
		}
		
		LOG_F(INFO, "Run id: %x", runId);
		getRunInfo(hPipe, runId, &targetName, &targetArgs);

		flags |= InjectFlags::REPLAY | InjectFlags::TRACE;
		CloseHandle(hPipe);
	}
	else if (lstrcmp(argv[1], L"-t") == 0) {
		targetName = argv[2];
		targetArgs = argv[2];
		
		trace = true;

		if (argc > 3) {
			DWORD size = 0;
			for (DWORD i = 2; i < argc; i++) {
				size += lstrlenW(argv[i]);
				size += 1; // space or null
			}
			printf("SIZE: %x\n", size);
			targetArgs = (LPTSTR)HeapAlloc(hHeap, NULL, size * sizeof(TCHAR));

			DWORD pos = 0;
			for (DWORD i = 2; i < argc; i++) {
				DWORD length = lstrlenW(argv[i]);
				lstrcpynW(targetArgs + pos, argv[i], length + 1);
				*(targetArgs + pos + length) = 0x20;
				pos += length + 1;
			}
			*(targetArgs + size) = 0;
		}
		
		flags |= InjectFlags::TRACE;
	}
	else {
		targetName = argv[1];
		targetArgs = argv[1];

		if (argc > 2) {
			DWORD size = 0;
			for (DWORD i = 1; i < argc; i++) {
				size += lstrlenW(argv[i]);
				size += 1; // space or null
			}
			printf("SIZE: %x\n", size);
			targetArgs = (LPTSTR)HeapAlloc(hHeap, NULL, size * sizeof(TCHAR));
			
			DWORD pos = 0;
			for (DWORD i = 1; i < argc; i++) {
				DWORD length = lstrlenW(argv[i]);
				lstrcpynW(targetArgs + pos, argv[i], length+1);
				*(targetArgs + pos + length) = 0x20;
				pos += length + 1;
			}
			*(targetArgs + size) = 0;
		}
	}

	LOG_F(INFO, "Target name: %S", targetName);
	LOG_F(INFO, "Target args: %S", targetArgs);
	printf("Target args: %S\n", targetArgs);

	for(DWORD i=0; i<100; i++) {
		if (!replay) {
			HANDLE hPipe = getPipe();
			if (hPipe == INVALID_HANDLE_VALUE) {
				continue;
			}
			runId = getRunID(hPipe, targetName, targetArgs);
			CloseHandle(hPipe);
		}

		printf("RUN ID: %d\n", runId);
		STARTUPINFO si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));

		BOOL success = CreateProcess(
			targetName,
			targetArgs,
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
			LOG_F(ERROR, "Could not start process (%x)", GetLastError());
			return 1;
		}

		ResumeThread(pi.hThread);

		if (!replay && !trace) {
			BOOL crashed = debug_main_loop(runId);
			HANDLE hPipe = getPipe();
			finalize(hPipe, runId, crashed);
			CloseHandle(hPipe);
			if (crashed) {
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				break;
			}
		}
		else {
			Tracer tracer;
			tracer.addThread(pi.dwThreadId, pi.hThread);
			tracer.TraceMainLoop(runId, flags);
			break;
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		LOG_F(1, "Iteration complete");
	}
    return 0;
}

