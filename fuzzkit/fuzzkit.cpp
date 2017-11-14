// fuzzkit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <stdlib.h>
#include <psapi.h>
#include <tchar.h>
#include <algorithm>
#include <iostream>
#include <string> 
#include <map>
#include <list>

#include "ImportHandler.h"
#include "ExportHandler.h"

typedef unsigned __int64 QWORD;
// TODO: check return of every call
// TODO: support 32bit

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
}

int injectorRelocations(CREATE_PROCESS_DEBUG_INFO cpdi, PIMAGE_NT_HEADERS pNtHeaders, LPVOID remoteBase) {
	SIZE_T bytesWritten;
	// fixup reloc
	// get size of reloc table
	IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// intended base
	DWORD baseOfCode = pNtHeaders->OptionalHeader.BaseOfCode;

	DWORD consumed = 0;
	LPVOID relocVA = (LPVOID)((uintptr_t)remoteBase + relocDir.VirtualAddress);
	// iterate over reloc bases
	while (consumed < relocDir.Size) {
		SIZE_T bytesRead;
		IMAGE_BASE_RELOCATION relocBase;
		ReadProcessMemory(cpdi.hProcess, relocVA, &relocBase, sizeof(IMAGE_BASE_RELOCATION), &bytesRead);

		// calculate remoteBase + pageRVA
		LPVOID pageBase = (LPVOID)((uintptr_t)remoteBase + relocBase.VirtualAddress);

		// consume relocBase
		consumed += 8;
		relocVA = (LPVOID)((uintptr_t)relocVA + 8);

		// calculate num blocks (block size - 8)
		DWORD blockCount = (relocBase.SizeOfBlock - 8) / 2;

		// iterate blocks
		DWORD highAdj = 0;
		LPVOID highAdjVA = 0;
		BOOL processHighAdj = false;

		uintptr_t imageBaseInt = pNtHeaders->OptionalHeader.ImageBase;
		uintptr_t remoteBaseInt = (uintptr_t)remoteBase;

		for (int i = 0; i < blockCount; i++) {
			// get reloc type, offset
			WORD relocationBlock;
			ReadProcessMemory(cpdi.hProcess, relocVA, &relocationBlock, sizeof(WORD), &bytesRead);

			WORD type = relocationBlock >> 12;
			WORD offset = relocationBlock & 0xFFF;

			LPVOID targetVA = (LPVOID)((uintptr_t)pageBase + offset);

			WORD target16;
			DWORD target32;
			QWORD target64;

			if (!processHighAdj) {
				// switch reloc type
				switch (type) {
				case IMAGE_REL_BASED_HIGH:
					ReadProcessMemory(cpdi.hProcess, targetVA, &target16, sizeof(WORD), &bytesRead);
					target16 -= imageBaseInt >> 16;
					target16 += remoteBaseInt >> 16;
					WriteProcessMemory(cpdi.hProcess, targetVA, &target16, sizeof(WORD), &bytesWritten);
					break;
				case IMAGE_REL_BASED_LOW:
					ReadProcessMemory(cpdi.hProcess, targetVA, &target16, sizeof(WORD), &bytesRead);
					target16 -= imageBaseInt & 0xFFFF;
					target16 += remoteBaseInt & 0xFFFF;
					WriteProcessMemory(cpdi.hProcess, targetVA, &target16, sizeof(WORD), &bytesWritten);
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					ReadProcessMemory(cpdi.hProcess, targetVA, &target32, sizeof(DWORD), &bytesRead);
					target32 -= imageBaseInt;
					target32 += remoteBaseInt;
					WriteProcessMemory(cpdi.hProcess, targetVA, &target32, sizeof(DWORD), &bytesWritten);
					break;
				case IMAGE_REL_BASED_HIGHADJ:
					// who the fuck designed this bullshit?
					ReadProcessMemory(cpdi.hProcess, targetVA, &target16, sizeof(WORD), &bytesRead);
					highAdj = target16 << 16;
					highAdjVA = targetVA;
					processHighAdj = true;
					break;
				case IMAGE_REL_BASED_DIR64:
					ReadProcessMemory(cpdi.hProcess, targetVA, &target64, sizeof(QWORD), &bytesRead);
					target64 -= imageBaseInt;
					target64 += remoteBaseInt;
					WriteProcessMemory(cpdi.hProcess, targetVA, &target64, sizeof(QWORD), &bytesWritten);
					break;
				default:
					break;
				}
			}
			else {
				// seriously, HIGHADJ is stupid
				highAdj |= relocationBlock;
				highAdj -= imageBaseInt & 0xFFFF0000;
				highAdj += remoteBaseInt & 0xFFFF0000;
				target16 = highAdj >> 16;
				WriteProcessMemory(cpdi.hProcess, highAdjVA, &target16, sizeof(WORD), &bytesWritten);

				highAdj = 0;
				highAdjVA = 0;
				processHighAdj = false;
			}

			consumed += 2;
			relocVA = (LPVOID)((uintptr_t)relocVA + 2);
		}
	}

	return 0;
}

int injectorImports(CREATE_PROCESS_DEBUG_INFO cpdi, LPVOID remoteBase) {
	// get module bases
	std::map<std::string, LPVOID> bases;
	std::map<std::string, LPVOID> hints;
	SIZE_T bytesRead;

	// get addrs from EnumProcessModules
	printf("ENUM PROCESS MODULES:\n");
	HMODULE hMods[1024] = { 0 };
	DWORD cbNeeded;

	// TODO: use EnumProcessModulesEx for 32 bit compatibility
	EnumProcessModules(cpdi.hProcess, hMods, sizeof(HMODULE) * 1024, &cbNeeded);

	DWORD modCount = cbNeeded / sizeof(HMODULE);
	if (modCount > 1024) {
		modCount = 1024;
	}

	for (DWORD i = 0; i < modCount; i++) {
		TCHAR nameW[MAX_PATH];
		GetModuleBaseName(cpdi.hProcess, hMods[i], nameW, MAX_PATH);
		
		CHAR nameC[MAX_PATH];
		SIZE_T ret;
		wcstombs_s(&ret, nameC, MAX_PATH, nameW, MAX_PATH);
		printf("\t%s\n", nameC);

		MODULEINFO modinfo;
		GetModuleInformation(cpdi.hProcess, hMods[i], &modinfo, sizeof(modinfo));
		std::string name(nameC);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		bases[name] = modinfo.lpBaseOfDll;
	}

	// get bases from imports
	ImportHandler importHandler(cpdi.hProcess, cpdi.lpBaseOfImage);
	while (1) {
		std::string moduleName = importHandler.GetNextModule();
		std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

		if (moduleName == "") {
			break;
		}

		importHandler.GetNextFunction();
		LPVOID addr = (LPVOID)importHandler.GetFunctionAddr();
		
		std::map<std::string, LPVOID>::iterator itBases;
		itBases = bases.find(moduleName);
		if (itBases != bases.end()) {
			continue;
		}

		printf("%x\t%s\n", addr, moduleName.c_str());
		hints[moduleName] = addr;
	}

	// walk import table of injectable
	ImportHandler injectableImportHandler(cpdi.hProcess, remoteBase);
	while (1) {
		std::string moduleName = injectableImportHandler.GetNextModule();
		std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
		if (moduleName == "") {
			break;
		}

		printf("%s\n", moduleName.c_str());

		// get base
		// check bases
		std::map<std::string, LPVOID>::iterator itBases;
		itBases = bases.find(moduleName);
		if (itBases == bases.end()) {
			// check hints
			std::map<std::string, LPVOID>::iterator itHints;
			itHints = hints.find(moduleName);
			bool found = false;

			if (itHints != hints.end()) {
				// get base from hint
				printf("OMG HINT %x\n", itHints->second);
				UINT64 hintPage = (UINT64)itHints->second & 0xFFFFFFFFFFFFF000;
				BYTE magic[2];
				
				for (int i = 0; i < 20; i++) {
					ReadProcessMemory(cpdi.hProcess, (LPVOID)hintPage, magic, sizeof(BYTE) * 2, &bytesRead);
					
					if (bytesRead == 0) {
						break;
					}

					if (magic[0] == 0x4D && magic[1] == 0x5A) {
						printf("%x\t%x, %x\n", hintPage, magic[0], magic[1]);
						bases[moduleName] = (LPVOID)hintPage;
						found = true;
						break;
					}

					hintPage -= 0x1000;
				}
			}
			
			if (!found) {
				// TODO: implement recursive loader (read: injector)
				printf("OMG NOT FOUND %s\n", moduleName);
				continue;
			}
		}

		// gather desired functions
		std::list<std::string> functions;
		while (1) {
			std::string functionName = injectableImportHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}
			functions.push_back(functionName);
		}

		// walk exports from base, gather function addrs
		ExportHandler exportHandler(cpdi.hProcess, bases[moduleName]);
		std::map<std::string, UINT64> exportAddresses = exportHandler.GetFunctionAddresses(functions);

		// fixup imports
		injectableImportHandler.ResetFunctions();
		while (1) {
			std::string functionName = injectableImportHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}

			if (exportAddresses.find(functionName) == exportAddresses.end()) {
				printf("ERROR: Could not resolve %s", functionName.c_str());
			}

			UINT64 addr = exportAddresses[functionName];
			injectableImportHandler.RewriteFunctionAddr(addr);
		}
	}
}

int hooker(CREATE_PROCESS_DEBUG_INFO cpdi, LPVOID remoteBase) {
	ExportHandler injectedExportHandler(cpdi.hProcess, remoteBase);
	UINT64 address = (UINT64)remoteBase + injectedExportHandler.GetFunctionAddress("ReadFileHook");

	printf("ADDRESS: %x\n", address);

	ImportHandler importHandler(cpdi.hProcess, cpdi.lpBaseOfImage);
	while (1) {
		std::string moduleName = importHandler.GetNextModule();
		if (moduleName == "") {
			break;
		}

		while (1) {
			std::string functionName = importHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}

			if (!functionName.compare("ReadFile")) {
				importHandler.RewriteFunctionAddr(address);
				printf("FUNCTION ADDR: %x\n", importHandler.GetFunctionAddr());
			}
		}
	}

	walk_imports(cpdi.hProcess, cpdi.lpBaseOfImage);
	return 0;
}

int injector(CREATE_PROCESS_DEBUG_INFO cpdi) {
	// read in injectable
	HANDLE hFile = CreateFile(L"injectable.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		return 1;
	}

	DWORD highSize = 0;
	DWORD lowSize = GetFileSize(hFile, &highSize);
	if (highSize) {
		printf("ERROR: injectable exceeds 4GB\n");
		return 1;
	}

	PBYTE buf = (PBYTE)VirtualAlloc(NULL, lowSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf) {
		printf("ERROR: VirtualAlloc (%x)\n", GetLastError());
		return 1;
	}

	DWORD bytes_read;
	if (!ReadFile(hFile, buf, lowSize, &bytes_read, NULL) || bytes_read != lowSize) {
		printf("ERROR: ReadFile (ms_buf) (%x)\n", GetLastError());
		return 1;
	}

	// get nt headers
	PIMAGE_NT_HEADERS pNtHeaders = ImageNtHeader(buf);
	if (!pNtHeaders) {
		printf("ERROR: ImageNtHeader (%x)\n", GetLastError());
		return 1;
	}

	// allocate mem in target process
	LPVOID remoteBase = VirtualAllocEx(cpdi.hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// get dos and section headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(buf + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	// write headers
	SIZE_T bytesWritten;
	WriteProcessMemory(cpdi.hProcess, remoteBase, buf, pSectionHeader->PointerToRawData, &bytesWritten);

	// loop write sections
	WORD sectionCount = pNtHeaders->FileHeader.NumberOfSections;
	for (WORD i = 0; i < sectionCount; i++) {
		pSectionHeader = (PIMAGE_SECTION_HEADER)(buf + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
	
		LPVOID remoteVA = (LPVOID)((uintptr_t)remoteBase + pSectionHeader->VirtualAddress);
		WriteProcessMemory(cpdi.hProcess, remoteVA, buf + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, &bytesWritten);
	}

	injectorRelocations(cpdi, pNtHeaders, remoteBase);

	injectorImports(cpdi, remoteBase);

	hooker(cpdi, remoteBase);

	return 0;
}

// inject
// read file
// sum headers + virtual sizes (just use ImageSize?)
// allocate virtual size in remote process
// load file into remote process section by section

// hook
// locate hook functions (export table?)
// walk import table and replace any functions found to match

int debug_main_loop() {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;

	for (;;)
	{
		DEBUG_EVENT dbgev;

		WaitForDebugEvent(&dbgev, INFINITE);
		printf("DEBUG EVENT: %d\n", dbgev.dwDebugEventCode);

		switch (dbgev.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			PVOID address;
			address = dbgev.u.Exception.ExceptionRecord.ExceptionAddress;
			switch (dbgev.u.Exception.ExceptionRecord.ExceptionCode)
			{
				case EXCEPTION_ACCESS_VIOLATION:
					break;
				case EXCEPTION_BREAKPOINT:
					printf("BREAK AT %x\n", address);
					//walk_imports(cpdi.hProcess, cpdi.lpBaseOfImage);
					injector(cpdi);
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
			printf("START ADDR %x\n", cpdi.lpStartAddress);
			DebugBreakProcess(cpdi.hProcess);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			// TODO: exit when all processes have exited
			break;
		case LOAD_DLL_DEBUG_EVENT:
			LOAD_DLL_DEBUG_INFO lddi = dbgev.u.LoadDll;
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
	printf("Welcome to fuzzkit!\n");

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

	printf("CALLING: CreateProcess %S\n", name);

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

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

