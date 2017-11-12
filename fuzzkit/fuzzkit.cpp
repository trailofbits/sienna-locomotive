// fuzzkit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <psapi.h>
#include <DbgHelp.h>
#include <tchar.h>
#include <iostream>

int walk_import_descriptor(CREATE_PROCESS_DEBUG_INFO cpdi, IMAGE_IMPORT_DESCRIPTOR iid, WORD machine) {
	PVOID lpBaseOfImage = cpdi.lpBaseOfImage;
	LPVOID lpvScratch;
	SIZE_T bytesRead;
	
	if (machine == IMAGE_FILE_MACHINE_AMD64) {
		DWORD index = 0;
		do {
			IMAGE_THUNK_DATA64 itd_orig;
			lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + iid.OriginalFirstThunk + index * sizeof(IMAGE_THUNK_DATA64));
			ReadProcessMemory(cpdi.hProcess, lpvScratch, &itd_orig, sizeof(IMAGE_THUNK_DATA64), &bytesRead);

			if (itd_orig.u1.AddressOfData == 0) {
				break;
			}

			uint64_t iatFirstThunkAddr;
			lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + iid.FirstThunk + index * sizeof(uint64_t));
			ReadProcessMemory(cpdi.hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint64_t), &bytesRead);

			if (iatFirstThunkAddr == 0) {
				break;
			}

			if (itd_orig.u1.Ordinal & 0x80000000) {
				// ordinal 
				printf("\t%x\t%x (ord)\n", iatFirstThunkAddr, itd_orig.u1.Ordinal & 0x7FFFFFFF);
			}
			else {
				BYTE pFuncName[MAX_PATH];
				PBYTE dst = pFuncName;
				lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + itd_orig.u1.AddressOfData + 2);

				DWORD nameIndex = 0;
				do {
					ReadProcessMemory(cpdi.hProcess, lpvScratch, pFuncName + nameIndex, sizeof(BYTE), &bytesRead);
					nameIndex++;
					lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
				} while (pFuncName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);

				printf("\t%x\t%s\n", iatFirstThunkAddr, pFuncName);
			}

			index++;
		} while (1);
	}
	else if (machine == IMAGE_FILE_MACHINE_I386) {
		DWORD index = 0;
		do {
			IMAGE_THUNK_DATA32 itd_orig;
			lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + iid.OriginalFirstThunk + index * sizeof(IMAGE_THUNK_DATA32));
			ReadProcessMemory(cpdi.hProcess, lpvScratch, &itd_orig, sizeof(IMAGE_THUNK_DATA32), &bytesRead);

			if (itd_orig.u1.AddressOfData == 0) {
				break;
			}

			uint32_t iatFirstThunkAddr;
			lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + iid.FirstThunk + index * sizeof(uint32_t));
			ReadProcessMemory(cpdi.hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint32_t), &bytesRead);

			if (iatFirstThunkAddr == 0) {
				break;
			}

			if (itd_orig.u1.Ordinal & 0x80000000) {
				// ordinal 
				printf("\t%x\t%x (ord)\n", iatFirstThunkAddr, itd_orig.u1.Ordinal & 0x7FFFFFFF);
			}
			else {
				BYTE pFuncName[MAX_PATH];
				PBYTE dst = pFuncName;
				lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + itd_orig.u1.AddressOfData + 2);

				DWORD nameIndex = 0;
				do {
					ReadProcessMemory(cpdi.hProcess, lpvScratch, pFuncName + nameIndex, sizeof(BYTE), &bytesRead);
					nameIndex++;
					lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
				} while (pFuncName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);

				printf("\t%x\t%s\n", iatFirstThunkAddr, pFuncName);
			}

			index++;
		} while (1);
	}

	return 0;
}

int walk_imports(CREATE_PROCESS_DEBUG_INFO cpdi) {
	SIZE_T bytesRead;
	PVOID lpBaseOfImage = cpdi.lpBaseOfImage;

	if (lpBaseOfImage != 0) {
		IMAGE_DOS_HEADER dosHeader;
		printf("dosHeader addr: %x\n", lpBaseOfImage);
		ReadProcessMemory(cpdi.hProcess, lpBaseOfImage, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead);

		// IMAGE_NT_HEADERS64?
		WORD machine;
		LPVOID lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + dosHeader.e_lfanew + 4);
		printf("machine addr: %x\n", lpvScratch);
		if (!ReadProcessMemory(cpdi.hProcess, (PVOID)((uintptr_t)lpvScratch), &machine, sizeof(WORD), &bytesRead) || bytesRead != sizeof(WORD)) {
			printf("ERROR: ReadProcessMemory(machine) (%x) (%x)\n", GetLastError(), bytesRead);
		}
		printf("machine: %x\n", machine);

		lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + dosHeader.e_lfanew);
		printf("ntHeaders addr: %x\n", lpvScratch);
		uintptr_t importEntryVA;
		if (machine == IMAGE_FILE_MACHINE_AMD64) {
			IMAGE_NT_HEADERS64 ntHeaders = { 0 };
			if (!ReadProcessMemory(cpdi.hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &bytesRead)) {
				printf("ERROR: ReadProcessMemory(ntHeaders) (%x)\n", GetLastError());
				return 1;
			}

			IMAGE_DATA_DIRECTORY importEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			printf("importEntry.virtual addr: %x\n", importEntry.VirtualAddress);
			importEntryVA = importEntry.VirtualAddress;
		}
		else if (machine == IMAGE_FILE_MACHINE_I386) {
			IMAGE_NT_HEADERS32 ntHeaders = { 0 };
			if (!ReadProcessMemory(cpdi.hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS32), &bytesRead)) {
				printf("ERROR: ReadProcessMemory(ntHeaders) (%x)\n", GetLastError());
				return 1;
			}

			IMAGE_DATA_DIRECTORY importEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			printf("importEntry.virtual addr: %x\n", importEntry.VirtualAddress);
			importEntryVA = importEntry.VirtualAddress;
		}
		
		IMAGE_IMPORT_DESCRIPTOR iid;
		DWORD index = 0;
		printf("iid addr: %x\n", lpvScratch);
		
		do {
			lpvScratch = (PVOID)((uintptr_t)lpBaseOfImage + importEntryVA + sizeof(IMAGE_IMPORT_DESCRIPTOR)*index);
			ReadProcessMemory(cpdi.hProcess, lpvScratch, &iid, sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead);
			index++;

			if (iid.Characteristics == 0) {
				break;
			}

			BYTE pModName[MAX_PATH];
			PBYTE dst = pModName;
			lpvScratch = (LPVOID)((uintptr_t)lpBaseOfImage + iid.Name);

			DWORD nameIndex = 0;
			do {
				ReadProcessMemory(cpdi.hProcess, lpvScratch, pModName + nameIndex, sizeof(BYTE), &bytesRead);
				nameIndex++;
				lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
			} while (pModName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);

			printf("Name: %s\n", (CHAR *)pModName);
			walk_import_descriptor(cpdi, iid, machine);
		} while (iid.Characteristics != 0); // this is checked elsewhere but whatever, safety first
	}

	return 0;
}

int injector(CREATE_PROCESS_DEBUG_INFO cpdi) {
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

	PIMAGE_NT_HEADERS pNtHeaders = ImageNtHeader(buf);
	if (!pNtHeaders) {
		printf("ERROR: ImageNtHeader (%x)\n", GetLastError());
		return 1;
	}

	printf("IMAGE SIZE: %x\n", pNtHeaders->OptionalHeader.SizeOfImage);
	LPVOID remoteBase = VirtualAllocEx(cpdi.hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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

	// fixup reloc
	// get size of reloc table
	// calculate diff between preferred and remote base
	// iterate over reloc bases
		// calculate remoteBase + pageRVA
		// calculate num blocks (block size - 8)
		// iterate blocks
			// get reloc type, offset
			// switch reloc type
				// do reloc

	// fixup IAT

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
	// TODO: exit when all processes have exited

	// ANSWER: does LOAD_DLL_DEBUG_EVENT fire before first brk hit
	// ANSWER: should we hook them as they are loaded (probably) or when brk is hit
	// ANSWER: once first brk is hit, which DLLs are loaded

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
					walk_imports(cpdi);
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
			injector(cpdi);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
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

