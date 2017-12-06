// triage.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "triton/api.hpp"
#include "triton/x86Specifications.hpp"

DWORD handleTaint(triton::API *api, HANDLE hTraceFile, DWORD pos) {
	UINT64 addr;
	UINT64 size;
	DWORD bytesRead;
	ReadFile(hTraceFile, &addr, sizeof(UINT64), &bytesRead, NULL);
	ReadFile(hTraceFile, &size, sizeof(UINT64), &bytesRead, NULL);
	printf("TAINT: %x to %x\n", addr, addr + size);
	for (UINT64 i = addr; i < addr + size; i++) {
		api->taintMemory(i);
	}
	return pos + sizeof(UINT64) * 2;
}

DWORD handleAddr(HANDLE hTraceFile, DWORD pos, UINT64 *headAddr) {
	DWORD bytesRead;
	ReadFile(hTraceFile, headAddr, sizeof(UINT64), &bytesRead, NULL);
	return pos + sizeof(UINT64);
}

DWORD handleInsn(triton::API *api, UINT64 addr, BYTE *insnBytes, BYTE insnLength) {
	triton::arch::Instruction inst;
	inst.setOpcode(insnBytes, insnLength);
	inst.setAddress(addr);
	api->processing(inst);
	return insnLength;
}

int main()
{
	triton::API api;
	api.setArchitecture(triton::arch::ARCH_X86_64);
	DWORD bytesRead;

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.trc", 0);
	HANDLE hTraceFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTraceFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}

	DWORD highSize = 0;
	DWORD size = GetFileSize(hTraceFile, &highSize);
	if (highSize) {
		printf("ERROR: trace file exceeds 4GB\n");
		exit(1);
	}

	ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\mem.dmp", 0);
	HANDLE hMemFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hMemFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}

	ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.csh", 0);
	HANDLE hCrashFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCrashFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}

	UINT64 exceptionAddr;
	DWORD exceptionCode;
	ReadFile(hCrashFile, &exceptionAddr, sizeof(UINT64), &bytesRead, NULL);
	ReadFile(hCrashFile, &exceptionCode, sizeof(DWORD), &bytesRead, NULL);
	CloseHandle(hCrashFile);

	DWORD pos = 0;
	UINT64 currAddr = 0;
	while (pos < size) {
		BYTE insnLength;
		BYTE insnBytes[15];

		ReadFile(hTraceFile, &insnLength, 1, &bytesRead, NULL);
		pos += 1;

		if (insnLength > 15) {
			if (insnLength == 0x80) {
				pos = handleAddr(hTraceFile, pos, &currAddr);
				continue;
			}
			else if (insnLength == 0x81) {
				pos = handleTaint(&api, hTraceFile, pos);
				continue;
			} else {
				printf("ERROR: invalid insn length at pos %d\n", pos);
				exit(1);
			}
		}

		ReadFile(hTraceFile, insnBytes, insnLength, &bytesRead, NULL);
		for (int i = 0; i < insnLength; i++) {
			printf("%x ", insnBytes[i]);
		}
		printf("\n");

		handleInsn(&api, currAddr, insnBytes, insnLength);
		if (currAddr == exceptionAddr) {
			printf("POTENTIAL CRASH\n");
		}

		currAddr += insnLength;
		pos += insnLength;
	}

    return 0;
}