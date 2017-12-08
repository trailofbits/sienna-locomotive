// triage.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <DbgHelp.h>
#include "triton/api.hpp"
#include "triton/x86Specifications.hpp"

DWORD handleTaint(triton::API *api, HANDLE hTraceFile, DWORD pos) {
	UINT64 addr;
	UINT64 size;
	DWORD bytesRead;
	ReadFile(hTraceFile, &addr, sizeof(UINT64), &bytesRead, NULL);
	ReadFile(hTraceFile, &size, sizeof(UINT64), &bytesRead, NULL);
	printf("TAINT: %llx to %llx\n", addr, addr + size);
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

PMINIDUMP_HEADER pMinidumpHeader;
VOID getMem(UINT64 addr) {
	printf("SIG_MATCH: %x\n", pMinidumpHeader->Signature == MINIDUMP_SIGNATURE);
	printf("NUM STREAMS: %x\n", pMinidumpHeader->NumberOfStreams);
	printf("STREAM RVA: %x\n", pMinidumpHeader->StreamDirectoryRva);
	PMINIDUMP_DIRECTORY pMinidumpDirectoryFirst = (PMINIDUMP_DIRECTORY)((UINT64)pMinidumpHeader + pMinidumpHeader->StreamDirectoryRva);
	for (ULONG32 i = 0; i < pMinidumpHeader->NumberOfStreams; i++) {
		PMINIDUMP_DIRECTORY pMinidumpDirectory = pMinidumpDirectoryFirst + i;
		printf("STREAM TYPE: %x\n", pMinidumpDirectory->StreamType);
		if (pMinidumpDirectory->StreamType == Memory64ListStream) {
			PMINIDUMP_MEMORY64_LIST pMem64List = (PMINIDUMP_MEMORY64_LIST)((UINT64)pMinidumpHeader + pMinidumpDirectory->Location.Rva);
			UINT64 pMem = (UINT64)pMinidumpHeader + pMem64List->BaseRva;
			for (ULONG64 j = 0; j < pMem64List->NumberOfMemoryRanges; j++) {
				ULONG64 memStart = pMem64List->MemoryRanges[j].StartOfMemoryRange;
				ULONG64 dataSize = pMem64List->MemoryRanges[j].DataSize;
				ULONG64 memEnd = memStart + dataSize;
				if (addr >= memStart && addr < memEnd) {
					printf("FOUND\n");
					// pMem + (addr - memStart);
					return;
				}
				printf("MEM START: %llx\n", memStart);
				printf("MEM SIZE: %llx\n", dataSize);
				pMem += dataSize;
			}
			break;
		}
	}
}

/*
__imp_??0?$ComparableFunctor@$$A6AXAEAVAPI@triton@@AEBVMemoryAccess@arch@2@@Z@triton@@QEAA@P6AXAEAVAPI@1@AEBVMemoryAccess@arch@1@@Z@Z
__imp_??0?$ComparableFunctor@$$A6AXAEAVAPI@triton@@AEBVMemoryAccess@arch@2@@Z@triton@@QEAA@V?$function@$$A6AXAEAVAPI@triton@@AEBVMemoryAccess@arch@2@@Z@std@@PEAX@Z
__imp_??0?$ComparableFunctor@$$A6AXAEAVAPI@triton@@AEBVMemoryAccess@arch@2@@Z@triton@@QEAA@V?$function@$$A6AXAEAVAPI@triton@@AEBVMemoryAccess@arch@2@@Z@std@@PEAX@Z
*/

void getConcreteMemCallback(triton::API &api, const triton::arch::MemoryAccess &memAccess) {
	UINT64 address = memAccess.getAddress();
	UINT32 size = memAccess.getSize();

	PMINIDUMP_DIRECTORY pMinidumpDirectoryFirst = (PMINIDUMP_DIRECTORY)((UINT64)pMinidumpHeader + pMinidumpHeader->StreamDirectoryRva);
	for (ULONG32 i = 0; i < pMinidumpHeader->NumberOfStreams; i++) {
		PMINIDUMP_DIRECTORY pMinidumpDirectory = pMinidumpDirectoryFirst + i;
		if (pMinidumpDirectory->StreamType == Memory64ListStream) {
			PMINIDUMP_MEMORY64_LIST pMem64List = (PMINIDUMP_MEMORY64_LIST)((UINT64)pMinidumpHeader + pMinidumpDirectory->Location.Rva);
			UINT64 pMem = (UINT64)pMinidumpHeader + pMem64List->BaseRva;
			for (ULONG64 j = 0; j < pMem64List->NumberOfMemoryRanges; j++) {
				ULONG64 memStart = pMem64List->MemoryRanges[j].StartOfMemoryRange;
				ULONG64 dataSize = pMem64List->MemoryRanges[j].DataSize;
				ULONG64 memEnd = memStart + dataSize;
				if (address >= memStart && address < memEnd) {
					std::vector<uint8_t> memValues;
					for (ULONG64 k = address; k < address + size; k++) {
						memValues.push_back(*(uint8_t *)(pMem + (k - memStart)));
					}
					api.setConcreteMemoryAreaValue(memAccess.getAddress(), memValues);
					api.concretizeMemory(memAccess);
					break;
				}
				pMem += dataSize;
			}
			break;
		}
	}
}

void concretizeRegisters(triton::API &api) {
	PMINIDUMP_DIRECTORY pMinidumpDirectoryFirst = (PMINIDUMP_DIRECTORY)((UINT64)pMinidumpHeader + pMinidumpHeader->StreamDirectoryRva);
	for (ULONG32 i = 0; i < pMinidumpHeader->NumberOfStreams; i++) {
		PMINIDUMP_DIRECTORY pMinidumpDirectory = pMinidumpDirectoryFirst + i;
		if (pMinidumpDirectory->StreamType == ThreadListStream) {
			PMINIDUMP_THREAD_LIST pThreadList = (PMINIDUMP_THREAD_LIST)((UINT64)pMinidumpHeader + pMinidumpDirectory->Location.Rva);
			for (ULONG64 j = 0; j < pThreadList->NumberOfThreads; j++) {
				printf("THREAD ID: %x\n", pThreadList->Threads[j].ThreadId);
				PCONTEXT pContext = (PCONTEXT)((UINT64)pMinidumpHeader + pThreadList->Threads[j].ThreadContext.Rva);

				// TODO: support 32 bit

				/*printf("RIP: %llx\n", pContext->Rip);

				printf("RAX: %llx\n", pContext->Rax);
				printf("RCX: %llx\n", pContext->Rcx);
				printf("RDX: %llx\n", pContext->Rdx);
				printf("RBX: %llx\n", pContext->Rbx);

				printf("RSP: %llx\n", pContext->Rsp);
				printf("RBP: %llx\n", pContext->Rbp);
				printf("RSI: %llx\n", pContext->Rsi);
				printf("RDI: %llx\n", pContext->Rdi);

				printf("R8: %llx\n", pContext->R8);
				printf("R9: %llx\n", pContext->R9);
				printf("R10: %llx\n", pContext->R10);
				printf("R11: %llx\n", pContext->R11);
				printf("R12: %llx\n", pContext->R12);
				printf("R13: %llx\n", pContext->R13);
				printf("R14: %llx\n", pContext->R14);
				printf("R15: %llx\n", pContext->R15);*/

				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RIP), pContext->Rip);

				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RAX), pContext->Rax);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RCX), pContext->Rcx);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RDX), pContext->Rdx);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RBX), pContext->Rbx);

				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RSP), pContext->Rsp);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RBP), pContext->Rbp);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RSI), pContext->Rsi);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_RDI), pContext->Rdi);

				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R8), pContext->R8);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R9), pContext->R9);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R10), pContext->R10);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R11), pContext->R11);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R12), pContext->R12);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R13), pContext->R13);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R14), pContext->R14);
				api.setConcreteRegisterValue(api.getRegister(triton::arch::ID_REG_R15), pContext->R15);

				break;
			}
		}

	}
}

int main()
{
	triton::API api;
	api.setArchitecture(triton::arch::ARCH_X86_64);
	void(*cb)(triton::API &, const triton::arch::MemoryAccess &) = getConcreteMemCallback;
	api.addCallback(cb);
	DWORD bytesRead;

	// trace
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

	// memdump
	ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\mem.dmp", 0);
	HANDLE hMemFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hMemFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}
	
	highSize = 0;
	size = GetFileSize(hMemFile, &highSize);
	if (highSize) {
		printf("ERROR: injectable exceeds 4GB\n");
		exit(1);
	}

	PBYTE buf = (PBYTE)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf) {
		printf("ERROR: VirtualAlloc (%x)\n", GetLastError());
		exit(1);
	}

	if (!ReadFile(hMemFile, buf, size, &bytesRead, NULL) || bytesRead != size) {
		printf("ERROR: ReadFile (memfile) (%x)\n", GetLastError());
		exit(1);
	}

	pMinidumpHeader = (PMINIDUMP_HEADER)buf;
	concretizeRegisters(api);

	// crash info
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
		/*for (int i = 0; i < insnLength; i++) {
			printf("%x ", insnBytes[i]);
		}
		printf("\n");*/

		handleInsn(&api, currAddr, insnBytes, insnLength);
		if (currAddr == exceptionAddr) {
			printf("POTENTIAL CRASH\n");
			std::set<const triton::arch::Register *> taintedRegs = api.getTaintedRegisters();
			std::set<const triton::arch::Register *>::iterator it;
			for (it = taintedRegs.begin(); it != taintedRegs.end(); it++) {
				printf("TAINTED: %s\n", (*it)->getName().c_str());
			}
			exit(0);
		}

		currAddr += insnLength;
		pos += insnLength;
	}

    return 0;
}