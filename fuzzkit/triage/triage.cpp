// triage.cpp : Defines the entry point for the console application.
//

#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>
#include <map>
#include "triton/api.hpp"
#include "triton/x86Specifications.hpp"

extern "C" {
#include "xed-interface.h"
}

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"

#include "Crash.h"

PMINIDUMP_HEADER pMinidumpHeader;
std::map<UINT64, BOOL> conMem;
PCONTEXT pContext;
std::map<triton::arch::registers_e, BOOL> conRegs;

DWORD handleTaint(triton::API *api, HANDLE hTraceFile, DWORD pos) {
	UINT64 addr;
	UINT64 size;
	DWORD bytesRead;
	if (!ReadFile(hTraceFile, &addr, sizeof(UINT64), &bytesRead, NULL)) {
		LOG_F(ERROR, "HandleTaint (%x)", GetLastError);
		exit(1);
	}

	if(!ReadFile(hTraceFile, &size, sizeof(UINT64), &bytesRead, NULL)) {
		LOG_F(ERROR, "HandleTaint (%x)", GetLastError);
		exit(1);
	}

	LOG_F(INFO, "Tainted %llx to %llx\n", addr, addr + size);
	for (UINT64 i = addr; i < addr + size; i++) {
		api->taintMemory(i);
	}
	return pos + sizeof(UINT64) * 2;
}

DWORD handleAddr(HANDLE hTraceFile, DWORD pos, UINT64 *headAddr) {
	DWORD bytesRead;
	if(!ReadFile(hTraceFile, headAddr, sizeof(UINT64), &bytesRead, NULL)) {
		LOG_F(ERROR, "HandleTaint (%x)", GetLastError);
		exit(1);
	}
	return pos + sizeof(UINT64);
}

DWORD handleInsn(triton::API *api, triton::arch::Instruction *insn, UINT64 addr, BYTE *insnBytes, BYTE insnLength) {
	insn->setOpcode(insnBytes, insnLength);
	insn->setAddress(addr);
	api->processing(*insn);
	return insnLength;
}

void getConcreteMemCallback(triton::API &api, const triton::arch::MemoryAccess &memAccess) {
	UINT64 address = memAccess.getAddress();
	UINT32 size = memAccess.getSize();

	if (conMem.find(address) != conMem.end()) {
		return;
	}

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

	conMem[address] = TRUE;
}

void concretizeRegs(triton::API &api) {
	triton::arch::Register reg;

	reg = api.getRegister(triton::arch::ID_REG_RIP);
	api.setConcreteRegisterValue(reg, pContext->Rip);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RAX);
	api.setConcreteRegisterValue(reg, pContext->Rax);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RCX);
	api.setConcreteRegisterValue(reg, pContext->Rcx);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RDX);
	api.setConcreteRegisterValue(reg, pContext->Rdx);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RBX);
	api.setConcreteRegisterValue(reg, pContext->Rbx);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RSP);
	api.setConcreteRegisterValue(reg, pContext->Rsp);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RBP);
	api.setConcreteRegisterValue(reg, pContext->Rbp);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RSI);
	api.setConcreteRegisterValue(reg, pContext->Rsi);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_RDI);
	api.setConcreteRegisterValue(reg, pContext->Rdi);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R8);
	api.setConcreteRegisterValue(reg, pContext->R8);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R9);
	api.setConcreteRegisterValue(reg, pContext->R9);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R10);
	api.setConcreteRegisterValue(reg, pContext->R10);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R11);
	api.setConcreteRegisterValue(reg, pContext->R11);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R12);
	api.setConcreteRegisterValue(reg, pContext->R12);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R13);
	api.setConcreteRegisterValue(reg, pContext->R13);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R14);
	api.setConcreteRegisterValue(reg, pContext->R14);
	api.concretizeRegister(reg);

	reg = api.getRegister(triton::arch::ID_REG_R15);
	api.setConcreteRegisterValue(reg, pContext->R15);
	api.concretizeRegister(reg);
}

void getContext(triton::API &api) {
	PMINIDUMP_DIRECTORY pMinidumpDirectoryFirst = (PMINIDUMP_DIRECTORY)((UINT64)pMinidumpHeader + pMinidumpHeader->StreamDirectoryRva);
	for (ULONG32 i = 0; i < pMinidumpHeader->NumberOfStreams; i++) {
		PMINIDUMP_DIRECTORY pMinidumpDirectory = pMinidumpDirectoryFirst + i;
		if (pMinidumpDirectory->StreamType == ThreadListStream) {
			PMINIDUMP_THREAD_LIST pThreadList = (PMINIDUMP_THREAD_LIST)((UINT64)pMinidumpHeader + pMinidumpDirectory->Location.Rva);
			for (ULONG64 j = 0; j < pThreadList->NumberOfThreads; j++) {
				pContext = (PCONTEXT)((UINT64)pMinidumpHeader + pThreadList->Threads[j].ThreadContext.Rva);
				break;
			}
		}

	}
}

DWORD printUsage(LPWSTR *argv) {
	printf("USAGE:");
	printf("\run: \t%S -r ID\n", argv[0]);
	return 0;
}

int main()
{
	DWORD runId;
	int argc;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 3) {
		printUsage(argv);
		exit(1);
	}

	if (lstrcmp(argv[1], L"-r") == 0) {
		if (argc > 2) {
			runId = wcstoul(argv[2], NULL, NULL);
		}
		else {
			printUsage(argv);
			exit(1);
		}
	}

	triton::API api;
	api.setArchitecture(triton::arch::ARCH_X86_64);
	api.addCallback(getConcreteMemCallback);

	DWORD bytesRead;

	// trace
	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.trc", runId);
	HANDLE hTraceFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTraceFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "Could not open execution trace (%x)", GetLastError());
		exit(1);
	}

	DWORD highSize = 0;
	DWORD traceSize = GetFileSize(hTraceFile, &highSize);
	if (highSize) {
		LOG_F(ERROR, "Trace file exceeds 4GB", GetLastError());
		exit(1);
	}

	// memdump
	ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\mem.dmp", runId);
	HANDLE hMemFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hMemFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "Could not open memory dump (%x)", GetLastError());
		exit(1);
	}
	
	highSize = 0;
	DWORD size = GetFileSize(hMemFile, &highSize);
	if (highSize) {
		// TODO: this might happen
		LOG_F(ERROR, "Memory dump exceeds 4GB");
		exit(1);
	}

	PBYTE buf = (PBYTE)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf) {
		LOG_F(ERROR, "Could not allocate memory for memory dump (%x)", GetLastError());
		exit(1);
	}

	if (!ReadFile(hMemFile, buf, size, &bytesRead, NULL) || bytesRead != size) {
		LOG_F(ERROR, "Could not read memory dump (%x)", GetLastError());
		exit(1);
	}

	pMinidumpHeader = (PMINIDUMP_HEADER)buf;
	getContext(api);
	concretizeRegs(api);

	// crash info
	ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.csh", runId);
	HANDLE hCrashFile = CreateFile(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCrashFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "Could not open crash file (%x)", GetLastError());
		exit(1);
	}

	UINT64 exceptionAddr;
	DWORD exceptionCode;
	if(!ReadFile(hCrashFile, &exceptionAddr, sizeof(UINT64), &bytesRead, NULL)) {
		LOG_F(ERROR, "Main (%x)", GetLastError);
		exit(1);
	}

	if(!ReadFile(hCrashFile, &exceptionCode, sizeof(DWORD), &bytesRead, NULL)) {
		LOG_F(ERROR, "Main (%x)", GetLastError);
		exit(1);
	}

	if(!CloseHandle(hCrashFile)) {
		LOG_F(ERROR, "Main (%x)", GetLastError);
		exit(1);
	}

	DWORD pos = 0;
	UINT64 currAddr = 0;
	Crash *crash = NULL;
	xed_tables_init();

	while (pos < traceSize) {
		BYTE insnLength;
		BYTE insnBytes[15];

		if(!ReadFile(hTraceFile, &insnLength, 1, &bytesRead, NULL)) {
			LOG_F(ERROR, "Main (%x)", GetLastError);
			exit(1);
		}

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
				LOG_F(ERROR, "Invalid insn length at pos %x", pos);
				exit(1);
			}
		}

		if(!ReadFile(hTraceFile, insnBytes, insnLength, &bytesRead, NULL)) {
			LOG_F(ERROR, "Main (%x)", GetLastError);
			exit(1);
		}

		/*for (int i = 0; i < insnLength; i++) {
			printf("%02x ", insnBytes[i]);
		}
		printf("\n");*/

		triton::arch::Instruction *insn = new triton::arch::Instruction();
		handleInsn(&api, insn, currAddr, insnBytes, insnLength);

		/*xed_decoded_inst_t xedd;
		xed_decoded_inst_zero(&xedd);
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		xed_decode(&xedd, insnBytes, insnLength);
		CHAR buf[1000] = { 0 };
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 1000, 0, 0, 0);*/
		//printf("%llx\t%s\n", currAddr, insn->getDisassembly().c_str());

		if (currAddr == exceptionAddr) {
			crash = new Crash(api, insn, insnBytes, insnLength, exceptionAddr, exceptionCode);
		}

		currAddr += insnLength;
		pos += insnLength;
	}

	crash->dumpInfo();

    return 0;
}