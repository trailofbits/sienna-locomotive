#pragma once

#include <Windows.h>
#include <string>

class ImportHandler {
public:
	HANDLE hProcess;
	LPVOID lpvBaseOfImage;
	IMAGE_DOS_HEADER dosHeader;
	WORD machine;
	uintptr_t importEntryVA;
	IMAGE_IMPORT_DESCRIPTOR iid;
	DWORD iidIndex = 0;

	IMAGE_THUNK_DATA itdOrig;
	uint64_t iatFirstThunkAddr;
	DWORD itdIndex = 0;

	ImportHandler(HANDLE hProcess, LPVOID lpvBaseOfImage);
	std::string GetNextModule();

	std::string GetNextFunction();
	VOID ResetFunctions();
	UINT64 GetFunctionOrd();
	UINT64 GetFunctionAddr();
	BOOL RewriteFunctionAddr(UINT64 addr);
};