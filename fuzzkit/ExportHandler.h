#pragma once

#pragma once

#include <Windows.h>
#include <string>
#include <list>
#include <map>

class ExportHandler {
public:
	HANDLE hProcess;
	LPVOID lpvBaseOfImage;
	IMAGE_DOS_HEADER dosHeader;
	WORD machine;
	uintptr_t exportEntryVA;

	ExportHandler(HANDLE hProcess, LPVOID lpvBaseOfImage);

	std::map<std::string, UINT64> GetFunctionAddresses(std::list<std::string>);
	UINT64 GetFunctionAddress(std::string);
};