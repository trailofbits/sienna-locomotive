#pragma once

#include "stdafx.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <map>
#include <list>
#include <string>
#include <algorithm>

#include "ImportHandler.h"
#include "ExportHandler.h"
/*
	Handle to target process
	Target process base address
	File to inject
	Map of functions to hook
	
	Out:
		Base address of injected
		List of dependencies to be loaded
*/

typedef unsigned __int64 QWORD;

class Injector {
public:
	Injector(HANDLE hProcess, LPVOID lpBaseOfImage, std::string dllName, std::map<std::string, std::string> hookMap) : 
		hProcess(hProcess), lpBaseOfImage(lpBaseOfImage), dllName(dllName), hookMap(hookMap) { };
	DWORD Inject(DWORD runId);
	LPVOID BaseOfInjected();
	std::list<std::string> MissingModules();
	DWORD ResolveImports(std::map<std::string, LPVOID> loadedMap);

private:
	HANDLE hProcess;
	LPVOID lpBaseOfImage;
	std::string dllName;
	std::map<std::string, std::string> hookMap;
	std::list<std::string> missingModules;
	LPVOID injectedBase;

	DWORD HandleRelocations(PIMAGE_NT_HEADERS pNtHeaders);
	DWORD HandleImports();
	DWORD HandleHook();
	DWORD HandleRunId(DWORD runId);
};