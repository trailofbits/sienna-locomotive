#include "Injector.h"

LPVOID Injector::BaseOfInjected() {
	return this->injectedBase;
}

std::set<std::string> Injector::MissingModules() {
	return this->missingModules;
}

DWORD Injector::HandleRelocations(PIMAGE_NT_HEADERS pNtHeaders) {
	SIZE_T bytesWritten;
	// fixup reloc
	// get size of reloc table
	IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// intended base
	DWORD baseOfCode = pNtHeaders->OptionalHeader.BaseOfCode;

	DWORD consumed = 0;
	LPVOID relocVA = (LPVOID)((uintptr_t)this->injectedBase + relocDir.VirtualAddress);
	// iterate over reloc bases
	while (consumed < relocDir.Size) {
		SIZE_T bytesRead;
		IMAGE_BASE_RELOCATION relocBase;
		if (!ReadProcessMemory(this->hProcess, relocVA, &relocBase, sizeof(IMAGE_BASE_RELOCATION), &bytesRead)) {
			LOG_F(ERROR, "HandleRelocations (%x)", GetLastError()); 
			exit(1);
		}

		// calculate this->injectedBase + pageRVA
		LPVOID pageBase = (LPVOID)((uintptr_t)this->injectedBase + relocBase.VirtualAddress);

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
		uintptr_t injectedBaseInt = (uintptr_t)this->injectedBase;

		for (DWORD i = 0; i < blockCount; i++) {
			// get reloc type, offset
			WORD relocationBlock;
			if(!ReadProcessMemory(this->hProcess, relocVA, &relocationBlock, sizeof(WORD), &bytesRead)) {
				LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
				exit(1);
			}

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
					if(!ReadProcessMemory(this->hProcess, targetVA, &target16, sizeof(WORD), &bytesRead)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}

					target16 -= imageBaseInt >> 16;
					target16 += injectedBaseInt >> 16;
					if(!WriteProcessMemory(this->hProcess, targetVA, &target16, sizeof(WORD), &bytesWritten)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					break;
				case IMAGE_REL_BASED_LOW:
					if(!ReadProcessMemory(this->hProcess, targetVA, &target16, sizeof(WORD), &bytesRead)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					target16 -= imageBaseInt & 0xFFFF;
					target16 += injectedBaseInt & 0xFFFF;
					if(!WriteProcessMemory(this->hProcess, targetVA, &target16, sizeof(WORD), &bytesWritten)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					if(!ReadProcessMemory(this->hProcess, targetVA, &target32, sizeof(DWORD), &bytesRead)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					target32 -= imageBaseInt;
					target32 += injectedBaseInt;
					if(!WriteProcessMemory(this->hProcess, targetVA, &target32, sizeof(DWORD), &bytesWritten)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					break;
				case IMAGE_REL_BASED_HIGHADJ:
					// who the fuck designed this bullshit?
					if(!ReadProcessMemory(this->hProcess, targetVA, &target16, sizeof(WORD), &bytesRead)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					highAdj = target16 << 16;
					highAdjVA = targetVA;
					processHighAdj = true;
					break;
				case IMAGE_REL_BASED_DIR64:
					if(!ReadProcessMemory(this->hProcess, targetVA, &target64, sizeof(QWORD), &bytesRead)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					target64 -= imageBaseInt;
					target64 += injectedBaseInt;
					if(!WriteProcessMemory(this->hProcess, targetVA, &target64, sizeof(QWORD), &bytesWritten)) {
						LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
						exit(1);
					}
					break;
				default:
					break;
				}
			}
			else {
				// seriously, HIGHADJ is stupid
				highAdj |= relocationBlock;
				highAdj -= imageBaseInt & 0xFFFF0000;
				highAdj += injectedBaseInt & 0xFFFF0000;
				target16 = highAdj >> 16;
				if(!WriteProcessMemory(this->hProcess, highAdjVA, &target16, sizeof(WORD), &bytesWritten)) {
					LOG_F(ERROR, "HandleRelocations (%x)", GetLastError());
					exit(1);
				}

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

DWORD Injector::HandleImports() {
	// get module bases
	std::map<std::string, LPVOID> bases;
	std::map<std::string, LPVOID> hints;
	SIZE_T bytesRead;

	// get addrs from EnumProcessModules
	HMODULE hMods[1024] = { 0 };
	DWORD cbNeeded;

	// TODO: use EnumProcessModulesEx for 32 bit compatibility
	if(!EnumProcessModules(this->hProcess, hMods, sizeof(HMODULE) * 1024, &cbNeeded)) {
		LOG_F(ERROR, "HandleImports (%x)", GetLastError());
		exit(1);
	}

	DWORD modCount = cbNeeded / sizeof(HMODULE);
	if (modCount > 1024) {
		modCount = 1024;
	}

	for (DWORD i = 0; i < modCount; i++) {
		TCHAR nameW[MAX_PATH];
		if(!GetModuleBaseName(this->hProcess, hMods[i], nameW, MAX_PATH)) {
			LOG_F(ERROR, "HandleImports (%x)", GetLastError());
			exit(1);
		}

		CHAR nameC[MAX_PATH];
		SIZE_T ret;
		wcstombs_s(&ret, nameC, MAX_PATH, nameW, MAX_PATH);

		MODULEINFO modinfo;
		if(!GetModuleInformation(this->hProcess, hMods[i], &modinfo, sizeof(modinfo))) {
			LOG_F(ERROR, "HandleImports (%x)", GetLastError());
			exit(1);
		}

		std::string name(nameC);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		bases[name] = modinfo.lpBaseOfDll;
	}

	// get bases from imports
	ImportHandler importHandler(this->hProcess, this->lpBaseOfImage);
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

		hints[moduleName] = addr;
	}

	// walk import table of injectable
	ImportHandler injectableImportHandler(this->hProcess, this->injectedBase);
	while (1) {
		std::string moduleName = injectableImportHandler.GetNextModule();
		std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
		if (moduleName == "") {
			break;
		}

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
				LOG_F(INFO, "Using hint %x for %s", itHints->second, itHints->first.c_str());
				UINT64 hintPage = (UINT64)itHints->second & 0xFFFFFFFFFFFFF000;
				BYTE magic[2];

				for (int i = 0; i < 20; i++) {
					if(!ReadProcessMemory(this->hProcess, (LPVOID)hintPage, magic, sizeof(BYTE) * 2, &bytesRead)) {
						LOG_F(ERROR, "HandleImports (%x)", GetLastError());
						exit(1);
					}

					if (bytesRead == 0) {
						break;
					}

					if (magic[0] == 0x4D && magic[1] == 0x5A) {
						bases[moduleName] = (LPVOID)hintPage;
						found = true;
						break;
					}

					hintPage -= 0x1000;
				}
			}

			if (!found) {
				LOG_F(INFO, "Address not found for %s", moduleName.c_str());
				missingModules.insert(moduleName);
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
		ExportHandler exportHandler(this->hProcess, bases[moduleName]);
		std::map<std::string, UINT64> exportAddresses = exportHandler.GetFunctionAddresses(functions);

		// fixup imports
		injectableImportHandler.ResetFunctions();
		while (1) {
			std::string functionName = injectableImportHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}

			if (exportAddresses.find(functionName) == exportAddresses.end()) {
				LOG_F(WARNING, "Could not resolve %s", functionName.c_str());
			}

			UINT64 addr = exportAddresses[functionName];
			injectableImportHandler.RewriteFunctionAddr(addr);
		}
	}
	return 0;
}

DWORD Injector::ResolveImports(std::map<std::string, LPVOID> loadedMap) {
	ImportHandler injectableImportHandler(this->hProcess, this->injectedBase);
	while (1) {
		std::string moduleName = injectableImportHandler.GetNextModule();
		std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
		if (moduleName == "") {
			break;
		}

		std::map<std::string, LPVOID>::iterator loadedMapIt;
		if (this->missingModules.find(moduleName) == this->missingModules.end() || loadedMap.find(moduleName) == loadedMap.end()) {
			continue;
		}

		LOG_F(INFO, "Resolving %s in %s", moduleName.c_str(), this->dllName.c_str());
		missingModules.erase(moduleName);
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
		ExportHandler exportHandler(this->hProcess, loadedMap[moduleName]);
		std::map<std::string, UINT64> exportAddresses = exportHandler.GetFunctionAddresses(functions);

		// fixup imports
		injectableImportHandler.ResetFunctions();
		while (1) {
			std::string functionName = injectableImportHandler.GetNextFunction();
			if (functionName == "") {
				break;
			}

			if (exportAddresses.find(functionName) == exportAddresses.end()) {
				LOG_F(WARNING, "Could not resolve %s", functionName.c_str());
			}

			UINT64 addr = exportAddresses[functionName];
			injectableImportHandler.RewriteFunctionAddr(addr);
		}
	}

	return 0;
}

std::string Injector::DllName()
{
	return this->dllName;
}

DWORD Injector::HandleHook() {
	std::map<std::string, std::string>::iterator hookMapIt;

	// TODO: add filtering by DLL name
	for (hookMapIt = hookMap.begin(); hookMapIt != hookMap.end(); hookMapIt++) {
		std::string hookFn = hookMapIt->first;
		std::string origFn = hookMapIt->second;
		ExportHandler injectedExportHandler(this->hProcess, this->injectedBase);
		UINT64 address = injectedExportHandler.GetFunctionAddress(hookFn);
		LOG_F(INFO, "Setting %s: %x", hookFn.c_str(), address);
		hookAddrMap[hookFn] = address;

		ImportHandler importHandler(this->hProcess, this->lpBaseOfImage);
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

				if (!functionName.compare(origFn)) {
					importHandler.RewriteFunctionAddr(address);
				}
			}
		}
	}

	return 0;
}

DWORD Injector::HandleRunId(DWORD runId) {
	ExportHandler exportHandler(this->hProcess, this->injectedBase);
	UINT64 address = exportHandler.GetFunctionAddress("runId");

	if (!WriteProcessMemory(this->hProcess, (LPVOID)address, &runId, sizeof(DWORD), NULL)) {
		LOG_F(ERROR, "Could not write run id to injected DLL (%x)", GetLastError());
		return 1;
	}
	return 0;
}

DWORD Injector::Inject() {
	// read in injectable
	std::wstring wDllName(dllName.begin(), dllName.end());
	HANDLE hFile = CreateFile(wDllName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "Could not open injectable file (%x)", GetLastError());
		exit(1);
	}

	DWORD highSize = 0;
	DWORD lowSize = GetFileSize(hFile, &highSize);
	if (highSize) {
		LOG_F(ERROR, "Injectable exceeds 4GB?");
		exit(1);
	}

	PBYTE buf = (PBYTE)VirtualAlloc(NULL, lowSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buf) {
		LOG_F(ERROR, "Could not allocate mem for injectable (%x)\n", GetLastError());
		exit(1);
	}

	DWORD bytes_read;
	if (!ReadFile(hFile, buf, lowSize, &bytes_read, NULL) || bytes_read != lowSize) {
		LOG_F(ERROR, "Could not read injectable (%x)\n", GetLastError());
		exit(1);
	}

	// get nt headers
	PIMAGE_NT_HEADERS pNtHeaders = ImageNtHeader(buf);
	if (!pNtHeaders) {
		LOG_F(ERROR, "Could not get NT Headers from injectable (%x)\n", GetLastError());
		exit(1);
	}

	// allocate mem in target process
	this->injectedBase = VirtualAllocEx(this->hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if(this->injectedBase == NULL) {
		LOG_F(ERROR, "Inject (%x)", GetLastError());
		exit(1);
	}

	// get dos and section headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(buf + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	// write headers
	SIZE_T bytesWritten;
	if(!WriteProcessMemory(this->hProcess, this->injectedBase, buf, pSectionHeader->PointerToRawData, &bytesWritten)) {
		LOG_F(ERROR, "Inject (%x)", GetLastError());
		exit(1);
	}

		// loop write sections
		WORD sectionCount = pNtHeaders->FileHeader.NumberOfSections;
	for (WORD i = 0; i < sectionCount; i++) {
		pSectionHeader = (PIMAGE_SECTION_HEADER)(buf + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);

		LPVOID remoteVA = (LPVOID)((uintptr_t)this->injectedBase + pSectionHeader->VirtualAddress);
		if(!WriteProcessMemory(this->hProcess, remoteVA, buf + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, &bytesWritten)) {
			LOG_F(ERROR, "Inject (%x)", GetLastError());
			exit(1);
		}
	}

	HandleRelocations(pNtHeaders);

	HandleImports();

	HandleHook();

	return 0;
}

DWORD Injector::Inject(DWORD runId) {
	Inject();
	HandleRunId(runId);

	return 0;
}