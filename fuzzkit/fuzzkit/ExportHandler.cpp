#include "ExportHandler.h"

ExportHandler::ExportHandler(HANDLE hProcess, LPVOID lpvBaseOfImage) {
	this->hProcess = hProcess;
	this->lpvBaseOfImage = lpvBaseOfImage;

	SIZE_T bytesRead;

	if (this->lpvBaseOfImage != 0) {
		if (!ReadProcessMemory(hProcess, this->lpvBaseOfImage, &(this->dosHeader), sizeof(IMAGE_DOS_HEADER), &bytesRead)) {
			LOG_F(ERROR, "ReadProcessMemory (dosHeader) (%x)", GetLastError());
			exit(1);
		}

		LPVOID lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->dosHeader.e_lfanew + 4);
		if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)lpvScratch), &(this->machine), sizeof(WORD), &bytesRead) || bytesRead != sizeof(WORD)) {
			LOG_F(ERROR, "ReadProcessMemory (machine) (%x)", GetLastError(), bytesRead);
			exit(1);
		}

		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->dosHeader.e_lfanew);
		if (this->machine == IMAGE_FILE_MACHINE_AMD64) {
			IMAGE_NT_HEADERS64 ntHeaders = { 0 };
			if (!ReadProcessMemory(hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &bytesRead)) {
				LOG_F(ERROR, "ReadProcessMemory (ntHeaders) (%x)", GetLastError());
				exit(1);
			}

			IMAGE_DATA_DIRECTORY exportEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			this->exportEntryVA = exportEntry.VirtualAddress;
		}
		else if (this->machine == IMAGE_FILE_MACHINE_I386) {
			IMAGE_NT_HEADERS32 ntHeaders = { 0 };
			if (!ReadProcessMemory(hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS32), &bytesRead)) {
				LOG_F(ERROR, "ReadProcessMemory (ntHeaders) (%x)", GetLastError());
				exit(1);
			}

			IMAGE_DATA_DIRECTORY exportEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			this->exportEntryVA = exportEntry.VirtualAddress;
		}
	}
}

std::map<std::string, UINT64> ExportHandler::GetFunctionAddresses(std::list<std::string> functions)
{
	std::map<std::string, UINT64> addresses;

	IMAGE_EXPORT_DIRECTORY ied;
	if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + this->exportEntryVA), &ied, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
		LOG_F(ERROR, "Getting function addresses (%x)", GetLastError());
		exit(1);
	}

	DWORD numFunctions = ied.NumberOfFunctions;
	DWORD addressTableRVA = ied.AddressOfFunctions;
	DWORD nameTableRVA = ied.AddressOfNames;

	if (numFunctions != ied.NumberOfNames) {
		LOG_F(WARNING, "numFunctions != numNames");
	}

	for (int i = 0; i < numFunctions; i++) {
		DWORD nameRVA;
		if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + nameTableRVA + sizeof(DWORD) * i), &nameRVA, sizeof(DWORD), NULL)) {
			LOG_F(ERROR, "Getting function addresses (%x)", GetLastError());
			exit(1);
		}

		CHAR name[MAX_PATH];
		DWORD nameIndex = 0;
		do {
			if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + nameRVA + sizeof(CHAR) * nameIndex), name+nameIndex, sizeof(CHAR), NULL)) {
				LOG_F(ERROR, "Getting function addresses (%x)", GetLastError());
				exit(1);
			}
			nameIndex++;
		} while (name[nameIndex - 1] != 0);

		std::string nameStr(name);

		std::list<std::string>::iterator functionIt;
		for (functionIt = functions.begin(); functionIt != functions.end(); functionIt++) {
			if (!nameStr.compare(*functionIt)) {
				DWORD addressRVA;
				if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + addressTableRVA + sizeof(DWORD) * i), &addressRVA, sizeof(DWORD), NULL)) {
					LOG_F(ERROR, "Getting function addresses (%x)", GetLastError());
					exit(1);
				}
				addresses[nameStr] = (UINT64)this->lpvBaseOfImage + addressRVA;
				break;
			}
		}
	}

	return addresses;
}

UINT64 ExportHandler::GetFunctionAddress(std::string targetName)
{
	UINT64 address = 0;
	IMAGE_EXPORT_DIRECTORY ied;
	if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + this->exportEntryVA), &ied, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
		LOG_F(ERROR, "Getting function address (%x)", GetLastError());
		exit(1);
	}

	DWORD numFunctions = ied.NumberOfFunctions;
	DWORD addressTableRVA = ied.AddressOfFunctions;
	DWORD nameTableRVA = ied.AddressOfNames;

	if (numFunctions != ied.NumberOfNames) {
		LOG_F(WARNING, "numFunctions != numNames");
	}

	for (int i = 0; i < numFunctions; i++) {
		DWORD nameRVA;
		if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + nameTableRVA + sizeof(DWORD) * i), &nameRVA, sizeof(DWORD), NULL)) {
			LOG_F(ERROR, "Getting function address (%x)", GetLastError());
			exit(1);
		}

		CHAR name[MAX_PATH];
		DWORD nameIndex = 0;
		do {
			if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + nameRVA + sizeof(CHAR) * nameIndex), name + nameIndex, sizeof(CHAR), NULL)) {
				LOG_F(ERROR, "Getting function address (%x)", GetLastError());
				exit(1);
			}
			nameIndex++;
		} while (name[nameIndex - 1] != 0);

		std::string nameStr(name);
		if (!nameStr.compare(targetName)) {
			DWORD addressRVA;
			if(!ReadProcessMemory(this->hProcess, (LPVOID)((UINT64)this->lpvBaseOfImage + addressTableRVA + sizeof(DWORD) * i), &addressRVA, sizeof(DWORD), NULL)) {
				LOG_F(ERROR, "Getting function address (%x)", GetLastError());
				exit(1);
			}
			address = (UINT64)this->lpvBaseOfImage + addressRVA;
			break;
		}
	}

	return address;
}
