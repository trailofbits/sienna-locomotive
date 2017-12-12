#include "ImportHandler.h"

ImportHandler::ImportHandler(HANDLE hProcess, LPVOID lpvBaseOfImage) {
	this->hProcess = hProcess;
	this->lpvBaseOfImage = lpvBaseOfImage;

	SIZE_T bytesRead;

	if (this->lpvBaseOfImage != 0) {
		ReadProcessMemory(hProcess, this->lpvBaseOfImage, &(this->dosHeader), sizeof(IMAGE_DOS_HEADER), &bytesRead);

		LPVOID lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->dosHeader.e_lfanew + 4);
		if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)lpvScratch), &(this->machine), sizeof(WORD), &bytesRead) || bytesRead != sizeof(WORD)) {
			LOG_F(ERROR, "ReadProcessMemory (machine) (%x) (%x)", GetLastError(), bytesRead);
		}

		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->dosHeader.e_lfanew);
		if (this->machine == IMAGE_FILE_MACHINE_AMD64) {
			IMAGE_NT_HEADERS64 ntHeaders = { 0 };
			if (!ReadProcessMemory(hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &bytesRead)) {
				LOG_F(ERROR, "ReadProcessMemory (ntHeaders64) (%x)", GetLastError());
				return;
			}

			IMAGE_DATA_DIRECTORY importEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			this->importEntryVA = importEntry.VirtualAddress;
		}
		else if (this->machine == IMAGE_FILE_MACHINE_I386) {
			IMAGE_NT_HEADERS32 ntHeaders = { 0 };
			if (!ReadProcessMemory(hProcess, lpvScratch, &ntHeaders, sizeof(IMAGE_NT_HEADERS32), &bytesRead)) {
				LOG_F(ERROR, "ReadProcessMemory (ntHeaders32) (%x)", GetLastError());
				return;
			}

			IMAGE_DATA_DIRECTORY importEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			this->importEntryVA = importEntry.VirtualAddress;
		}
	}
}

std::string ImportHandler::GetNextModule() {
	if (this->iidIndex != 0 && this->iid.Characteristics == 0) {
		return "";
	}

	SIZE_T bytesRead;
	LPVOID lpvScratch = (PVOID)((uintptr_t)this->lpvBaseOfImage + this->importEntryVA + sizeof(IMAGE_IMPORT_DESCRIPTOR)*this->iidIndex);
	ReadProcessMemory(this->hProcess, lpvScratch, &(this->iid), sizeof(IMAGE_IMPORT_DESCRIPTOR), &bytesRead);
	this->iidIndex++;

	if (this->iidIndex != 0 && this->iid.Characteristics == 0) {
		return "";
	}

	BYTE pModName[MAX_PATH] = { 0 };
	PBYTE dst = pModName;
	lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.Name);

	DWORD nameIndex = 0;
	do {
		ReadProcessMemory(this->hProcess, lpvScratch, pModName + nameIndex, sizeof(BYTE), &bytesRead);
		nameIndex++;
		lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
	} while (pModName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);


	this->itdIndex = 0;
	return (CHAR *)pModName;
}

VOID ImportHandler::ResetFunctions() {
	this->itdIndex = 0;
	this->itdOrig.u1.AddressOfData = 0;
}

std::string ImportHandler::GetNextFunction() {
	if (this->iid.Characteristics == 0) {
		return "";
	}

	SIZE_T bytesRead;
	LPVOID lpvScratch;

	if (this->machine == IMAGE_FILE_MACHINE_AMD64) {
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.OriginalFirstThunk + this->itdIndex * sizeof(IMAGE_THUNK_DATA64));
		ReadProcessMemory(this->hProcess, lpvScratch, &(this->itdOrig), sizeof(IMAGE_THUNK_DATA64), &bytesRead);

		if (this->itdOrig.u1.AddressOfData == 0) {
			return "";
		}
		
		BYTE pFuncName[MAX_PATH];
		if (this->itdOrig.u1.Ordinal & 0x80000000) {
			// ordinal 
			// TODO: return #N
			return "!ORDINAL";
		}
		else {
			PBYTE dst = pFuncName;
			lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->itdOrig.u1.AddressOfData + 2);

			DWORD nameIndex = 0;
			do {
				ReadProcessMemory(this->hProcess, lpvScratch, pFuncName + nameIndex, sizeof(BYTE), &bytesRead);
				nameIndex++;
				lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
			} while (pFuncName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);
		}

		this->itdIndex++;
		return (CHAR *)pFuncName;
	}
	else if (this->machine == IMAGE_FILE_MACHINE_I386) {
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.OriginalFirstThunk + this->itdIndex * sizeof(IMAGE_THUNK_DATA32));
		ReadProcessMemory(this->hProcess, lpvScratch, &(this->itdOrig), sizeof(IMAGE_THUNK_DATA32), &bytesRead);

		if (this->itdOrig.u1.AddressOfData == 0) {
			return "";
		}

		BYTE pFuncName[MAX_PATH];
		if (this->itdOrig.u1.Ordinal & 0x80000000) {
			// ordinal 
			// TODO: return #N
			return "!ORDINAL";
		}
		else {
			PBYTE dst = pFuncName;
			lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->itdOrig.u1.AddressOfData + 2);

			DWORD nameIndex = 0;
			do {
				ReadProcessMemory(this->hProcess, lpvScratch, pFuncName + nameIndex, sizeof(BYTE), &bytesRead);
				nameIndex++;
				lpvScratch = (LPVOID)((uintptr_t)lpvScratch + 1);
			} while (pFuncName[nameIndex - 1] != 0 && nameIndex < MAX_PATH);
		}

		this->itdIndex++;
		return (CHAR *)pFuncName;
	}

	return "";
}

UINT64 ImportHandler::GetFunctionOrd() {
	return this->itdOrig.u1.Ordinal & 0x7FFFFFFF;
}

UINT64 ImportHandler::GetFunctionAddr() {
	LPVOID lpvScratch;
	SIZE_T bytesRead;

	if (this->machine == IMAGE_FILE_MACHINE_AMD64) {
		uint64_t iatFirstThunkAddr;
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.FirstThunk + (this->itdIndex - 1) * sizeof(uint64_t));
		ReadProcessMemory(this->hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint64_t), &bytesRead);
		return iatFirstThunkAddr;
	}
	else if (machine == IMAGE_FILE_MACHINE_I386) {
		uint32_t iatFirstThunkAddr;
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.FirstThunk + (this->itdIndex - 1) * sizeof(uint32_t));
		ReadProcessMemory(this->hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint32_t), &bytesRead);
		return iatFirstThunkAddr;
	}

	return 0;
}

BOOL ImportHandler::RewriteFunctionAddr(UINT64 addr) {
	LPVOID lpvScratch = 0;
	SIZE_T bytesWritten = 0;

	if (this->machine == IMAGE_FILE_MACHINE_AMD64) {
		uint64_t iatFirstThunkAddr = addr;
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.FirstThunk + (this->itdIndex-1) * sizeof(uint64_t));
		if (!WriteProcessMemory(this->hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint64_t), &bytesWritten)) {
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQueryEx(this->hProcess, lpvScratch, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			LOG_F(WARNING, "Could not hook function first try (%x) (%x)", bytesWritten, GetLastError());
			
			// TODO: do this intelligently
			DWORD old;
			VirtualProtectEx(this->hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &old);

			if (!WriteProcessMemory(this->hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint64_t), &bytesWritten)) {
				LOG_F(ERROR, "Could not hook function second try (%x) (%x)", bytesWritten, GetLastError());
				return false;
			}
			
			LOG_F(INFO, "Don't worry, second try was successful");
			VirtualProtectEx(this->hProcess, mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &old);
			return true;
		}
		return true;
	}
	else if (machine == IMAGE_FILE_MACHINE_I386) {
		uint32_t iatFirstThunkAddr = (uint32_t)addr;
		lpvScratch = (LPVOID)((uintptr_t)this->lpvBaseOfImage + this->iid.FirstThunk + (this->itdIndex-1) * sizeof(uint32_t));
		WriteProcessMemory(this->hProcess, lpvScratch, &iatFirstThunkAddr, sizeof(uint32_t), &bytesWritten);
		return true;
	}

	return false;
}