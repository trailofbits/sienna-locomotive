// triage.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

int main()
{
	HANDLE hTraceFile = CreateFile(L"trace.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTraceFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}

	DWORD highSize = 0;
	DWORD size = GetFileSize(hTraceFile, &highSize);
	if (highSize) {
		printf("ERROR: injectable exceeds 4GB\n");
		exit(1);
	}

	DWORD pos = 0;
	while (pos < size) {
		BYTE insnLength;
		BYTE insnBytes[15];

		DWORD bytesRead;
		ReadFile(hTraceFile, &insnLength, 1, &bytesRead, NULL);
		if (insnLength > 15) {
			printf("ERROR: invalid insn length at pos %d\n", pos);
			exit(1);
		}

		pos += 1;

		ReadFile(hTraceFile, insnBytes, insnLength, &bytesRead, NULL);
		for (int i = 0; i < insnLength; i++) {
			printf("%x ", insnBytes[i]);
		}
		printf("\n");

		pos += insnLength;
		break;
	}

    return 0;
}

