// test_application.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

int main()
{
	LPCWSTR name = L"C:\\Users\\dgoddard\\Documents\\sample.txt";
	HANDLE file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		return 1;
	}

	BYTE buf[0x1000];
	DWORD bytes_to_read = 8;
	DWORD bytes_read;
	if (!ReadFile(file, buf, bytes_to_read, &bytes_read, NULL) || bytes_read != bytes_to_read) {
		printf("ERROR: ReadFile (ms_buf) (%x)\n", GetLastError());
		return 1;
	}

	buf[8] = 0;
	printf("BUF: %s\n", buf);
	
	CloseHandle(file);
    return 0;
}

