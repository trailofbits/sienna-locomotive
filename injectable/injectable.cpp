// injectable.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>

extern "C" __declspec(dllexport) BOOL ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) 
{
	printf("IN READ FILE HOOK!!!!\n");
	for (DWORD i = 0; i < nNumberOfBytesToRead; i++) {
		((BYTE *)lpBuffer)[i] = 'A';
	}

	*lpNumberOfBytesRead = nNumberOfBytesToRead;

	return true;
}