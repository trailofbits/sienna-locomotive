// injectable.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>

/*
	Lookup: fastest IPC on Windows
	Read data
	Send to server
	Server sends back mutation
*/

extern "C" __declspec(dllexport) BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) 
{
	for (DWORD i = 0; i < nNumberOfBytesToRead; i++) {
		((BYTE *)lpBuffer)[i] = 'A';
	}

	*lpNumberOfBytesRead = nNumberOfBytesToRead;

	return true;
}