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

VOID mutate(LPVOID buf, DWORD size) {
	HANDLE hPipe = CreateFile(
		L"\\\\.\\pipe\\fuzz_server",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		// TODO: fallback mutations?
		return;
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hPipe,
		&readMode,
		NULL,
		NULL);

	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);
	TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);
}

extern "C" __declspec(dllexport) BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) 
{
	ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	
	mutate(lpBuffer, nNumberOfBytesToRead);

	*lpNumberOfBytesRead = nNumberOfBytesToRead;

	return true;
}