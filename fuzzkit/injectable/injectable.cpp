// injectable.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>

extern "C" __declspec(dllexport) DWORD runId;
__declspec(dllexport) DWORD runId;
DWORD mutateCount = 0;

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

	DWORD maskedRunId = runId & 0x7FFFFFFF;
	BOOL replay = runId >> 31;

	if (!replay) {
		BYTE eventId = 1;

		WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
		WriteFile(hPipe, &maskedRunId, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);
		TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);

		// send buf size to server
		// send buf addr to server
	}
	else {
		BYTE eventId = 2;

		WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
		WriteFile(hPipe, &maskedRunId, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);
		TransactNamedPipe(hPipe, &size, sizeof(DWORD), buf, size, &bytesRead, NULL);
	}
	mutateCount++;
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