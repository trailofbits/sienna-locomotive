// fuzz_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

#define BUFSIZE 100000

DWORD handleRequest(BYTE *buf, DWORD size) {
	// mutation logic here
	for (int i = 0; i < size; i++) {
		buf[i] = 'A';
	}
	return 0;
}

DWORD WINAPI threadHandler(LPVOID lpvPipe) {
	HANDLE hPipe = (HANDLE)lpvPipe;
	HANDLE hHeap = GetProcessHeap();

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwReplyBytes = 0;

	DWORD size = 0;
	BOOL success = ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);
	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	success = ReadFile(hPipe, buf, size, &dwBytesRead, NULL);

	if (dwBytesRead == 0 || !success) {
		printf("ERROR: read pipe failure (%x)\n", GetLastError());
		return 1;
	}

	if (dwBytesRead != size) {
		size = dwBytesRead;
	}

	handleRequest(buf, size);
	success = WriteFile(hPipe, buf, size, &dwBytesWritten, NULL);
	HeapFree(hHeap, NULL, buf);

	return 0;
}

int main()
{
	while (1) {
		DWORD outSize = BUFSIZE;
		DWORD inSize = BUFSIZE;
		HANDLE hPipe = CreateNamedPipe(
			L"\\\\.\\pipe\\fuzz_server",
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
			outSize,
			inSize,
			0,
			NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("ERROR: could not create pipe\n");
			return 1;
		}

		BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (connected) {
			DWORD threadID;
			HANDLE hThread = CreateThread(
				NULL,
				0,
				threadHandler,
				(LPVOID)hPipe,
				0,
				&threadID);

			if (hThread == NULL)
			{
				printf("ERROR: CreateThread (%x)\n", GetLastError());
				return -1;
			}
			else {
				CloseHandle(hThread);
			}
		}
		else {
			CloseHandle(hPipe);
		}
	}

    return 0;
}

