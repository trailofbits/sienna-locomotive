// fuzz_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

DWORD WINAPI threadHandler(LPVOID hPipe) {

	return 0;
}

int main()
{
	while (1) {
		DWORD outSize = 1000000; // ~1MB
		DWORD inSize = 1000000;
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

