// fuzz_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <set>

#define BUFSIZE 100000

DWORD mutate(BYTE *buf, DWORD size) {
	// mutation logic here
	for (int i = 0; i < size; i++) {
		buf[i] = 'A';
	}
	return 0;
}

DWORD handleMutation(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	BOOL success = ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);

	printf("INFO: runId %x\n", runId);

	DWORD size = 0;
	success = ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);
	
	HANDLE hHeap = GetProcessHeap();
	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	success = ReadFile(hPipe, buf, size, &dwBytesRead, NULL);

	if (dwBytesRead == 0 || !success) {
		printf("ERROR: read pipe failure (%x)\n", GetLastError());
		return 1;
	}

	if (dwBytesRead != size) {
		size = dwBytesRead;
	}

	mutate(buf, size);
	success = WriteFile(hPipe, buf, size, &dwBytesWritten, NULL);
	HeapFree(hHeap, NULL, buf);
	return 0;
}

DWORD findUnusedId() {
	HANDLE hFind;
	WIN32_FIND_DATA findData;
	std::set<UINT64> usedIds;

	hFind = FindFirstFile(L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\*", &findData);
	if(hFind != INVALID_HANDLE_VALUE) {
		do {
			if (findData.cFileName[0] >= 0x30 && findData.cFileName[0] <= 0x39) {
				UINT64 runId = wcstoul(findData.cFileName, NULL, 0);
				usedIds.insert(runId);
				printf("%x\n", runId);
			}
		} while (FindNextFile(hFind, &findData));
	}

	UINT64 id = 0;
	for (id = 0; id <= UINT64_MAX; id++) {
		if (usedIds.find(id) == usedIds.end()) {
			break;
		}
	}

	WCHAR targetDir[MAX_PATH];
	wsprintf(targetDir, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d", id);
	CreateDirectory(targetDir, NULL);

	return id;
}

DWORD generateRunId(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = findUnusedId();

	BOOL success = WriteFile(hPipe, &runId, sizeof(DWORD), &dwBytesWritten, NULL);
	return 0;
}

DWORD WINAPI threadHandler(LPVOID lpvPipe) {
	HANDLE hPipe = (HANDLE)lpvPipe;

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	BYTE eventId = 255;
	BOOL success = ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL);

	switch (eventId) {
		case 0:
			generateRunId(hPipe);
			break;
		case 1:
			handleMutation(hPipe);
			break;
		default:
			// TODO: log error
			break;
	}

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

