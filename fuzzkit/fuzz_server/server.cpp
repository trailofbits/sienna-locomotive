// fuzz_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <set>

#define BUFSIZE 100000

CRITICAL_SECTION critId;

DWORD findUnusedId() {
	HANDLE hFind;
	WIN32_FIND_DATA findData;
	std::set<UINT64> usedIds;

	EnterCriticalSection(&critId);
	hFind = FindFirstFile(L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\*", &findData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (findData.cFileName[0] >= 0x30 && findData.cFileName[0] <= 0x39) {
				UINT64 runId = wcstoul(findData.cFileName, NULL, 0);
				usedIds.insert(runId);
			}
		} while (FindNextFile(hFind, &findData));
		FindClose(hFind);
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
	LeaveCriticalSection(&critId);

	return id;
}

DWORD generateRunId(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = findUnusedId();

	BOOL success = WriteFile(hPipe, &runId, sizeof(DWORD), &dwBytesWritten, NULL);

	// get program name
	TCHAR commandLine[8192] = { 0 };
	DWORD size = 0;
	ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);
	if (size > 8191) {
		printf("ERROR: invalid size for command name");
		return 1;
	}
	
	ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL);

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\program.txt", runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL);
	CloseHandle(hFile);
	
	ZeroMemory(commandLine, 8192);

	// get program arguments
	size = 0;
	ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);
	if (size > 8191) {
		printf("ERROR: invalid size for command name");
		return 1;
	}
	
	ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL);

	ZeroMemory(targetFile, MAX_PATH + 1);
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\arguments.txt", runId);
	hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL);
	CloseHandle(hFile);

	return 0;
}

DWORD mutate(BYTE *buf, DWORD size) {
	// mutation logic here
	for (DWORD i = 0; i < size; i++) {
		buf[i] = 'A';
	}
	return 0;
}

DWORD handleMutation(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	BOOL success = ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);

	DWORD mutateCount = 0;
	success = ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL);

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

	WCHAR targetFile[MAX_PATH+1];
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\%d.fkt", runId, mutateCount);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	WriteFile(hFile, buf, size, &dwBytesWritten, NULL);
	CloseHandle(hFile);

	HeapFree(hHeap, NULL, buf);
	return 0;
}

DWORD handleReplay(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	BOOL success = ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);

	DWORD mutateCount = 0;
	success = ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL);

	// TODO: validate size matches file size
	DWORD size = 0;
	success = ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);

	HANDLE hHeap = GetProcessHeap();
	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

	WCHAR targetFile[MAX_PATH + 1];
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\%d.fkt", runId, mutateCount);
	// TODO: validate file exists
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	success = ReadFile(hFile, buf, size, &dwBytesRead, NULL);
	
	success = WriteFile(hPipe, buf, size, &dwBytesWritten, NULL);
	
	CloseHandle(hFile);
	HeapFree(hHeap, NULL, buf);

	return 0;
}

DWORD serveRunInfo(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);

	TCHAR commandLine[8192] = { 0 };
	WCHAR targetFile[MAX_PATH + 1] = { 0 };

	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\program.txt", runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL);
	CloseHandle(hFile);

	WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL);
	WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL);

	ZeroMemory(commandLine, 8192);

	ZeroMemory(targetFile, MAX_PATH + 1);
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\arguments.txt", runId);
	hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL);
	CloseHandle(hFile);

	WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL);
	WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL);

	return 0;
}

DWORD finalizeRun(HANDLE hPipe) {
	DWORD dwBytesRead = 0;

	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);

	BOOL crash = false;
	ReadFile(hPipe, &crash, sizeof(BOOL), &dwBytesRead, NULL);

	if (!crash) {
		EnterCriticalSection(&critId);
		WIN32_FIND_DATA findData;
		WCHAR targetFile[MAX_PATH + 1] = { 0 };
		wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\*", runId);

		// empty directory
		HANDLE hFind = FindFirstFile(targetFile, &findData);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				// TODO: this will fail on directories, but we don't have any directories yet
				wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\%s", runId, findData.cFileName);
				DeleteFile(targetFile);
			} while (FindNextFile(hFind, &findData));
			FindClose(hFind);
		}

		wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d", runId);
		RemoveDirectory(targetFile);
		LeaveCriticalSection(&critId);
	}

	return 0;
}

enum Event {EVT_RUN_ID, EVT_MUTATION, EVT_REPLAY, EVT_RUN_INFO, EVT_RUN_COMPLETE};

DWORD WINAPI threadHandler(LPVOID lpvPipe) {
	HANDLE hPipe = (HANDLE)lpvPipe;

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	BYTE eventId = 255;
	BOOL success = ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL);

	switch (eventId) {
		case EVT_RUN_ID:
			generateRunId(hPipe);
			break;
		case EVT_MUTATION:
			handleMutation(hPipe);
			break;
		case EVT_REPLAY:
			handleReplay(hPipe);
			break;
		case EVT_RUN_INFO:
			serveRunInfo(hPipe);
			break;
		case EVT_RUN_COMPLETE:
			finalizeRun(hPipe);
			break;
		default:
			// TODO: log error
			printf("UNKNOWN EVENT ID %d\n", eventId);
			break;
	}

	return 0;
}

int main()
{
	InitializeCriticalSection(&critId);
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
	DeleteCriticalSection(&critId);
    return 0;
}

