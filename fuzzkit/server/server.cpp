// fuzz_server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <set>
#include <unordered_map>

#define BUFSIZE 100000

CRITICAL_SECTION critId;
CRITICAL_SECTION critTrace;
CRITICAL_SECTION critLog;

std::unordered_map<DWORD, HANDLE> traceFileMap;
HANDLE hLog = INVALID_HANDLE_VALUE;

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
	
	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));

	// get program arguments
	size = 0;
	ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);
	if (size > 8191) {
		printf("ERROR: invalid size for command name");
		return 1;
	}
	
	ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL);

	ZeroMemory(targetFile, (MAX_PATH + 1)*sizeof(WCHAR));
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
	runId = runId & 0x7FFFFFFF;

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
	runId = runId & 0x7FFFFFFF;

	TCHAR commandLine[8192] = { 0 };
	WCHAR targetFile[MAX_PATH + 1] = { 0 };

	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\program.txt", runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL);
	CloseHandle(hFile);

	WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL);
	WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL);

	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));

	ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
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

/*
in	runId
out	path size
out path
*/
DWORD traceInit(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	EnterCriticalSection(&critTrace);

	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);
	runId = runId & 0x7FFFFFFF;

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.trc", runId);
	HANDLE hTraceFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	traceFileMap[runId] = hTraceFile;

	ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\mem.dmp", runId);
	DWORD size = (wcslen(targetFile) + 1) * sizeof(WCHAR);

	WriteFile(hPipe, &size, sizeof(DWORD), &dwBytesWritten, NULL);
	WriteFile(hPipe, &targetFile, size, &dwBytesWritten, NULL);

	LeaveCriticalSection(&critTrace);
	return 0;
}

DWORD traceInsns(HANDLE hPipe) {
	printf("IN TRACEINSN\n");
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0; 

	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);
	runId = runId & 0x7FFFFFFF;

	while (1) {
		UINT64 bbAddr = 0;
		ReadFile(hPipe, &bbAddr, sizeof(UINT64), &dwBytesRead, NULL);

		UINT64 traceSize = 0;
		ReadFile(hPipe, &traceSize, sizeof(UINT64), &dwBytesRead, NULL);

		if (bbAddr == 0 && traceSize == 0) {
			break;
		}

		HANDLE hHeap = GetProcessHeap();
		BYTE *traceBuf = (BYTE *)HeapAlloc(hHeap, NULL, traceSize);

		ReadFile(hPipe, traceBuf, traceSize, &dwBytesRead, NULL);

		// keep it synchronous 
		BYTE nullByte = 0;
		WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL);

		if (traceFileMap.find(runId) == traceFileMap.end()) {
			printf("ERROR: insns no trace file found for runId %x\n", runId);
		}
		else {
			EnterCriticalSection(&critTrace);
			HANDLE hTraceFile = traceFileMap[runId];
			BYTE addrByte = 0x80;
			WriteFile(hTraceFile, &addrByte, sizeof(BYTE), &dwBytesWritten, NULL);
			WriteFile(hTraceFile, &bbAddr, sizeof(UINT64), &dwBytesWritten, NULL);
			WriteFile(hTraceFile, traceBuf, traceSize, &dwBytesWritten, NULL);
			LeaveCriticalSection(&critTrace);
		}

		/*printf("%x, %x, %x\t", runId, bbAddr, traceSize);
		for (int i = 0; i < traceSize; i++) {
			printf("%x ", traceBuf[i]);
		}
		printf("\n");*/
		HeapFree(hHeap, NULL, traceBuf);
	}

	printf("OUT LOOP!\n");

	return 0;
}

DWORD traceTaint(HANDLE hPipe) {
	printf("IN TAINT\n");
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);
	runId = runId & 0x7FFFFFFF;

	UINT64 taintAddr = 0;
	ReadFile(hPipe, &taintAddr, sizeof(UINT64), &dwBytesRead, NULL);

	UINT64 taintSize = 0;
	ReadFile(hPipe, &taintSize, sizeof(UINT64), &dwBytesRead, NULL);

	if (traceFileMap.find(runId) == traceFileMap.end()) {
		printf("ERROR: taint no trace file found for runId %x\n", runId);
	}
	else {
		EnterCriticalSection(&critTrace);
		HANDLE hTraceFile = traceFileMap[runId];

		BYTE taintByte = 0x81;
		WriteFile(hTraceFile, &taintByte, sizeof(BYTE), &dwBytesWritten, NULL);
		WriteFile(hTraceFile, &taintAddr, sizeof(UINT64), &dwBytesWritten, NULL);
		WriteFile(hTraceFile, &taintSize, sizeof(UINT64), &dwBytesWritten, NULL);
		LeaveCriticalSection(&critTrace);
	}

	// keep it synchronous for now
	BYTE nullByte = 0;
	WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL);

	return 0;
}

DWORD traceCrash(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	EnterCriticalSection(&critTrace);

	DWORD runId = 0;
	ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL);
	runId = runId & 0x7FFFFFFF;

	UINT64 exceptionAddr = 0;
	ReadFile(hPipe, &exceptionAddr, sizeof(UINT64), &dwBytesRead, NULL);

	DWORD exceptionCode = 0;
	ReadFile(hPipe, &exceptionCode, sizeof(DWORD), &dwBytesRead, NULL);

	if (traceFileMap.find(runId) == traceFileMap.end()) {
		printf("ERROR: crash no trace file found for runId %x\n", runId);
	}
	else {
		HANDLE hTraceFile = traceFileMap[runId];
		CloseHandle(hTraceFile);
	}

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.csh", runId);
	HANDLE hCrashFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	WriteFile(hCrashFile, &exceptionAddr, sizeof(UINT64), &dwBytesWritten, NULL);
	WriteFile(hCrashFile, &exceptionCode, sizeof(DWORD), &dwBytesWritten, NULL);
	CloseHandle(hCrashFile);

	// keep it synchronous for now
	BYTE nullByte = 0;
	WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL);

	LeaveCriticalSection(&critTrace);
	return 0;
}

DWORD handleLog(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD size = 0;
	BOOL success = ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL);

	HANDLE hHeap = GetProcessHeap();
	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

	success = ReadFile(hPipe, buf, size, &dwBytesRead, NULL);

	EnterCriticalSection(&critLog);
	WriteFile(hLog, buf, dwBytesRead, &dwBytesWritten, NULL);
	LeaveCriticalSection(&critLog);

	return 0;
}

enum Event {
	EVT_RUN_ID,				// 0
	EVT_MUTATION,			// 1
	EVT_REPLAY,				// 2
	EVT_RUN_INFO,			// 3
	EVT_RUN_COMPLETE,		// 4
	EVT_TRACE_INIT,			// 5
	EVT_TRACE_INSNS,		// 6
	EVT_TRACE_TAINT,		// 7
	EVT_TRACE_CRASH_INFO,	// 8
	EVT_LOG					// 9
};

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
		case EVT_TRACE_INIT:
			traceInit(hPipe);
			break;
		case EVT_TRACE_INSNS:
			traceInsns(hPipe);
			break;
		case EVT_TRACE_TAINT:
			traceTaint(hPipe);
			break;
		case EVT_TRACE_CRASH_INFO:
			traceCrash(hPipe);
			break;
		case EVT_LOG:
			handleLog(hPipe);
			break;
		default:
			// TODO: log error
			printf("UNKNOWN EVENT ID %d\n", eventId);
			break;
	}

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	return 0;
}

int main()
{
	InitializeCriticalSection(&critId);
	InitializeCriticalSection(&critTrace);
	InitializeCriticalSection(&critLog);

	HANDLE hLog = CreateFile(L"fuzzkit.log", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	SetFilePointer(hLog, 0, 0, FILE_END);

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

	// TODO: stop gracefully?
	DeleteCriticalSection(&critId);
	DeleteCriticalSection(&critTrace);
	DeleteCriticalSection(&critLog);
    return 0;
}

