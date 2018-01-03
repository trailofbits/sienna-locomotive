// fuzz_server.cpp : Defines the entry point for the console application.
//

#include <random>
#define NOMINMAX
#include <Windows.h>
#include <set>
#include <unordered_map>

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"


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

	DWORD id = 0;
	for (id = 0; id <= UINT64_MAX; id++) {
		if (usedIds.find(id) == usedIds.end()) {
			LOG_F(INFO, "Found run id %x", id);
			break;
		}
	}

	WCHAR targetDir[MAX_PATH];
	wsprintf(targetDir, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d", id);
	if(!CreateDirectory(targetDir, NULL)) {
		LOG_F(ERROR, "FindUnusedId (%x)", GetLastError());
		exit(1);
	}

	LeaveCriticalSection(&critId);

	return id;
}

DWORD generateRunId(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	LOG_F(INFO, "Run id requested");
	DWORD runId = findUnusedId();

	BOOL success = WriteFile(hPipe, &runId, sizeof(DWORD), &dwBytesWritten, NULL);

	// get program name
	TCHAR commandLine[8192] = { 0 };
	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if (size > 8191) {
		LOG_F(ERROR, "Invalid size for command name");
		return 1;
	}
	
	if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\program.txt", runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}
	
	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));

	// get program arguments
	size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if (size > 8191) {
		LOG_F(ERROR, "Invalid size for command name");
		return 1;
	}
	
	if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	ZeroMemory(targetFile, (MAX_PATH + 1)*sizeof(WCHAR));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\arguments.txt", runId);
	hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "GenerateRunId (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

VOID strategyAAAA(BYTE *buf, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		buf[i] = 'A';
	}
}

VOID strategyRandByte(BYTE *buf, DWORD size) {
	std::random_device rd;
	srand(rd());
	DWORD random = rand();
	random <<= 15;
	random |= rand();

	DWORD pos = random % size;
	BYTE mut = rand() % 256;

	buf[pos] = mut;
}

DWORD mutate(BYTE *buf, DWORD size) {
	strategyRandByte(buf, size);

	return 0;
}

DWORD writeFKT(HANDLE hFile, DWORD pathSize, TCHAR *filePath, DWORD64 position, DWORD size, BYTE* buf) {
	DWORD dwBytesWritten = 0;

	if (!WriteFile(hFile, "FKT\0", 4, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	// only one type for right now, files
	DWORD type = 1;
	if (!WriteFile(hFile, &type, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &pathSize, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, filePath, pathSize * sizeof(TCHAR), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &position, sizeof(DWORD64), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &size, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD handleMutation(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	DWORD mutateCount = 0;
	if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	DWORD pathSize = 0;
	if (!ReadFile(hPipe, &pathSize, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (pathSize > MAX_PATH) {
		LOG_F(ERROR, "HandleMutation MAX_PATH", GetLastError());
		exit(1);
	}

	TCHAR filePath[MAX_PATH + 1];
	if (!ReadFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	filePath[pathSize] = 0;

	DWORD64 position = 0;
	if (!ReadFile(hPipe, &position, sizeof(DWORD64), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}
	
	HANDLE hHeap = GetProcessHeap();
	if(hHeap == NULL) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	
	if(buf == NULL) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hPipe, buf, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	if (dwBytesRead != size) {
		size = dwBytesRead;
	}

	mutate(buf, size);
	
	if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH+1];
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\%d.fkt", runId, mutateCount);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	writeFKT(hFile, pathSize, filePath, position, size, buf);

	if(!HeapFree(hHeap, NULL, buf)) {
		LOG_F(ERROR, "HandleMutation (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD getBytesFKT(HANDLE hFile, BYTE *buf, DWORD size) {
	DWORD dwBytesRead = 0;

	SetFilePointer(hFile, -(LONG)size, NULL, FILE_END);

	if (!ReadFile(hFile, buf, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}
}

DWORD handleReplay(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	runId = runId & 0x7FFFFFFF;

	DWORD mutateCount = 0;
	
	if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	// TODO: validate size matches file size
	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	HANDLE hHeap = GetProcessHeap();

	if(hHeap == NULL) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	
	if(buf == NULL) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH + 1];
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\%d.fkt", runId, mutateCount);
	// TODO: validate file exists
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	getBytesFKT(hFile, buf, size);
	
	if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}
	
	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!HeapFree(hHeap, NULL, buf)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD serveRunInfo(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	runId = runId & 0x7FFFFFFF;

	TCHAR commandLine[8192] = { 0 };
	WCHAR targetFile[MAX_PATH + 1] = { 0 };

	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\program.txt", runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}
	
	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));
	ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\arguments.txt", runId);
	
	hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD finalizeRun(HANDLE hPipe) {
	DWORD dwBytesRead = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "FinalizeRun (%x)", GetLastError());
		exit(1);
	}

	BOOL crash = false;
	if(!ReadFile(hPipe, &crash, sizeof(BOOL), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "FinalizeRun (%x)", GetLastError());
		exit(1);
	}
	LOG_F(INFO, "Finalizing run %x", runId);

	if (!crash) {
		LOG_F(INFO, "No crash removing run %x", runId);
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
		if(!RemoveDirectory(targetFile)) {
			LOG_F(ERROR, "FinalizeRun (%x)", GetLastError());
			exit(1);
		}

		LeaveCriticalSection(&critId);
	}
	else {
		LOG_F(INFO, "Crash found for run %x", runId);
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
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}
	runId = runId & 0x7FFFFFFF;

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.trc", runId);
	HANDLE hTraceFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);

	if(hTraceFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	traceFileMap[runId] = hTraceFile;

	ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\mem.dmp", runId);
	DWORD size = (wcslen(targetFile) + 1) * sizeof(WCHAR);

	if(!WriteFile(hPipe, &size, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &targetFile, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	LeaveCriticalSection(&critTrace);
	return 0;
}

DWORD traceInsns(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0; 

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
		exit(1);
	}

	runId = runId & 0x7FFFFFFF;

	while (1) {
		UINT64 bbAddr = 0;
		if(!ReadFile(hPipe, &bbAddr, sizeof(UINT64), &dwBytesRead, NULL)) {
			LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
			exit(1);
		}

		DWORD traceSize = 0;
		if(!ReadFile(hPipe, &traceSize, sizeof(DWORD), &dwBytesRead, NULL)) {
			LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
			exit(1);
		}

		if (bbAddr == 0 && traceSize == 0) {
			break;
		}

		HANDLE hHeap = GetProcessHeap();
		BYTE *traceBuf = (BYTE *)HeapAlloc(hHeap, NULL, traceSize);

		if(!ReadFile(hPipe, traceBuf, traceSize, &dwBytesRead, NULL)) {
			LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
			exit(1);
		}

		// keep it synchronous 
		BYTE nullByte = 0;
		if(!WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL)) {
			LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
			exit(1);
		}

		if (traceFileMap.find(runId) == traceFileMap.end()) {
			LOG_F(ERROR, "No trace file found for runId %x (instruction)", runId);
			exit(1);
		}
		else {
			EnterCriticalSection(&critTrace);
			HANDLE hTraceFile = traceFileMap[runId];
			BYTE addrByte = 0x80;
			if(!WriteFile(hTraceFile, &addrByte, sizeof(BYTE), &dwBytesWritten, NULL)) {
				LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
				exit(1);
			}

			if(!WriteFile(hTraceFile, &bbAddr, sizeof(UINT64), &dwBytesWritten, NULL)) {
				LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
				exit(1);
			}
			
			if(!WriteFile(hTraceFile, traceBuf, traceSize, &dwBytesWritten, NULL)) {
				LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
				exit(1);
			}
			LeaveCriticalSection(&critTrace);
		}

		/*printf("%x, %x, %x\t", runId, bbAddr, traceSize);
		for (int i = 0; i < traceSize; i++) {
			printf("%x ", traceBuf[i]);
		}
		printf("\n");*/
		if(!HeapFree(hHeap, NULL, traceBuf)) {
			LOG_F(ERROR, "TraceInsns (%x)", GetLastError());
			exit(1);
		}
	}
	
	// TODO: close file on broken pipe?

	return 0;
}

DWORD traceTaint(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
		exit(1);
	}

	runId = runId & 0x7FFFFFFF;

	UINT64 taintAddr = 0;
	if(!ReadFile(hPipe, &taintAddr, sizeof(UINT64), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
		exit(1);
	}

	UINT64 taintSize = 0;
	if(!ReadFile(hPipe, &taintSize, sizeof(UINT64), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
		exit(1);
	}

	if (traceFileMap.find(runId) == traceFileMap.end()) {
		LOG_F(ERROR, "No trace file found for runId %x (taint)", runId);
		exit(1);
	}
	else {
		EnterCriticalSection(&critTrace);
		HANDLE hTraceFile = traceFileMap[runId];

		BYTE taintByte = 0x81;
		if(!WriteFile(hTraceFile, &taintByte, sizeof(BYTE), &dwBytesWritten, NULL)) {
			LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
			exit(1);
		}

		if(!WriteFile(hTraceFile, &taintAddr, sizeof(UINT64), &dwBytesWritten, NULL)) {
			LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
			exit(1);
		}

		if(!WriteFile(hTraceFile, &taintSize, sizeof(UINT64), &dwBytesWritten, NULL)) {
			LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
			exit(1);
		}

		LeaveCriticalSection(&critTrace);
	}

	// keep it synchronous for now
	BYTE nullByte = 0;
	if(!WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceTaint (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD traceCrash(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	EnterCriticalSection(&critTrace);

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}
	runId = runId & 0x7FFFFFFF;

	UINT64 exceptionAddr = 0;
	if(!ReadFile(hPipe, &exceptionAddr, sizeof(UINT64), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	DWORD exceptionCode = 0;
	if(!ReadFile(hPipe, &exceptionCode, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	if (traceFileMap.find(runId) == traceFileMap.end()) {
		LOG_F(ERROR, "Crash no trace file found for runId %x", runId);
		exit(1);
	}
	else {
		HANDLE hTraceFile = traceFileMap[runId];
		if(!CloseHandle(hTraceFile)) {
			LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
			exit(1);
		}
	}

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, L"C:\\Users\\dgoddard\\Documents\\work\\fuzz_working\\%d\\execution.csh", runId);
	HANDLE hCrashFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	
	if(!WriteFile(hCrashFile, &exceptionAddr, sizeof(UINT64), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hCrashFile, &exceptionCode, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hCrashFile)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	// keep it synchronous for now
	BYTE nullByte = 0;
	if(!WriteFile(hPipe, &nullByte, sizeof(BYTE), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "TraceCrash (%x)", GetLastError());
		exit(1);
	}

	LeaveCriticalSection(&critTrace);
	return 0;
}

// TODO: I think we can delete this
DWORD handleLog(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleLog (%x)", GetLastError());
		exit(1);
	}

	HANDLE hHeap = GetProcessHeap();
	if(hHeap == NULL) {
		LOG_F(ERROR, "HandleLog (%x)", GetLastError());
		exit(1);
	}

	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	if(buf == NULL) {
		LOG_F(ERROR, "HandleLog (%x)", GetLastError());
		exit(1);
	}

	if(!ReadFile(hPipe, buf, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleLog (%x)", GetLastError());
		exit(1);
	}

	EnterCriticalSection(&critLog);
	if(!WriteFile(hLog, buf, dwBytesRead, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleLog (%x)", GetLastError());
		exit(1);
	}
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
};

DWORD WINAPI threadHandler(LPVOID lpvPipe) {
	HANDLE hPipe = (HANDLE)lpvPipe;

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	BYTE eventId = 255;
	if(!ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "ThreadHandler (%x)", GetLastError());
		exit(1);
	}

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
		default:
			// TODO: log error
			LOG_F(WARNING, "Unknown event id %x", eventId);
			break;
	}

	if(!FlushFileBuffers(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (%x)", GetLastError());
		exit(1);
	}

	if(!DisconnectNamedPipe(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

int main(int mArgc, char **mArgv)
{
	loguru::init(mArgc, mArgv);
	loguru::add_file("log\\server.log", loguru::Append, loguru::Verbosity_MAX);
	LOG_F(INFO, "Server started!");

	InitializeCriticalSection(&critId);
	InitializeCriticalSection(&critTrace);
	InitializeCriticalSection(&critLog);

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
			LOG_F(ERROR, "Could not create pipe");
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
				LOG_F(ERROR, "CreateThread (%x)\n", GetLastError());
				return -1;
			}
			else {
				CloseHandle(hThread);
			}
		}
		else {
			LOG_F(ERROR, "Could not connect to hPipe");
			CloseHandle(hPipe);
		}
	}

	// TODO: stop gracefully?
	DeleteCriticalSection(&critId);
	DeleteCriticalSection(&critTrace);
	DeleteCriticalSection(&critLog);
    return 0;
}

